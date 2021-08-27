/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021 SChernykh <https://github.com/SChernykh>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "common.h"
#include "p2p_server.h"
#include "p2pool.h"
#include "params.h"
#include "keccak.h"
#include "side_chain.h"
#include "pool_block.h"
#include "block_cache.h"
#include <fstream>
#include <numeric>

static constexpr char log_category_prefix[] = "P2PServer ";
static constexpr char saved_peer_list_file_name[] = "p2pool_peers.txt";

static constexpr int DEFAULT_BACKLOG = 16;
static constexpr uint64_t DEFAULT_BAN_TIME = 600;

#include "tcp_server.inl"

namespace p2pool {

P2PServer::P2PServer(p2pool* pool)
	: TCPServer(P2PClient::allocate)
	, m_pool(pool)
	, m_cache(new BlockCache())
	, m_cacheLoaded(false)
	, m_rd{}
	, m_rng(m_rd())
	, m_block(new PoolBlock())
	, m_timer{}
	, m_peerId(m_rng())
	, m_peerListLastSaved(0)
{
	uv_mutex_init_checked(&m_rngLock);
	uv_mutex_init_checked(&m_blockLock);
	uv_mutex_init_checked(&m_peerListLock);
	uv_mutex_init_checked(&m_broadcastLock);
	uv_rwlock_init_checked(&m_cachedBlocksLock);

	int err = uv_async_init(&m_loop, &m_broadcastAsync, on_broadcast);
	if (err) {
		LOGERR(1, "uv_async_init failed, error " << uv_err_name(err));
		return;
	}
	m_broadcastAsync.data = this;
	m_broadcastQueue.reserve(2);

	err = uv_timer_init(&m_loop, &m_timer);
	if (err) {
		LOGERR(1, "failed to create timer, error " << uv_err_name(err));
		panic();
	}

	if (m_cache) {
		WriteLock lock(m_cachedBlocksLock);
		m_cache->load_all(m_pool->side_chain(), *this);
		m_cacheLoaded = true;
	}

	m_timer.data = this;
	err = uv_timer_start(&m_timer, on_timer, 10000, 2000);
	if (err) {
		LOGERR(1, "failed to start timer, error " << uv_err_name(err));
		panic();
	}

	start_listening(pool->params().m_p2pAddresses);
	connect_to_peers(pool->params().m_p2pPeerList);
	load_saved_peer_list();
}

P2PServer::~P2PServer()
{
	uv_timer_stop(&m_timer);
	uv_close(reinterpret_cast<uv_handle_t*>(&m_broadcastAsync), nullptr);

	shutdown_tcp();

	uv_mutex_destroy(&m_rngLock);
	uv_mutex_destroy(&m_blockLock);
	uv_mutex_destroy(&m_peerListLock);
	uv_mutex_destroy(&m_broadcastLock);
	uv_rwlock_destroy(&m_cachedBlocksLock);

	delete m_block;

	for (auto it : m_cachedBlocks) {
		delete it.second;
	}

	delete m_cache;
}

void P2PServer::add_cached_block(const PoolBlock& block)
{
	if (m_cacheLoaded) {
		LOGERR(1, "add_cached_block can only be called on startup. Fix the code!");
		return;
	}

	PoolBlock* new_block = new PoolBlock(block);
	m_cachedBlocks.insert({ new_block->m_sidechainId, new_block });
}

void P2PServer::store_in_cache(const PoolBlock& block)
{
	if (m_cache && block.m_verified && !block.m_invalid) {
		m_cache->store(block);
	}
}

void P2PServer::connect_to_peers(const std::string& peer_list)
{
	parse_address_list(peer_list,
		[this](bool is_v6, const std::string& /*address*/, const std::string& ip, int port)
		{
			connect_to_peer(is_v6, ip.c_str(), port);
		});
}

void P2PServer::on_connect_failed(bool is_v6, const raw_ip& ip, int port)
{
	MutexLock lock(m_peerListLock);

	for (auto it = m_peerList.begin(); it != m_peerList.end(); ++it) {
		if ((it->m_isV6 == is_v6) && (it->m_port == port) && (it->m_addr == ip)) {
			++it->m_numFailedConnections;
			if (it->m_numFailedConnections >= 10) {
				m_peerList.erase(it);
			}
			return;
		}
	}
}

void P2PServer::update_peer_connections()
{
	std::vector<Peer> peer_list;
	{
		MutexLock lock(m_peerListLock);
		peer_list = m_peerList;
	}

	const time_t cur_time = time(nullptr);

	std::vector<raw_ip> connected_clients;
	{
		MutexLock lock(m_clientsListLock);
		connected_clients.reserve(m_numConnections);
		for (P2PClient* client = static_cast<P2PClient*>(m_connectedClientsList->m_next); client != m_connectedClientsList; client = static_cast<P2PClient*>(client->m_next)) {
			connected_clients.emplace_back(client->m_addr);

			const int timeout = client->m_handshakeComplete ? 300 : 5;
			if (cur_time >= client->m_lastAlive + timeout) {
				const uint64_t idle_time = static_cast<uint64_t>(cur_time - client->m_lastAlive);
				LOGWARN(5, "peer " << static_cast<char*>(client->m_addrString) << " has been idle for " << idle_time << " seconds, disconnecting");
				client->close();
			}
		}
	}

	// Try to have at least 8 outgoing connections
	for (uint32_t i = m_numConnections - m_numIncomingConnections; (i < 8) && !peer_list.empty();) {
		const uint64_t k = get_random64() % peer_list.size();
		const Peer& peer = peer_list[k];

		bool already_connected = false;
		for (const raw_ip& ip : connected_clients) {
			if (ip == peer.m_addr) {
				already_connected = true;
				break;
			}
		}

		if (!already_connected && connect_to_peer(peer.m_isV6, peer.m_addr, peer.m_port)) {
			++i;
		}

		if (k + 1 < peer_list.size()) {
			peer_list[k] = peer_list.back();
		}
		peer_list.pop_back();
	}
}

void P2PServer::update_peer_list()
{
	const time_t cur_time = time(nullptr);
	{
		MutexLock lock(m_clientsListLock);

		for (P2PClient* client = static_cast<P2PClient*>(m_connectedClientsList->m_next); client != m_connectedClientsList; client = static_cast<P2PClient*>(client->m_next)) {
			if (!client->m_handshakeComplete || !client->m_handshakeSolutionSent) {
				continue;
			}

			if (cur_time >= client->m_lastPeerListRequest + 60) {
				client->m_lastPeerListRequest = cur_time;
				send(client,
					[](void* buf)
					{
						LOGINFO(5, "sending PEER_LIST_REQUEST");
						*reinterpret_cast<uint8_t*>(buf) = static_cast<uint8_t>(MessageId::PEER_LIST_REQUEST);
						return 1;
					});
			}
		}
	}
}

void P2PServer::save_peer_list_async()
{
	const time_t cur_time = time(nullptr);
	if (cur_time < m_peerListLastSaved + 300) {
		return;
	}

	struct Work
	{
		uv_work_t req;
		P2PServer* server;
	};

	Work* work = new Work{};
	work->req.data = work;
	work->server = this;

	const int err = uv_queue_work(&m_loop, &work->req,
		[](uv_work_t* req)
		{
			bkg_jobs_tracker.start("P2PServer::save_peer_list_async");
			reinterpret_cast<Work*>(req->data)->server->save_peer_list();
		},
		[](uv_work_t* req, int /*status*/)
		{
			delete reinterpret_cast<Work*>(req->data);
			bkg_jobs_tracker.stop("P2PServer::save_peer_list_async");
		});

	if (err) {
		LOGERR(1, "update_peer_list: uv_queue_work failed, error " << uv_err_name(err));
		delete work;
	}
}

void P2PServer::save_peer_list()
{
	std::ofstream f(saved_peer_list_file_name, std::ios::binary);

	if (!f.is_open()) {
		LOGERR(1, "failed to save peer list");
		return;
	}

	size_t num_peers;
	{
		MutexLock lock(m_peerListLock);

		num_peers = m_peerList.size();
		for (const Peer& p : m_peerList) {
			const char* addr_str;
			char addr_str_buf[64];

			if (p.m_isV6) {
				in6_addr addr{};
				memcpy(addr.s6_addr, p.m_addr.data, sizeof(addr.s6_addr));
				addr_str = inet_ntop(AF_INET6, &addr, addr_str_buf, sizeof(addr_str_buf));
				if (addr_str) {
					f << '[' << addr_str << "]:" << p.m_port << '\n';
				}
			}
			else {
				in_addr addr{};
				memcpy(&addr.s_addr, p.m_addr.data + 12, sizeof(addr.s_addr));
				addr_str = inet_ntop(AF_INET, &addr, addr_str_buf, sizeof(addr_str_buf));
				if (addr_str) {
					f << addr_str << ':' << p.m_port << '\n';
				}
			}
		}
	}

	f.close();

	LOGINFO(5, "peer list saved (" << num_peers << " peers)");
	m_peerListLastSaved = time(nullptr);
}

void P2PServer::load_saved_peer_list()
{
	std::ifstream f(saved_peer_list_file_name);
	if (!f.is_open()) {
		return;
	}

	std::string saved_list, address;
	while (!f.eof()) {
		std::getline(f, address);
		if (!address.empty()) {
			if (!saved_list.empty()) {
				saved_list += ',';
			}
			saved_list += address;
		}
	}
	f.close();

	MutexLock lock(m_peerListLock);

	parse_address_list(saved_list,
		[this](bool is_v6, const std::string& /*address*/, const std::string& ip, int port)
		{
			Peer p;
			if (is_v6) {
				sockaddr_in6 addr6;
				const int err = uv_ip6_addr(ip.c_str(), port, &addr6);
				if (err) {
					LOGERR(1, "failed to parse IPv6 address " << ip << ", error " << uv_err_name(err));
					return;
				}
				p.m_isV6 = true;
				memcpy(p.m_addr.data, &addr6.sin6_addr, sizeof(in6_addr));
				p.m_port = port;
				p.m_numFailedConnections = 0;
			}
			else {
				sockaddr_in addr4;
				const int err = uv_ip4_addr(ip.c_str(), port, &addr4);
				if (err) {
					LOGERR(1, "failed to parse IPv4 address " << ip << ", error " << uv_err_name(err));
					return;
				}
				p.m_isV6 = false;
				p.m_addr = {};
				p.m_addr.data[10] = 0xFF;
				p.m_addr.data[11] = 0xFF;
				memcpy(p.m_addr.data + 12, &addr4.sin_addr, sizeof(in_addr));
				p.m_port = port;
				p.m_numFailedConnections = 0;
			}

			bool already_added = false;
			for (const Peer& peer : m_peerList) {
				if ((peer.m_isV6 == p.m_isV6) && (peer.m_addr == p.m_addr)) {
					already_added = true;
					break;
				}
			}

			if (!already_added && !is_banned(p.m_addr)) {
				m_peerList.push_back(p);
			}
		});
	LOGINFO(5, "peer list loaded (" << m_peerList.size() << " peers)");
}

void P2PServer::update_peer_in_list(bool is_v6, const raw_ip& ip, int port)
{
	MutexLock lock(m_peerListLock);

	for (Peer& p : m_peerList) {
		if ((p.m_isV6 == is_v6) && (p.m_addr == ip)) {
			p.m_port = port;
			p.m_numFailedConnections = 0;
			return;
		}
	}

	if (!is_banned(ip)) {
		m_peerList.emplace_back(Peer{ is_v6, ip, port, 0 });
	}
}

void P2PServer::remove_peer_from_list(P2PClient* client)
{
	MutexLock lock(m_peerListLock);

	for (auto it = m_peerList.begin(); it != m_peerList.end(); ++it) {
		const Peer& p = *it;
		if ((p.m_isV6 == client->m_isV6) && (p.m_port == client->m_listenPort) && (p.m_addr == client->m_addr)) {
			m_peerList.erase(it);
			return;
		}
	}
}

void P2PServer::broadcast(const PoolBlock& block)
{
	Broadcast* data = new Broadcast{};

	data->blob.reserve(block.m_mainChainData.size() + block.m_sideChainData.size());
	data->blob = block.m_mainChainData;
	data->blob.insert(data->blob.end(), block.m_sideChainData.begin(), block.m_sideChainData.end());

	data->pruned_blob.reserve(block.m_mainChainData.size() + block.m_sideChainData.size() + 16 - block.m_mainChainOutputsBlobSize);
	data->pruned_blob.assign(block.m_mainChainData.begin(), block.m_mainChainData.begin() + block.m_mainChainOutputsOffset);

	// 0 outputs in the pruned blob
	data->pruned_blob.push_back(0);

	const uint64_t total_reward = std::accumulate(block.m_outputs.begin(), block.m_outputs.end(), 0ULL,
		[](uint64_t a, const PoolBlock::TxOutput& b)
		{
			return a + b.m_reward;
		});

	writeVarint(total_reward, data->pruned_blob);
	writeVarint(block.m_mainChainOutputsBlobSize, data->pruned_blob);

	data->pruned_blob.insert(data->pruned_blob.end(), block.m_mainChainData.begin() + block.m_mainChainOutputsOffset + block.m_mainChainOutputsBlobSize, block.m_mainChainData.end());
	data->pruned_blob.insert(data->pruned_blob.end(), block.m_sideChainData.begin(), block.m_sideChainData.end());

	data->ancestor_hashes.reserve(block.m_uncles.size() + 1);
	data->ancestor_hashes = block.m_uncles;
	data->ancestor_hashes.push_back(block.m_parent);

	LOGINFO(5, "Broadcasting block " << block.m_sidechainId << " (height " << block.m_sidechainHeight << "): " << data->pruned_blob.size() << '/' << data->blob.size() << " bytes (pruned/full)");

	{
		MutexLock lock(m_broadcastLock);
		m_broadcastQueue.push_back(data);
	}

	if (uv_is_closing(reinterpret_cast<uv_handle_t*>(&m_broadcastAsync))) {
		return;
	}

	const int err = uv_async_send(&m_broadcastAsync);
	if (err) {
		LOGERR(1, "uv_async_send failed, error " << uv_err_name(err));

		bool found = false;
		{
			MutexLock lock(m_broadcastLock);

			auto it = std::find(m_broadcastQueue.begin(), m_broadcastQueue.end(), data);
			if (it != m_broadcastQueue.end()) {
				found = true;
				m_broadcastQueue.erase(it);
			}
		}

		if (found) {
			delete data;
		}
	}
}

void P2PServer::on_broadcast()
{
	std::vector<Broadcast*> broadcast_queue;
	broadcast_queue.reserve(2);

	{
		MutexLock lock(m_broadcastLock);
		broadcast_queue = m_broadcastQueue;
		m_broadcastQueue.clear();
	}

	if (broadcast_queue.empty()) {
		return;
	}

	ON_SCOPE_LEAVE([&broadcast_queue]()
		{
			for (Broadcast* data : broadcast_queue) {
				delete data;
			}
		});

	MutexLock lock(m_clientsListLock);

	for (P2PClient* client = static_cast<P2PClient*>(m_connectedClientsList->m_next); client != m_connectedClientsList; client = static_cast<P2PClient*>(client->m_next)) {
		if (!client->m_handshakeComplete || !client->m_handshakeSolutionSent) {
			continue;
		}

		for (Broadcast* data : broadcast_queue) {
			send(client, [client, data](void* buf) {
				uint8_t* p0 = reinterpret_cast<uint8_t*>(buf);
				uint8_t* p = p0;

				bool send_pruned = true;
				{
					ReadLock lock(client->m_broadcastedHashesLock);
					for (const hash& id : data->ancestor_hashes) {
						if (client->m_broadcastedHashes.find(id) == client->m_broadcastedHashes.end()) {
							send_pruned = false;
							break;
						}
					}
				}

				if (send_pruned) {
					LOGINFO(5, "sending BLOCK_BROADCAST (pruned) to " << log::Gray() << static_cast<char*>(client->m_addrString));
					*(p++) = static_cast<uint8_t>(MessageId::BLOCK_BROADCAST);

					*reinterpret_cast<uint32_t*>(p) = static_cast<uint32_t>(data->pruned_blob.size());
					p += sizeof(uint32_t);

					memcpy(p, data->pruned_blob.data(), data->pruned_blob.size());
					p += data->pruned_blob.size();
				}
				else {
					LOGINFO(5, "sending BLOCK_BROADCAST (full)   to " << log::Gray() << static_cast<char*>(client->m_addrString));
					*(p++) = static_cast<uint8_t>(MessageId::BLOCK_BROADCAST);

					*reinterpret_cast<uint32_t*>(p) = static_cast<uint32_t>(data->blob.size());
					p += sizeof(uint32_t);

					memcpy(p, data->blob.data(), data->blob.size());
					p += data->blob.size();
				}

				return p - p0;
				});
		}
	}
}

uint64_t P2PServer::get_random64()
{
	MutexLock lock(m_rngLock);
	return m_rng();
}

void P2PServer::print_status()
{
	LOGINFO(0, "status" <<
		"\nConnections    = " << m_numConnections << " (" << m_numIncomingConnections << " incoming)" <<
		"\nPeer list size = " << m_peerList.size()
	);
}

void P2PServer::on_timer()
{
	flush_cache();
	download_missing_blocks();
	update_peer_connections();
	update_peer_list();
	save_peer_list_async();
}

void P2PServer::flush_cache()
{
	if (!m_cache) {
		return;
	}

	struct Work
	{
		uv_work_t req;
		BlockCache* cache;
	};

	Work* work = new Work{};
	work->req.data = work;
	work->cache = m_cache;

	const int err = uv_queue_work(&m_loop, &work->req,
		[](uv_work_t* req)
		{
			bkg_jobs_tracker.start("P2PServer::flush_cache");
			reinterpret_cast<Work*>(req->data)->cache->flush();
		},
		[](uv_work_t* req, int)
		{
			delete reinterpret_cast<Work*>(req->data);
			bkg_jobs_tracker.stop("P2PServer::flush_cache");
		});

	if (err) {
		LOGERR(1, "flush_cache: uv_queue_work failed, error " << uv_err_name(err));
	}
}

void P2PServer::download_missing_blocks()
{
	std::vector<hash> missing_blocks;
	m_pool->side_chain().get_missing_blocks(missing_blocks);

	if (missing_blocks.empty()) {
		return;
	}

	MutexLock lock(m_clientsListLock);

	if (m_numConnections == 0) {
		return;
	}

	std::vector<P2PClient*> clients;
	clients.reserve(m_numConnections);

	for (P2PClient* client = static_cast<P2PClient*>(m_connectedClientsList->m_next); client != m_connectedClientsList; client = static_cast<P2PClient*>(client->m_next)) {
		if (!client->m_handshakeComplete || !client->m_handshakeSolutionSent) {
			continue;
		}

		clients.emplace_back(client);
	}

	// Try to download each block from a random client
	for (const hash& id : missing_blocks) {
		send(clients[get_random64() % clients.size()],
			[this, &id](void* buf)
			{
				uint8_t* p0 = reinterpret_cast<uint8_t*>(buf);
				uint8_t* p = p0;

				LOGINFO(5, "sending BLOCK_REQUEST for id = " << id);
				*(p++) = static_cast<uint8_t>(MessageId::BLOCK_REQUEST);

				memcpy(p, id.h, HASH_SIZE);
				p += HASH_SIZE;

				return p - p0;
			});
	}
}

P2PServer::P2PClient::P2PClient()
	: m_peerId(0)
	, m_expectedMessage(MessageId::HANDSHAKE_CHALLENGE)
	, m_handshakeChallenge(0)
	, m_handshakeSolutionSent(false)
	, m_handshakeComplete(false)
	, m_listenPort(-1)
	, m_lastPeerListRequest(0)
	, m_lastAlive(0)
{
	uv_rwlock_init_checked(&m_broadcastedHashesLock);
}

P2PServer::P2PClient::~P2PClient()
{
	uv_rwlock_destroy(&m_broadcastedHashesLock);
}

void P2PServer::P2PClient::reset()
{
	Client::reset();

	m_peerId = 0;
	m_expectedMessage = MessageId::HANDSHAKE_CHALLENGE;
	m_handshakeChallenge = 0;
	m_handshakeSolutionSent = false;
	m_handshakeComplete = false;
	m_listenPort = -1;
	m_lastPeerListRequest = 0;
	m_lastAlive = 0;

	WriteLock lock(m_broadcastedHashesLock);
	m_broadcastedHashes.clear();
}

bool P2PServer::P2PClient::on_connect()
{
	m_lastAlive = time(nullptr);
	return send_handshake_challenge();
}

bool P2PServer::P2PClient::on_read(char* data, uint32_t size)
{
	P2PServer* server = static_cast<P2PServer*>(m_owner);
	if (!server) {
		return false;
	}

	if ((data != m_readBuf + m_numRead) || (data + size > m_readBuf + sizeof(m_readBuf))) {
		LOGERR(1, "peer " << static_cast<char*>(m_addrString) << " invalid data pointer or size in on_read()");
		ban(DEFAULT_BAN_TIME);
		server->remove_peer_from_list(this);
		return false;
	}

	m_numRead += size;

	uint8_t* buf_begin = reinterpret_cast<uint8_t*>(m_readBuf);
	uint8_t* buf = buf_begin;
	uint32_t bytes_left = m_numRead;

	uint32_t bytes_read;
	do {
		MessageId id = static_cast<MessageId>(buf[0]);

		// Peer must complete the handshake challenge before sending any other messages
		if (!m_handshakeComplete && (id != m_expectedMessage)) {
			LOGWARN(5, "peer " << static_cast<char*>(m_addrString) << " didn't send handshake messages first");
			ban(DEFAULT_BAN_TIME);
			server->remove_peer_from_list(this);
			return false;
		}

		bytes_read = 0;
		switch (id)
		{
		case MessageId::HANDSHAKE_CHALLENGE:
			LOGINFO(5, "peer " << log::Gray() << static_cast<char*>(m_addrString) << log::NoColor() << " sent HANDSHAKE_CHALLENGE");

			if (bytes_left >= 1 + CHALLENGE_SIZE + sizeof(uint64_t)) {
				bytes_read = 1 + CHALLENGE_SIZE + sizeof(uint64_t);
				if (!on_handshake_challenge(buf + 1)) {
					ban(DEFAULT_BAN_TIME);
					server->remove_peer_from_list(this);
					return false;
				}
				m_expectedMessage = MessageId::HANDSHAKE_SOLUTION;
			}
			break;

		case MessageId::HANDSHAKE_SOLUTION:
			LOGINFO(5, "peer " << log::Gray() << static_cast<char*>(m_addrString) << log::NoColor() << " sent HANDSHAKE_SOLUTION");

			if (bytes_left >= 1 + HASH_SIZE + CHALLENGE_SIZE) {
				bytes_read = 1 + HASH_SIZE + CHALLENGE_SIZE;
				if (!on_handshake_solution(buf + 1)) {
					ban(DEFAULT_BAN_TIME);
					server->remove_peer_from_list(this);
					return false;
				}
			}
			break;

		case MessageId::LISTEN_PORT:
			LOGINFO(5, "peer " << log::Gray() << static_cast<char*>(m_addrString) << log::NoColor() << " sent LISTEN_PORT");

			if (bytes_left >= 1 + sizeof(int32_t)) {
				bytes_read = 1 + sizeof(int32_t);
				if (!on_listen_port(buf + 1)) {
					ban(DEFAULT_BAN_TIME);
					server->remove_peer_from_list(this);
					return false;
				}
			}
			break;

		case MessageId::BLOCK_REQUEST:
			LOGINFO(5, "peer " << log::Gray() << static_cast<char*>(m_addrString) << log::NoColor() << " sent BLOCK_REQUEST");

			if (bytes_left >= 1 + HASH_SIZE) {
				bytes_read = 1 + HASH_SIZE;
				if (!on_block_request(buf + 1)) {
					ban(DEFAULT_BAN_TIME);
					server->remove_peer_from_list(this);
					return false;
				}
			}
			break;

		case MessageId::BLOCK_RESPONSE:
			LOGINFO(5, "peer " << log::Gray() << static_cast<char*>(m_addrString) << log::NoColor() << " sent BLOCK_RESPONSE");

			if (bytes_left >= 1 + sizeof(uint32_t)) {
				const uint32_t block_size = *reinterpret_cast<uint32_t*>(buf + 1);
				if (bytes_left >= 1 + sizeof(uint32_t) + block_size) {
					bytes_read = 1 + sizeof(uint32_t) + block_size;
					if (!on_block_response(buf + 1 + sizeof(uint32_t), block_size)) {
						ban(DEFAULT_BAN_TIME);
						server->remove_peer_from_list(this);
						return false;
					}
				}
			}
			break;

		case MessageId::BLOCK_BROADCAST:
			LOGINFO(5, "peer " << log::Gray() << static_cast<char*>(m_addrString) << log::NoColor() << " sent BLOCK_BROADCAST");

			if (bytes_left >= 1 + sizeof(uint32_t)) {
				const uint32_t block_size = *reinterpret_cast<uint32_t*>(buf + 1);
				if (bytes_left >= 1 + sizeof(uint32_t) + block_size) {
					bytes_read = 1 + sizeof(uint32_t) + block_size;
					if (!on_block_broadcast(buf + 1 + sizeof(uint32_t), block_size)) {
						ban(DEFAULT_BAN_TIME);
						server->remove_peer_from_list(this);
						return false;
					}
				}
			}
			break;

		case MessageId::PEER_LIST_REQUEST:
			LOGINFO(5, "peer " << log::Gray() << static_cast<char*>(m_addrString) << log::NoColor() << " sent PEER_LIST_REQUEST");

			if (bytes_left >= 1) {
				bytes_read = 1;
				if (!on_peer_list_request(buf + 1)) {
					ban(DEFAULT_BAN_TIME);
					server->remove_peer_from_list(this);
					return false;
				}
			}
			break;

		case MessageId::PEER_LIST_RESPONSE:
			LOGINFO(5, "peer " << log::Gray() << static_cast<char*>(m_addrString) << log::NoColor() << " sent PEER_LIST_RESPONSE");

			if (bytes_left >= 2) {
				const uint8_t num_peers = buf[1];
				if (num_peers > PEER_LIST_RESPONSE_MAX_PEERS) {
					LOGWARN(5, "peer " << log::Gray() << static_cast<char*>(m_addrString) << log::NoColor() << " sent too long peer list (" << num_peers << ')');
					ban(DEFAULT_BAN_TIME);
					server->remove_peer_from_list(this);
					return false;
				}

				if (bytes_left >= 2u + num_peers * 19) {
					bytes_read = 2u + num_peers * 19;
					if (!on_peer_list_response(buf + 1)) {
						ban(DEFAULT_BAN_TIME);
						server->remove_peer_from_list(this);
						return false;
					}
				}
			}
			break;
		}

		if (bytes_read) {
			buf += bytes_read;
			bytes_left -= bytes_read;
			m_lastAlive = time(nullptr);
		}
	} while (bytes_read && bytes_left);

	// Move the possible unfinished message to the beginning of m_readBuf to free up more space for reading
	if (buf != buf_begin) {
		m_numRead = static_cast<uint32_t>(buf_begin + m_numRead - buf);
		if (m_numRead > 0) {
			memmove(m_readBuf, buf, m_numRead);
		}
	}

	return true;
}

bool P2PServer::P2PClient::send_handshake_challenge()
{
	P2PServer* owner = static_cast<P2PServer*>(m_owner);
	m_handshakeChallenge = owner->get_random64();

	return owner->send(this,
		[this, owner](void* buf)
		{
			uint8_t* p0 = reinterpret_cast<uint8_t*>(buf);
			uint8_t* p = p0;

			LOGINFO(5, "sending HANDSHAKE_CHALLENGE");
			*(p++) = static_cast<uint8_t>(MessageId::HANDSHAKE_CHALLENGE);

			uint64_t k = m_handshakeChallenge;
			for (int i = 0; i < CHALLENGE_SIZE; ++i) {
				*(p++) = k & 0xFF;
				k >>= 8;
			}

			k = owner->get_peerId();
			memcpy(p, &k, sizeof(uint64_t));
			p += sizeof(uint64_t);

			return p - p0;
		});
}

void P2PServer::P2PClient::send_handshake_solution(const uint8_t (&challenge)[CHALLENGE_SIZE])
{
	P2PServer* server = static_cast<P2PServer*>(m_owner);

	struct Work
	{
		uv_work_t req;
		P2PClient* client;
		P2PServer* server;
		uint32_t reset_counter;

		uint8_t challenge[CHALLENGE_SIZE];
		uint64_t salt;
		uint8_t solution_salt[CHALLENGE_SIZE];
		hash solution;
	};

	Work* work = new Work{};
	work->req.data = work;
	work->client = this;
	work->server = server;
	work->reset_counter = m_resetCounter.load();

	memcpy(work->challenge, challenge, CHALLENGE_SIZE);
	work->salt = server->get_random64();

	const int err = uv_queue_work(&server->m_loop, &work->req,
		[](uv_work_t* req)
		{
			bkg_jobs_tracker.start("P2PServer::send_handshake_solution");

			Work* work = reinterpret_cast<Work*>(req->data);
			const std::vector<uint8_t>& consensus_id = work->server->m_pool->side_chain().consensus_id();
			const int consensus_id_size = static_cast<int>(consensus_id.size());

			for (size_t iter = 1;; ++iter, ++work->salt) {
				uint64_t k = work->salt;
				for (size_t i = 0; i < CHALLENGE_SIZE; ++i) {
					work->solution_salt[i] = k & 0xFF;
					k >>= 8;
				}

				keccak_custom(
					[work, &consensus_id, consensus_id_size](int offset) -> uint8_t
					{
						if (offset < CHALLENGE_SIZE) {
							return work->challenge[offset];
						}
						offset -= CHALLENGE_SIZE;

						if (offset < consensus_id_size) {
							return consensus_id[offset];
						}

						return work->solution_salt[offset - consensus_id_size];
					}, CHALLENGE_SIZE * 2 + static_cast<int>(consensus_id.size()), work->solution.h, HASH_SIZE);

				// We might've been disconnected while working on the challenge, do nothing in this case
				if (work->client->m_resetCounter.load() != work->reset_counter) {
					return;
				}

				if (work->client->m_isIncoming) {
					// This is an incoming connection, so it must do PoW, not us
					return;
				}

				uint64_t* value = reinterpret_cast<uint64_t*>(work->solution.h);

				uint64_t high;
				umul128(value[HASH_SIZE / sizeof(uint64_t) - 1], CHALLENGE_DIFFICULTY, &high);

				if (high == 0) {
					LOGINFO(5, "found handshake challenge solution after " << iter << " iterations");
					return;
				}
			}
		},
		[](uv_work_t* req, int)
		{
			Work* work = reinterpret_cast<Work*>(req->data);

			ON_SCOPE_LEAVE(
				[work]()
				{
					delete work;
					bkg_jobs_tracker.stop("P2PServer::send_handshake_solution");
				});

			// We might've been disconnected while working on the challenge, do nothing in this case
			if (work->client->m_resetCounter.load() != work->reset_counter) {
				return;
			}

			const bool result = work->server->send(work->client,
				[work](void* buf)
				{
					uint8_t* p0 = reinterpret_cast<uint8_t*>(buf);
					uint8_t* p = p0;

					LOGINFO(5, "sending HANDSHAKE_SOLUTION");
					*(p++) = static_cast<uint8_t>(MessageId::HANDSHAKE_SOLUTION);

					memcpy(p, work->solution.h, HASH_SIZE);
					p += HASH_SIZE;

					memcpy(p, work->solution_salt, CHALLENGE_SIZE);
					p += CHALLENGE_SIZE;

					if (work->client->m_handshakeComplete) {
						work->client->on_after_handshake(p);
					}

					return p - p0;
				});

			if (result) {
				work->client->m_handshakeSolutionSent = true;
			}
			else {
				work->client->close();
			}
		});

	if (err) {
		LOGERR(1, "send_handshake_solution: uv_queue_work failed, error " << uv_err_name(err));
		delete work;
	}
}

bool P2PServer::P2PClient::check_handshake_solution(const hash& solution, const uint8_t (&solution_salt)[CHALLENGE_SIZE])
{
	P2PServer* owner = static_cast<P2PServer*>(m_owner);

	const std::vector<uint8_t>& consensus_id = owner->m_pool->side_chain().consensus_id();
	const int consensus_id_size = static_cast<int>(consensus_id.size());

	uint8_t challenge[CHALLENGE_SIZE];

	uint64_t k = m_handshakeChallenge;
	for (size_t i = 0; i < CHALLENGE_SIZE; ++i) {
		challenge[i] = k & 0xFF;
		k >>= 8;
	}

	hash check{};
	keccak_custom(
		[this, &challenge, &solution_salt, &consensus_id, consensus_id_size](int offset) -> uint8_t
		{
			if (offset < CHALLENGE_SIZE) {
				return challenge[offset];
			}
			offset -= CHALLENGE_SIZE;

			if (offset < consensus_id_size) {
				return consensus_id[offset];
			}

			return solution_salt[offset - consensus_id_size];
		}, CHALLENGE_SIZE * 2 + static_cast<int>(consensus_id.size()), check.h, HASH_SIZE);

	return solution == check;
}

bool P2PServer::P2PClient::on_handshake_challenge(const uint8_t* buf)
{
	P2PServer* server = static_cast<P2PServer*>(m_owner);

	uint8_t challenge[CHALLENGE_SIZE];
	memcpy(challenge, buf, CHALLENGE_SIZE);

	uint64_t peer_id;
	memcpy(&peer_id, buf + CHALLENGE_SIZE, sizeof(uint64_t));

	if (peer_id == server->get_peerId()) {
		LOGWARN(5, "tried to connect to self");
		return false;
	}

	m_peerId = peer_id;

	bool same_peer = false;
	{
		MutexLock lock(server->m_clientsListLock);
		for (const P2PClient* client = static_cast<P2PClient*>(server->m_connectedClientsList->m_next); client != server->m_connectedClientsList; client = static_cast<P2PClient*>(client->m_next)) {
			if ((client != this) && (client->m_peerId == peer_id)) {
				LOGWARN(5, "tried to connect to the same peer twice: current connection " << static_cast<const char*>(client->m_addrString) << ", new connection " << static_cast<const char*>(m_addrString));
				same_peer = true;
				break;
			}
		}
	}

	if (same_peer) {
		close();
		return true;
	}

	send_handshake_solution(challenge);
	return true;
}

bool P2PServer::P2PClient::on_handshake_solution(const uint8_t* buf)
{
	hash solution;
	uint8_t solution_salt[CHALLENGE_SIZE];
	memcpy(&solution, buf, HASH_SIZE);
	memcpy(solution_salt, buf + HASH_SIZE, CHALLENGE_SIZE);

	// Check that incoming connection provided enough PoW
	if (m_isIncoming) {
		uint64_t* value = reinterpret_cast<uint64_t*>(solution.h);

		uint64_t high;
		umul128(value[HASH_SIZE / sizeof(uint64_t) - 1], CHALLENGE_DIFFICULTY, &high);

		if (high) {
			LOGWARN(5, "peer " << static_cast<char*>(m_addrString) << " handshake doesn't have enough PoW");
			return false;
		}
	}

	if (!check_handshake_solution(solution, solution_salt)) {
		LOGWARN(5, "peer " << static_cast<char*>(m_addrString) << " handshake failed");
		return false;
	}

	m_handshakeComplete = true;
	LOGINFO(5, "peer " << log::Gray() << static_cast<char*>(m_addrString) << log::NoColor() << " handshake completed");

	if (m_handshakeSolutionSent) {
		return m_owner->send(this,
			[this, &solution, &solution_salt](void* buf)
			{
				uint8_t* p0 = reinterpret_cast<uint8_t*>(buf);
				uint8_t* p = p0;
				on_after_handshake(p);
				return p - p0;
			});
	}

	return true;
}

void P2PServer::P2PClient::on_after_handshake(uint8_t* &p)
{
	LOGINFO(5, "sending LISTEN_PORT");
	*(p++) = static_cast<uint8_t>(MessageId::LISTEN_PORT);

	const int32_t port = m_owner->listen_port();
	memcpy(p, &port, sizeof(port));
	p += sizeof(port);

	LOGINFO(5, "sending BLOCK_REQUEST for the chain tip");
	*(p++) = static_cast<uint8_t>(MessageId::BLOCK_REQUEST);

	hash empty;
	memcpy(p, empty.h, HASH_SIZE);
	p += HASH_SIZE;
}

bool P2PServer::P2PClient::on_listen_port(const uint8_t* buf)
{
	int32_t port;
	memcpy(&port, buf, sizeof(port));

	if ((port < 0) || (port >= 65536)) {
		LOGWARN(5, "peer " << static_cast<char*>(m_addrString) << " sent an invalid listen port number");
		return false;
	}

	m_listenPort = port;

	static_cast<P2PServer*>(m_owner)->update_peer_in_list(m_isV6, m_addr, port);
	return true;
}

bool P2PServer::P2PClient::on_block_request(const uint8_t* buf)
{
	hash id;
	memcpy(id.h, buf, HASH_SIZE);

	P2PServer* server = static_cast<P2PServer*>(m_owner);

	std::vector<uint8_t> blob;
	if (!server->m_pool->side_chain().get_block_blob(id, blob) && !id.empty()) {
		LOGWARN(5, "got a request for block with id " << id << " but couldn't find it");
	}

	return server->send(this,
		[this, &blob](void* buf)
		{
			uint8_t* p0 = reinterpret_cast<uint8_t*>(buf);
			uint8_t* p = p0;

			LOGINFO(5, "sending BLOCK_RESPONSE");
			*(p++) = static_cast<uint8_t>(MessageId::BLOCK_RESPONSE);

			*reinterpret_cast<uint32_t*>(p) = static_cast<uint32_t>(blob.size());
			p += sizeof(uint32_t);

			memcpy(p, blob.data(), blob.size());
			p += blob.size();

			return p - p0;
		});
}

bool P2PServer::P2PClient::on_block_response(const uint8_t* buf, uint32_t size)
{
	if (!size) {
		LOGINFO(5, "peer " << log::Gray() << static_cast<char*>(m_addrString) << log::NoColor() << " sent an empty block response");
		return true;
	}

	P2PServer* server = static_cast<P2PServer*>(m_owner);

	MutexLock lock(server->m_blockLock);

	const int result = server->m_block->deserialize(buf, size, server->m_pool->side_chain());
	if (result != 0) {
		LOGWARN(3, "peer " << static_cast<char*>(m_addrString) << " sent an invalid block, error " << result);
		return false;
	}

	return handle_incoming_block_async(server->m_block);
}

bool P2PServer::P2PClient::on_block_broadcast(const uint8_t* buf, uint32_t size)
{
	if (!size) {
		LOGWARN(3, "peer " << static_cast<char*>(m_addrString) << " broadcasted an empty block");
		return false;
	}

	P2PServer* server = static_cast<P2PServer*>(m_owner);

	MutexLock lock(server->m_blockLock);

	const int result = server->m_block->deserialize(buf, size, server->m_pool->side_chain());
	if (result != 0) {
		LOGWARN(3, "peer " << static_cast<char*>(m_addrString) << " sent an invalid block, error " << result);
		return false;
	}

	{
		WriteLock lock2(m_broadcastedHashesLock);
		m_broadcastedHashes.insert(server->m_block->m_sidechainId);
	}

	if (server->m_block->m_prevId != server->m_pool->miner_data().prev_id) {
		// This peer is mining on top of a different Monero block, investigate it
		const uint64_t peer_height = server->m_block->m_txinGenHeight;
		const uint64_t our_height = server->m_pool->miner_data().height;

		if (peer_height < our_height) {
			if (our_height - peer_height < 5) {
				LOGINFO(5, "peer " << static_cast<char*>(m_addrString) << " broadcasted a stale block (mainchain height " << peer_height << ", expected >= " << our_height << "), ignoring it");
				return true;
			}
			else {
				LOGWARN(5, "peer " << static_cast<char*>(m_addrString) << " broadcasted an unreasonably stale block (mainchain height " << peer_height << ", expected >= " << our_height << ')');
				return false;
			}
		}
		else if (peer_height > our_height) {
			if (peer_height >= our_height + 2) {
				LOGWARN(4, "peer " << static_cast<char*>(m_addrString) << " is ahead on mainchain (height " << peer_height << ", your height " << our_height << "). Is your monerod stuck or lagging?");
			}
			return true;
		}
		else {
			LOGINFO(4, "peer " << static_cast<char*>(m_addrString) << " is mining on an alternative mainchain tip (height " << peer_height << "), ignoring it");
			return true;
		}
	}

	server->m_block->m_wantBroadcast = true;

	return handle_incoming_block_async(server->m_block);
}

bool P2PServer::P2PClient::on_peer_list_request(const uint8_t*)
{
	P2PServer* server = static_cast<P2PServer*>(m_owner);

	Peer peers[PEER_LIST_RESPONSE_MAX_PEERS];
	uint32_t num_selected_peers = 0;
	{
		MutexLock lock(server->m_clientsListLock);

		// Send every 4th peer on average, selected at random
		const uint32_t n = server->m_numConnections;
		const uint32_t peers_to_send_target = std::min<uint32_t>(PEER_LIST_RESPONSE_MAX_PEERS, std::max<uint32_t>(1, n / 4));

		for (P2PClient* client = static_cast<P2PClient*>(server->m_connectedClientsList->m_next); client != server->m_connectedClientsList; client = static_cast<P2PClient*>(client->m_next)) {
			if (client->m_listenPort < 0) {
				continue;
			}

			uint64_t hi;
			umul128(server->get_random64(), n, &hi);

			if ((hi < peers_to_send_target) && (client->m_addr != m_addr)) {
				peers[num_selected_peers++] = { client->m_isV6, client->m_addr, client->m_listenPort, 0 };

				if (num_selected_peers >= PEER_LIST_RESPONSE_MAX_PEERS) {
					break;
				}
			}
		}
	}

	return server->send(this,
		[&peers, num_selected_peers](void* buf)
		{
			uint8_t* p0 = reinterpret_cast<uint8_t*>(buf);
			uint8_t* p = p0;

			LOGINFO(5, "sending PEER_LIST_RESPONSE");
			*(p++) = static_cast<uint8_t>(MessageId::PEER_LIST_RESPONSE);
			*(p++) = static_cast<uint8_t>(num_selected_peers);

			// 19 bytes per peer
			for (uint32_t i = 0; i < num_selected_peers; ++i) {
				const Peer& peer = peers[i];
				*(p++) = peer.m_isV6 ? 1 : 0;

				memcpy(p, peer.m_addr.data, sizeof(peer.m_addr.data));
				p += sizeof(peer.m_addr.data);

				memcpy(p, &peer.m_port, 2);
				p += 2;
			}

			return p - p0;
		});
}

bool P2PServer::P2PClient::on_peer_list_response(const uint8_t* buf) const
{
	P2PServer* server = static_cast<P2PServer*>(m_owner);

	MutexLock lock(server->m_peerListLock);

	const uint32_t num_peers = *(buf++);
	for (uint32_t i = 0; i < num_peers; ++i) {
		const bool is_v6 = *(buf++) != 0;

		raw_ip ip;
		memcpy(ip.data, buf, sizeof(ip.data));
		buf += sizeof(ip.data);

		int port = 0;
		memcpy(&port, buf, 2);
		buf += 2;

		bool already_added = false;
		for (const Peer& p : server->m_peerList) {
			if ((p.m_isV6 == is_v6) && (p.m_addr == ip)) {
				already_added = true;
				break;
			}
		}

		if (!already_added && !server->is_banned(ip)) {
			server->m_peerList.emplace_back(Peer{ is_v6, ip, port, 0 });
		}
	}

	return true;
}

bool P2PServer::P2PClient::handle_incoming_block_async(PoolBlock* block)
{
	P2PServer* server = static_cast<P2PServer*>(m_owner);

	if (server->m_pool->side_chain().block_seen(*block)) {
		LOGINFO(6, "block " << block->m_sidechainId << " was received before, skipping it");
		return true;
	}

	struct Work
	{
		uv_work_t req;
		PoolBlock block;
		P2PClient* client;
		P2PServer* server;
		uint32_t client_reset_counter;
		std::vector<hash> missing_blocks;
	};

	Work* work = new Work{ {}, *block, this, server, m_resetCounter.load(), {} };
	work->req.data = work;

	const int err = uv_queue_work(&server->m_loop, &work->req,
		[](uv_work_t* req)
		{
			bkg_jobs_tracker.start("P2PServer::handle_incoming_block_async");
			Work* work = reinterpret_cast<Work*>(req->data);
			work->client->handle_incoming_block(work->server->m_pool, work->block, work->client_reset_counter, work->missing_blocks);
		},
		[](uv_work_t* req, int /*status*/)
		{
			Work* work = reinterpret_cast<Work*>(req->data);
			work->client->post_handle_incoming_block(work->client_reset_counter, work->missing_blocks);
			delete work;
			bkg_jobs_tracker.stop("P2PServer::handle_incoming_block_async");
		});

	if (err != 0) {
		LOGERR(1, "handle_incoming_block_async: uv_queue_work failed, error " << uv_err_name(err));
		delete work;
		return false;
	}

	return true;
}

void P2PServer::P2PClient::handle_incoming_block(p2pool* pool, PoolBlock& block, const uint32_t reset_counter, std::vector<hash>& missing_blocks)
{
	if (!pool->side_chain().add_external_block(block, missing_blocks)) {
		// Client sent bad data, disconnect and ban it
		if (reset_counter == m_resetCounter.load()) {
			ban(DEFAULT_BAN_TIME);
			static_cast<P2PServer*>(m_owner)->remove_peer_from_list(this);
			close();
		}
	}
}

void P2PServer::P2PClient::post_handle_incoming_block(const uint32_t reset_counter, std::vector<hash>& missing_blocks)
{
	// We might have been disconnected while side_chain was adding the block
	// In this case we can't send BLOCK_REQUEST messages on this connection anymore
	if (reset_counter != m_resetCounter.load()) {
		return;
	}

	if (missing_blocks.empty()) {
		return;
	}

	P2PServer* server = static_cast<P2PServer*>(m_owner);

	ReadLock lock(server->m_cachedBlocksLock);

	for (const hash& id : missing_blocks) {
		auto it = server->m_cachedBlocks.find(id);
		if (it != server->m_cachedBlocks.end()) {
			LOGINFO(5, "using cached block for id = " << id);
			handle_incoming_block_async(it->second);
			continue;
		}

		const bool result = m_owner->send(this,
			[this, &id](void* buf)
			{
				uint8_t* p0 = reinterpret_cast<uint8_t*>(buf);
				uint8_t* p = p0;

				LOGINFO(5, "sending BLOCK_REQUEST for id = " << id);
				*(p++) = static_cast<uint8_t>(MessageId::BLOCK_REQUEST);

				memcpy(p, id.h, HASH_SIZE);
				p += HASH_SIZE;

				return p - p0;
			});

		if (!result) {
			return;
		}
	}
}

} // namespace p2pool
