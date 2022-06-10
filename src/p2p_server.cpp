/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2022 SChernykh <https://github.com/SChernykh>
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
#include "json_rpc_request.h"
#include "json_parsers.h"
#include <rapidjson/document.h>
#include <fstream>
#include <numeric>

static constexpr char log_category_prefix[] = "P2PServer ";
static constexpr char saved_peer_list_file_name[] = "p2pool_peers.txt";
static const char* seed_nodes[] = { "seeds.p2pool.io", ""};
static const char* seed_nodes_mini[] = { "seeds-mini.p2pool.io", "" };

static constexpr int DEFAULT_BACKLOG = 16;
static constexpr uint64_t DEFAULT_BAN_TIME = 600;

static constexpr size_t SEND_BUF_MIN_SIZE = 256;

#include "tcp_server.inl"

namespace p2pool {

P2PServer::P2PServer(p2pool* pool)
	: TCPServer(P2PClient::allocate)
	, m_pool(pool)
	, m_cache(pool->params().m_blockCache ? new BlockCache() : nullptr)
	, m_cacheLoaded(false)
	, m_initialPeerList(pool->params().m_p2pPeerList)
	, m_cachedBlocks(nullptr)
	, m_rng(RandomDeviceSeed::instance)
	, m_block(new PoolBlock())
	, m_timer{}
	, m_timerCounter(0)
	, m_timerInterval(2)
	, m_peerListLastSaved(0)
{
	// Diffuse the initial state in case it has low quality
	m_rng.discard(10000);

	m_peerId = m_rng();

	const Params& params = pool->params();

	set_max_outgoing_peers(params.m_maxOutgoingPeers);
	set_max_incoming_peers(params.m_maxIncomingPeers);

	uv_mutex_init_checked(&m_rngLock);
	uv_mutex_init_checked(&m_blockLock);
	uv_mutex_init_checked(&m_peerListLock);
	uv_mutex_init_checked(&m_broadcastLock);
	uv_mutex_init_checked(&m_missingBlockRequestsLock);
	uv_rwlock_init_checked(&m_cachedBlocksLock);

	int err = uv_async_init(&m_loop, &m_broadcastAsync, on_broadcast);
	if (err) {
		LOGERR(1, "uv_async_init failed, error " << uv_err_name(err));
		panic();
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
	err = uv_timer_start(&m_timer, on_timer, 1000, m_timerInterval * 1000);
	if (err) {
		LOGERR(1, "failed to start timer, error " << uv_err_name(err));
		panic();
	}

	load_peer_list();
	start_listening(params.m_p2pAddresses);
}

P2PServer::~P2PServer()
{
	uv_timer_stop(&m_timer);
	uv_close(reinterpret_cast<uv_handle_t*>(&m_timer), nullptr);
	uv_close(reinterpret_cast<uv_handle_t*>(&m_broadcastAsync), nullptr);

	shutdown_tcp();

	uv_mutex_destroy(&m_rngLock);
	uv_mutex_destroy(&m_blockLock);
	uv_mutex_destroy(&m_peerListLock);
	uv_mutex_destroy(&m_broadcastLock);
	uv_mutex_destroy(&m_missingBlockRequestsLock);

	clear_cached_blocks();
	uv_rwlock_destroy(&m_cachedBlocksLock);

	delete m_block;
	delete m_cache;

	for (const Broadcast* data : m_broadcastQueue) {
		delete data;
	}
}

void P2PServer::add_cached_block(const PoolBlock& block)
{
	if (m_cacheLoaded) {
		LOGERR(1, "add_cached_block can only be called on startup. Fix the code!");
		return;
	}

	if (!m_cachedBlocks) {
		m_cachedBlocks = new unordered_map<hash, PoolBlock*>();
	}

	if (m_cachedBlocks->find(block.m_sidechainId) == m_cachedBlocks->end()) {
		PoolBlock* new_block = new PoolBlock(block);
		m_cachedBlocks->insert({ new_block->m_sidechainId, new_block });
	}
}

void P2PServer::clear_cached_blocks()
{
	if (!m_cachedBlocks) {
		return;
	}

	WriteLock lock(m_cachedBlocksLock);

	// cppcheck-suppress identicalConditionAfterEarlyExit
	if (!m_cachedBlocks) {
		return;
	}

	for (auto it : *m_cachedBlocks) {
		delete it.second;
	}

	delete m_cachedBlocks;
	m_cachedBlocks = nullptr;
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
		[this](bool is_v6, const std::string& /*address*/, std::string ip, int port)
		{
			if (resolve_host(ip, is_v6)) {
				connect_to_peer(is_v6, ip.c_str(), port);
			}
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
	const uint64_t cur_time = seconds_since_epoch();
	const uint64_t last_updated = m_pool->side_chain().last_updated();

	bool has_good_peers = false;

	unordered_set<raw_ip> connected_clients;
	{
		MutexLock lock(m_clientsListLock);
		connected_clients.reserve(m_numConnections);
		for (P2PClient* client = static_cast<P2PClient*>(m_connectedClientsList->m_next); client != m_connectedClientsList; client = static_cast<P2PClient*>(client->m_next)) {
			bool disconnected = false;

			const int timeout = client->m_handshakeComplete ? 300 : 10;
			if (cur_time >= client->m_lastAlive + timeout) {
				const uint64_t idle_time = static_cast<uint64_t>(cur_time - client->m_lastAlive);
				LOGWARN(5, "peer " << static_cast<char*>(client->m_addrString) << " has been idle for " << idle_time << " seconds, disconnecting");
				client->close();
				disconnected = true;
			}

			if (client->m_handshakeComplete && client->m_lastBroadcastTimestamp) {
				// - Side chain is at least 15 minutes newer (last_updated >= client->m_lastBroadcastTimestamp + 900)
				// - It's been at least 10 seconds since side chain updated (cur_time >= last_updated + 10)
				// - It's been at least 10 seconds since the last block request (peer is not syncing)
				// - Peer should have sent a broadcast by now
				if (last_updated && (cur_time >= std::max(last_updated, client->m_lastBlockrequestTimestamp) + 10) && (last_updated >= client->m_lastBroadcastTimestamp + 900)) {
					const uint64_t dt = last_updated - client->m_lastBroadcastTimestamp;
					LOGWARN(5, "peer " << static_cast<char*>(client->m_addrString) << " is not broadcasting blocks (last update " << dt << " seconds ago)");
					client->ban(DEFAULT_BAN_TIME);
					remove_peer_from_list(client);
					client->close();
					disconnected = true;
				}
			}

			if (!disconnected) {
				connected_clients.insert(client->m_addr);
				if (client->m_handshakeComplete && !client->m_handshakeInvalid && (client->m_listenPort >= 0)) {
					has_good_peers = true;
				}
			}
		}
	}

	std::vector<Peer> peer_list;
	{
		MutexLock lock(m_peerListLock);

		if ((m_timerCounter % 30) == 1) {
			// Update last seen time for currently connected peers
			for (Peer& p : m_peerList) {
				if (connected_clients.find(p.m_addr) != connected_clients.end()) {
					p.m_lastSeen = cur_time;
				}
			}

			// Remove all peers that weren't seen for more than 1 hour
			m_peerList.erase(std::remove_if(m_peerList.begin(), m_peerList.end(), [cur_time](const Peer& p) { return p.m_lastSeen + 3600 < cur_time; }), m_peerList.end());
		}

		peer_list = m_peerList;
	}

	uint32_t N = m_maxOutgoingPeers;

	// Special case: when we can't find p2pool peers, scan through monerod peers (try 25 peers at a time)
	if (!has_good_peers && !m_peerListMonero.empty()) {
		LOGINFO(3, "Scanning monerod peers, " << m_peerListMonero.size() << " left");
		for (uint32_t i = 0; (i < 25) && !m_peerListMonero.empty(); ++i) {
			peer_list.push_back(m_peerListMonero.back());
			m_peerListMonero.pop_back();
		}
		N = static_cast<uint32_t>(peer_list.size());
	}

	// Try to have at least N outgoing connections (N defaults to 10, can be set via --out-peers command line parameter)
	for (uint32_t i = m_numConnections - m_numIncomingConnections; (i < N) && !peer_list.empty();) {
		const uint64_t k = get_random64() % peer_list.size();
		const Peer& peer = peer_list[k];

		if ((connected_clients.find(peer.m_addr) == connected_clients.end()) && connect_to_peer(peer.m_isV6, peer.m_addr, peer.m_port)) {
			++i;
		}

		if (k + 1 < peer_list.size()) {
			peer_list[k] = peer_list.back();
		}
		peer_list.pop_back();
	}

	if (!has_good_peers && ((m_timerCounter % 30) == 0)) {
		LOGERR(1, "no connections to other p2pool nodes, check your monerod/p2pool/network/firewall setup!!!");
		load_peer_list();
		if (m_peerListMonero.empty()) {
			load_monerod_peer_list();
		}
	}
}

void P2PServer::update_peer_list()
{
	const uint64_t cur_time = seconds_since_epoch();
	{
		MutexLock lock(m_clientsListLock);

		for (P2PClient* client = static_cast<P2PClient*>(m_connectedClientsList->m_next); client != m_connectedClientsList; client = static_cast<P2PClient*>(client->m_next)) {
			if (!client->m_handshakeComplete || !client->m_handshakeSolutionSent) {
				continue;
			}

			if (cur_time >= client->m_nextOutgoingPeerListRequest) {
				// Send peer list requests at random intervals (60-120 seconds)
				client->m_nextOutgoingPeerListRequest = cur_time + (60 + (get_random64() % 61));

				const bool result = send(client,
					[](void* buf, size_t buf_size)
					{
						LOGINFO(5, "sending PEER_LIST_REQUEST");

						if (buf_size < SEND_BUF_MIN_SIZE) {
							return 0;
						}

						*reinterpret_cast<uint8_t*>(buf) = static_cast<uint8_t>(MessageId::PEER_LIST_REQUEST);
						return 1;
					});

				if (result) {
					client->m_lastPeerListRequestTime = std::chrono::high_resolution_clock::now();
					++client->m_peerListPendingRequests;
				}
			}
		}
	}
}

void P2PServer::save_peer_list_async()
{
	const uint64_t cur_time = seconds_since_epoch();
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
		LOGERR(1, "save_peer_list_async: uv_queue_work failed, error " << uv_err_name(err));
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

	std::vector<Peer> peer_list;
	{
		MutexLock lock(m_peerListLock);
		peer_list = m_peerList;
	}

	for (const Peer& p : peer_list) {
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

	f.close();

	LOGINFO(5, "peer list saved (" << peer_list.size() << " peers)");
	m_peerListLastSaved = seconds_since_epoch();
}

void P2PServer::load_peer_list()
{
	size_t old_size;
	{
		MutexLock lock(m_peerListLock);
		old_size = m_peerList.size();
	}

	std::string saved_list;

	// Load peers from seed nodes if we're on the default or mini sidechain
	auto load_from_seed_nodes = [&saved_list](const char** nodes, int p2p_port) {
		for (size_t i = 0; nodes[i][0]; ++i) {
			LOGINFO(4, "loading peers from " << nodes[i]);

			addrinfo hints{};
			hints.ai_family = AF_UNSPEC;
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_flags = AI_ADDRCONFIG;

			addrinfo* result;
			const int err = getaddrinfo(nodes[i], nullptr, &hints, &result);
			if (err == 0) {
				for (addrinfo* r = result; r != NULL; r = r->ai_next) {
					const char* addr_str;
					char addr_str_buf[64];

					char buf[128];
					buf[0] = '\0';

					log::Stream s(buf);

					if (r->ai_family == AF_INET6) {
						addr_str = inet_ntop(AF_INET6, &reinterpret_cast<sockaddr_in6*>(r->ai_addr)->sin6_addr, addr_str_buf, sizeof(addr_str_buf));
						if (addr_str) {
							s << '[' << addr_str << "]:" << p2p_port << '\0';
						}
					}
					else {
						addr_str = inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in*>(r->ai_addr)->sin_addr, addr_str_buf, sizeof(addr_str_buf));
						if (addr_str) {
							s << addr_str << ':' << p2p_port << '\0';
						}
					}

					if (s.m_pos) {
						LOGINFO(4, "added " << static_cast<const char*>(buf) << " from " << nodes[i]);
						if (!saved_list.empty()) {
							saved_list += ',';
						}
						saved_list += buf;
					}
				}
				freeaddrinfo(result);
			}
			else {
				LOGWARN(3, "getaddrinfo failed for " << nodes[i] << ": " << gai_strerror(err));
			}
		}
	};

	if (m_pool->side_chain().is_default()) {
		load_from_seed_nodes(seed_nodes, DEFAULT_P2P_PORT);
	}
	else if (m_pool->side_chain().is_mini()) {
		load_from_seed_nodes(seed_nodes_mini, DEFAULT_P2P_PORT_MINI);
	}

	// Finally load peers from p2pool_peers.txt
	std::ifstream f(saved_peer_list_file_name);
	if (f.is_open()) {
		std::string address;
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
	}

	if (saved_list.empty()) {
		return;
	}

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
			}

			bool already_added = false;
			for (const Peer& peer : m_peerList) {
				if ((peer.m_isV6 == p.m_isV6) && (peer.m_addr == p.m_addr)) {
					already_added = true;
					break;
				}
			}

			p.m_port = port;
			p.m_numFailedConnections = 0;
			p.m_lastSeen = seconds_since_epoch();

			if (!already_added && !is_banned(p.m_addr)) {
				m_peerList.push_back(p);
			}
		});

	LOGINFO(4, "peer list loaded (" << (m_peerList.size() - old_size) << " peers)");
}

void P2PServer::load_monerod_peer_list()
{
	const Params& params = m_pool->params();

	JSONRPCRequest::call(params.m_host, params.m_rpcPort, "/get_peer_list", params.m_rpcLogin,
		[this](const char* data, size_t size)
		{
#define ERR_STR "/get_peer_list RPC request returned invalid JSON "

			using namespace rapidjson;

			Document doc;
			if (doc.Parse(data, size).HasParseError()) {
				LOGWARN(4, ERR_STR "(parse error)");
				return;
			}

			if (!doc.IsObject()) {
				LOGWARN(4, ERR_STR "(not an object)");
				return;
			}

			if (!doc.HasMember("white_list")) {
				LOGWARN(4, ERR_STR "('white_list' not found)");
				return;
			}

			const auto& white_list = doc["white_list"];

			if (!white_list.IsArray()) {
				LOGWARN(4, ERR_STR "('white_list' is not an array)");
				return;
			}

#undef ERR_STR

			const int port = m_pool->side_chain().is_mini() ? DEFAULT_P2P_PORT_MINI : DEFAULT_P2P_PORT;

			const SizeType n = white_list.Size();

			m_peerListMonero.clear();
			m_peerListMonero.reserve(n);

			for (SizeType i = 0; i < n; ++i) {
				auto& v = white_list[i];
				const char* ip;
				uint64_t last_seen;
				if (!parseValue(v, "host", ip) || !parseValue(v, "last_seen", last_seen)) {
					continue;
				}

				Peer p;
				p.m_lastSeen = last_seen;

				if (strchr(ip, ':')) {
					sockaddr_in6 addr6;
					const int err = uv_ip6_addr(ip, port, &addr6);
					if (err) {
						continue;
					}
					p.m_isV6 = true;
					memcpy(p.m_addr.data, &addr6.sin6_addr, sizeof(in6_addr));
				}
				else {
					sockaddr_in addr4;
					const int err = uv_ip4_addr(ip, port, &addr4);
					if (err) {
						continue;
					}
					p.m_isV6 = false;
					p.m_addr = {};
					p.m_addr.data[10] = 0xFF;
					p.m_addr.data[11] = 0xFF;
					memcpy(p.m_addr.data + 12, &addr4.sin_addr, sizeof(in_addr));
				}

				p.m_port = port;
				p.m_numFailedConnections = 0;

				if (!is_banned(p.m_addr)) {
					m_peerListMonero.push_back(p);
				}
			}

			// Put recently active peers first in the list
			std::sort(m_peerListMonero.begin(), m_peerListMonero.end(), [](const Peer& a, const Peer& b) { return a.m_lastSeen > b.m_lastSeen; });

			LOGINFO(4, "monerod peer list loaded (" << m_peerListMonero.size() << " peers)");
		},
		[](const char* data, size_t size)
		{
			if (size > 0) {
				LOGWARN(4, "/get_peer_list RPC request failed: error " << log::const_buf(data, size));
			}
		}, &m_loop);
}

void P2PServer::update_peer_in_list(bool is_v6, const raw_ip& ip, int port)
{
	const uint64_t cur_time = seconds_since_epoch();

	MutexLock lock(m_peerListLock);

	for (Peer& p : m_peerList) {
		if ((p.m_isV6 == is_v6) && (p.m_addr == ip)) {
			p.m_port = port;
			p.m_numFailedConnections = 0;
			p.m_lastSeen = cur_time;
			return;
		}
	}

	if (!is_banned(ip)) {
		m_peerList.emplace_back(Peer{ is_v6, ip, port, 0, cur_time });
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

void P2PServer::remove_peer_from_list(const raw_ip& ip)
{
	MutexLock lock(m_peerListLock);

	for (auto it = m_peerList.begin(); it != m_peerList.end(); ++it) {
		const Peer& p = *it;
		if (p.m_addr == ip) {
			m_peerList.erase(it);
			return;
		}
	}
}

void P2PServer::broadcast(const PoolBlock& block)
{
	MinerData miner_data = m_pool->miner_data();

	if (block.m_txinGenHeight + 2 < miner_data.height) {
		LOGWARN(3, "Trying to broadcast a stale block " << block.m_sidechainId << " (mainchain height " << block.m_txinGenHeight << ", current height is " << miner_data.height << ')');
		return;
	}

	if (block.m_txinGenHeight > miner_data.height + 2) {
		LOGWARN(3, "Trying to broadcast a block " << block.m_sidechainId << " ahead on mainchain (mainchain height " << block.m_txinGenHeight << ", current height is " << miner_data.height << ')');
		return;
	}

	Broadcast* data = new Broadcast();

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
			for (const Broadcast* data : broadcast_queue) {
				delete data;
			}
		});

	MutexLock lock(m_clientsListLock);

	for (P2PClient* client = static_cast<P2PClient*>(m_connectedClientsList->m_next); client != m_connectedClientsList; client = static_cast<P2PClient*>(client->m_next)) {
		if (!client->m_handshakeComplete || !client->m_handshakeSolutionSent) {
			continue;
		}

		for (Broadcast* data : broadcast_queue) {
			send(client, [client, data](void* buf, size_t buf_size) -> size_t
			{
				uint8_t* p0 = reinterpret_cast<uint8_t*>(buf);
				uint8_t* p = p0;

				bool send_pruned = true;

				const hash* a = client->m_broadcastedHashes;
				const hash* b = client->m_broadcastedHashes + array_size(&P2PClient::m_broadcastedHashes);

				for (const hash& id : data->ancestor_hashes) {
					if (std::find(a, b, id) == b) {
						send_pruned = false;
						break;
					}
				}

				if (send_pruned) {
					LOGINFO(6, "sending BLOCK_BROADCAST (pruned) to " << log::Gray() << static_cast<char*>(client->m_addrString));

					const uint32_t len = static_cast<uint32_t>(data->pruned_blob.size());
					if (buf_size < SEND_BUF_MIN_SIZE + 1 + sizeof(uint32_t) + len) {
						return 0;
					}

					*(p++) = static_cast<uint8_t>(MessageId::BLOCK_BROADCAST);

					memcpy(p, &len, sizeof(uint32_t));
					p += sizeof(uint32_t);

					if (len) {
						memcpy(p, data->pruned_blob.data(), len);
						p += len;
					}
				}
				else {
					LOGINFO(5, "sending BLOCK_BROADCAST (full)   to " << log::Gray() << static_cast<char*>(client->m_addrString));

					const uint32_t len = static_cast<uint32_t>(data->blob.size());
					if (buf_size < SEND_BUF_MIN_SIZE + 1 + sizeof(uint32_t) + len) {
						return 0;
					}

					*(p++) = static_cast<uint8_t>(MessageId::BLOCK_BROADCAST);

					memcpy(p, &len, sizeof(uint32_t));
					p += sizeof(uint32_t);

					if (len) {
						memcpy(p, data->blob.data(), len);
						p += len;
					}
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
	MutexLock lock(m_peerListLock);

	LOGINFO(0, "status" <<
		"\nConnections    = " << m_numConnections.load() << " (" << m_numIncomingConnections.load() << " incoming)" <<
		"\nPeer list size = " << m_peerList.size() <<
		"\nUptime         = " << log::Duration(seconds_since_epoch() - m_pool->start_time())
	);
}

void P2PServer::show_peers()
{
	MutexLock lock(m_clientsListLock);

	size_t n = 0;

	for (P2PClient* client = static_cast<P2PClient*>(m_connectedClientsList->m_next); client != m_connectedClientsList; client = static_cast<P2PClient*>(client->m_next)) {
		if (client->m_listenPort >= 0) {
			LOGINFO(0, (client->m_isIncoming ? "I " : "O ") << client->m_pingTime << " ms\t" << static_cast<char*>(client->m_addrString));
			++n;
		}
	}

	LOGINFO(0, "Total: " << n << " peers");
}

void P2PServer::on_timer()
{
	++m_timerCounter;

	if (!m_initialPeerList.empty()) {
		connect_to_peers(m_initialPeerList);
		m_initialPeerList.clear();
	}

	flush_cache();
	download_missing_blocks();
	update_peer_list();
	save_peer_list_async();
	update_peer_connections();
	check_zmq();
}

void P2PServer::flush_cache()
{
	if (!m_cache || ((m_timerCounter % 30) != 2)) {
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
		delete work;
	}
}

void P2PServer::download_missing_blocks()
{
	std::vector<hash> missing_blocks;
	m_pool->side_chain().get_missing_blocks(missing_blocks);

	if (missing_blocks.empty()) {
		MutexLock lock(m_missingBlockRequestsLock);
		m_missingBlockRequests.clear();
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

	if (clients.empty()) {
		return;
	}

	ReadLock lock2(m_cachedBlocksLock);

	// Try to download each block from a random client
	for (const hash& id : missing_blocks) {
		P2PClient* client = clients[get_random64() % clients.size()];

		{
			MutexLock lock3(m_missingBlockRequestsLock);

			const uint64_t truncated_block_id = *reinterpret_cast<const uint64_t*>(id.h);
			if (!m_missingBlockRequests.insert({ client->m_peerId, truncated_block_id }).second) {
				// We already asked this peer about this block
				// Don't try to ask another peer, leave it for another timer tick
				continue;
			}
		}

		if (m_cachedBlocks) {
			auto it = m_cachedBlocks->find(id);
			if (it != m_cachedBlocks->end()) {
				LOGINFO(5, "using cached block for id = " << id);
				client->handle_incoming_block_async(it->second);
				continue;
			}
		}

		const bool result = send(client,
			[&id](void* buf, size_t buf_size) -> size_t
			{
				LOGINFO(5, "sending BLOCK_REQUEST for id = " << id);

				if (buf_size < SEND_BUF_MIN_SIZE) {
					return 0;
				}

				uint8_t* p0 = reinterpret_cast<uint8_t*>(buf);
				uint8_t* p = p0;

				*(p++) = static_cast<uint8_t>(MessageId::BLOCK_REQUEST);

				memcpy(p, id.h, HASH_SIZE);
				p += HASH_SIZE;

				return p - p0;
			});

		if (result) {
			++client->m_blockPendingRequests;
		}
	}
}

void P2PServer::check_zmq()
{
	if ((m_timerCounter % 30) != 0) {
		return;
	}

	const uint64_t cur_time = seconds_since_epoch();
	const uint64_t last_active = m_pool->zmq_last_active();

	if (cur_time >= last_active + 300) {
		const uint64_t dt = static_cast<uint64_t>(cur_time - last_active);
		LOGERR(1, "no ZMQ messages received from monerod in the last " << dt << " seconds, check your monerod/p2pool/network/firewall setup!!!");
		m_pool->restart_zmq();
	}
}

P2PServer::P2PClient::P2PClient()
	: m_peerId(0)
	, m_expectedMessage(MessageId::HANDSHAKE_CHALLENGE)
	, m_handshakeChallenge(0)
	, m_handshakeSolutionSent(false)
	, m_handshakeComplete(false)
	, m_handshakeInvalid(false)
	, m_listenPort(-1)
	, m_fastPeerListRequestCount(0)
	, m_prevIncomingPeerListRequest(0)
	, m_nextOutgoingPeerListRequest(0)
	, m_lastPeerListRequestTime{}
	, m_peerListPendingRequests(0)
	, m_pingTime(0)
	, m_blockPendingRequests(0)
	, m_chainTipBlockRequest(false)
	, m_lastAlive(0)
	, m_lastBroadcastTimestamp(0)
	, m_lastBlockrequestTimestamp(0)
	, m_broadcastedHashes{}
{
}

P2PServer::P2PClient::~P2PClient()
{
}

void P2PServer::P2PClient::reset()
{
	Client::reset();

	m_peerId = 0;
	m_expectedMessage = MessageId::HANDSHAKE_CHALLENGE;
	m_handshakeChallenge = 0;
	m_handshakeSolutionSent = false;
	m_handshakeComplete = false;
	m_handshakeInvalid = false;
	m_listenPort = -1;
	m_fastPeerListRequestCount = 0;
	m_prevIncomingPeerListRequest = 0;
	m_nextOutgoingPeerListRequest = 0;
	m_lastPeerListRequestTime = {};
	m_peerListPendingRequests = 0;
	m_pingTime = 0;
	m_blockPendingRequests = 0;
	m_chainTipBlockRequest = false;
	m_lastAlive = 0;
	m_lastBroadcastTimestamp = 0;
	m_lastBlockrequestTimestamp = 0;

	for (hash& h : m_broadcastedHashes) {
		h = {};
	}
	m_broadcastedHashesIndex = 0;
}

bool P2PServer::P2PClient::on_connect()
{
	P2PServer* server = static_cast<P2PServer*>(m_owner);

	if (!server) {
		return false;
	}

	if (m_isIncoming && (server->m_numIncomingConnections > server->m_maxIncomingPeers)) {
		LOGINFO(5, "Connection from " << log::Gray() << static_cast<char*>(m_addrString) << log::NoColor() << " rejected (incoming connections limit was reached)");
		return false;
	}

	// Don't allow multiple connections to/from the same IP
	// server->m_clientsListLock is already locked here
	for (P2PClient* client = static_cast<P2PClient*>(server->m_connectedClientsList->m_next); client != server->m_connectedClientsList; client = static_cast<P2PClient*>(client->m_next)) {
		if ((client != this) && (client->m_addr == m_addr)) {
			LOGINFO(5, "peer " << static_cast<char*>(m_addrString) << " is already connected as " << static_cast<char*>(client->m_addrString));
			return false;
		}
	}

	m_lastAlive = seconds_since_epoch();
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

	uint32_t num_block_requests = 0;

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
			if (m_handshakeComplete) {
				LOGWARN(4, "peer " << log::Gray() << static_cast<char*>(m_addrString) << log::NoColor() << " sent an unexpected HANDSHAKE_CHALLENGE");
				ban(DEFAULT_BAN_TIME);
				server->remove_peer_from_list(this);
				return false;
			}

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
			if (m_handshakeComplete) {
				LOGWARN(4, "peer " << log::Gray() << static_cast<char*>(m_addrString) << log::NoColor() << " sent an unexpected HANDSHAKE_SOLUTION");
				ban(DEFAULT_BAN_TIME);
				server->remove_peer_from_list(this);
				return false;
			}

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
			if (m_listenPort >= 0) {
				LOGWARN(4, "peer " << static_cast<char*>(m_addrString) << " sent an unexpected LISTEN_PORT");
				ban(DEFAULT_BAN_TIME);
				server->remove_peer_from_list(this);
				return false;
			}

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
			++num_block_requests;
			if (num_block_requests > 100) {
				LOGWARN(4, "peer " << log::Gray() << static_cast<char*>(m_addrString) << log::NoColor() << " sent too many BLOCK_REQUEST messages at once");
				ban(DEFAULT_BAN_TIME);
				server->remove_peer_from_list(this);
				return false;
			}

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
			if (m_blockPendingRequests <= 0) {
				LOGWARN(4, "peer " << log::Gray() << static_cast<char*>(m_addrString) << log::NoColor() << " sent an unexpected BLOCK_RESPONSE");
				ban(DEFAULT_BAN_TIME);
				server->remove_peer_from_list(this);
				return false;
			}

			LOGINFO(5, "peer " << log::Gray() << static_cast<char*>(m_addrString) << log::NoColor() << " sent BLOCK_RESPONSE");

			if (bytes_left >= 1 + sizeof(uint32_t)) {
				const uint32_t block_size = read_unaligned(reinterpret_cast<uint32_t*>(buf + 1));
				if (bytes_left >= 1 + sizeof(uint32_t) + block_size) {
					bytes_read = 1 + sizeof(uint32_t) + block_size;

					--m_blockPendingRequests;
					if (!on_block_response(buf + 1 + sizeof(uint32_t), block_size)) {
						ban(DEFAULT_BAN_TIME);
						server->remove_peer_from_list(this);
						return false;
					}
				}
			}
			break;

		case MessageId::BLOCK_BROADCAST:
			LOGINFO(6, "peer " << log::Gray() << static_cast<char*>(m_addrString) << log::NoColor() << " sent BLOCK_BROADCAST");

			if (bytes_left >= 1 + sizeof(uint32_t)) {
				const uint32_t block_size = read_unaligned(reinterpret_cast<uint32_t*>(buf + 1));
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
			if (m_peerListPendingRequests <= 0) {
				LOGWARN(4, "peer " << log::Gray() << static_cast<char*>(m_addrString) << log::NoColor() << " sent an unexpected PEER_LIST_RESPONSE");
				ban(DEFAULT_BAN_TIME);
				server->remove_peer_from_list(this);
				return false;
			}

			LOGINFO(5, "peer " << log::Gray() << static_cast<char*>(m_addrString) << log::NoColor() << " sent PEER_LIST_RESPONSE");

			if (bytes_left >= 2) {
				const uint32_t num_peers = buf[1];
				if (num_peers > PEER_LIST_RESPONSE_MAX_PEERS) {
					LOGWARN(5, "peer " << log::Gray() << static_cast<char*>(m_addrString) << log::NoColor() << " sent too long peer list (" << num_peers << ')');
					ban(DEFAULT_BAN_TIME);
					server->remove_peer_from_list(this);
					return false;
				}

				if (bytes_left >= 2u + num_peers * 19u) {
					bytes_read = 2u + num_peers * 19u;

					using namespace std::chrono;
					m_pingTime = duration_cast<milliseconds>(high_resolution_clock::now() - m_lastPeerListRequestTime).count();

					--m_peerListPendingRequests;
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
			m_lastAlive = seconds_since_epoch();
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

void P2PServer::P2PClient::on_read_failed(int /*err*/)
{
	on_disconnected();
}

void P2PServer::P2PClient::on_disconnected()
{
	if (!m_handshakeComplete) {
		LOGWARN(5, "peer " << static_cast<char*>(m_addrString) << " disconnected before finishing handshake");

		ban(DEFAULT_BAN_TIME);
		P2PServer* server = static_cast<P2PServer*>(m_owner);
		if (server) {
			server->remove_peer_from_list(this);
		}
	}
}

bool P2PServer::P2PClient::send_handshake_challenge()
{
	P2PServer* owner = static_cast<P2PServer*>(m_owner);
	m_handshakeChallenge = owner->get_random64();

	return owner->send(this,
		[this, owner](void* buf, size_t buf_size) -> size_t
		{
			LOGINFO(5, "sending HANDSHAKE_CHALLENGE");

			if (buf_size < SEND_BUF_MIN_SIZE) {
				return 0;
			}

			uint8_t* p0 = reinterpret_cast<uint8_t*>(buf);
			uint8_t* p = p0;

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
				[work](void* buf, size_t buf_size) -> size_t
				{
					LOGINFO(5, "sending HANDSHAKE_SOLUTION");

					if (buf_size < SEND_BUF_MIN_SIZE) {
						return 0;
					}

					uint8_t* p0 = reinterpret_cast<uint8_t*>(buf);
					uint8_t* p = p0;

					*(p++) = static_cast<uint8_t>(MessageId::HANDSHAKE_SOLUTION);

					memcpy(p, work->solution.h, HASH_SIZE);
					p += HASH_SIZE;

					memcpy(p, work->solution_salt, CHALLENGE_SIZE);
					p += CHALLENGE_SIZE;

					if (work->client->m_handshakeComplete && !work->client->m_handshakeInvalid) {
						work->client->on_after_handshake(p);
					}

					return p - p0;
				});

			if (result) {
				work->client->m_handshakeSolutionSent = true;

				if (work->client->m_handshakeComplete && work->client->m_handshakeInvalid) {
					work->client->ban(DEFAULT_BAN_TIME);
					work->server->remove_peer_from_list(work->client);
					work->client->close();
				}
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
		[&challenge, &solution_salt, &consensus_id, consensus_id_size](int offset) -> uint8_t
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
		LOGWARN(5, "tried to connect to self at " << static_cast<const char*>(m_addrString));
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
			m_handshakeInvalid = true;
		}
	}

	if (!check_handshake_solution(solution, solution_salt)) {
		LOGWARN(5, "peer " << static_cast<char*>(m_addrString) << " handshake failed");
		m_handshakeInvalid = true;
	}

	m_handshakeComplete = true;

	if (!m_handshakeInvalid) {
		LOGINFO(5, "peer " << log::Gray() << static_cast<char*>(m_addrString) << log::NoColor() << " handshake completed");
	}

	if (m_handshakeSolutionSent) {
		if (m_handshakeInvalid) {
			return false;
		}

		return m_owner->send(this,
			[this](void* buf, size_t buf_size) -> size_t
			{
				LOGINFO(5, "sending LISTEN_PORT and BLOCK_REQUEST for the chain tip");

				if (buf_size < SEND_BUF_MIN_SIZE) {
					return 0;
				}

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

	++m_blockPendingRequests;
	m_chainTipBlockRequest = true;
	m_lastBroadcastTimestamp = seconds_since_epoch();
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
	m_lastBlockrequestTimestamp = seconds_since_epoch();

	hash id;
	memcpy(id.h, buf, HASH_SIZE);

	P2PServer* server = static_cast<P2PServer*>(m_owner);

	std::vector<uint8_t> blob;
	if (!server->m_pool->side_chain().get_block_blob(id, blob) && !id.empty()) {
		LOGWARN(5, "got a request for block with id " << id << " but couldn't find it");
	}

	return server->send(this,
		[&blob](void* buf, size_t buf_size) -> size_t
		{
			LOGINFO(5, "sending BLOCK_RESPONSE");

			const uint32_t len = static_cast<uint32_t>(blob.size());

			if (buf_size < SEND_BUF_MIN_SIZE + 1 + sizeof(uint32_t) + len) {
				return 0;
			}

			uint8_t* p0 = reinterpret_cast<uint8_t*>(buf);
			uint8_t* p = p0;

			*(p++) = static_cast<uint8_t>(MessageId::BLOCK_RESPONSE);

			memcpy(p, &len, sizeof(uint32_t));
			p += sizeof(uint32_t);

			if (len) {
				memcpy(p, blob.data(), len);
				p += len;
			}

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

	if (m_chainTipBlockRequest) {
		m_chainTipBlockRequest = false;

		const uint64_t peer_height = server->m_block->m_txinGenHeight;
		const uint64_t our_height = server->m_pool->miner_data().height;

		if (peer_height + 2 < our_height) {
			LOGWARN(4, "peer " << static_cast<char*>(m_addrString) << " is mining on top of a stale block (mainchain height " << peer_height << ", expected >= " << our_height << ')');
			return false;
		}
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

	m_broadcastedHashes[m_broadcastedHashesIndex.fetch_add(1) % array_size(&P2PClient::m_broadcastedHashes)] = server->m_block->m_sidechainId;

	MinerData miner_data = server->m_pool->miner_data();

	if (server->m_block->m_prevId != miner_data.prev_id) {
		// This peer is mining on top of a different Monero block, investigate it
		const uint64_t peer_height = server->m_block->m_txinGenHeight;
		const uint64_t our_height = miner_data.height;

		if (peer_height < our_height) {
			if (our_height - peer_height < 5) {
				using namespace std::chrono;
				const int64_t elapsed_ms = duration_cast<milliseconds>(high_resolution_clock::now() - miner_data.time_received).count();
				if (our_height - peer_height > 1) {
					LOGWARN(5, "peer " << static_cast<char*>(m_addrString) << " broadcasted a stale block (" << elapsed_ms << " ms late, mainchain height " << peer_height << ", expected >= " << our_height << "), ignoring it");
					return true;
				}
				else {
					LOGINFO(5, "peer " << static_cast<char*>(m_addrString) << " broadcasted a stale block (" << elapsed_ms << " ms late, mainchain height " << peer_height << ", expected >= " << our_height << ")");
				}
			}
			else {
				LOGWARN(4, "peer " << static_cast<char*>(m_addrString) << " broadcasted an unreasonably stale block (mainchain height " << peer_height << ", expected >= " << our_height << ')');
				return false;
			}
		}
		else if (peer_height > our_height) {
			if (peer_height >= our_height + 2) {
				LOGWARN(3, "peer " << static_cast<char*>(m_addrString) << " is ahead on mainchain (height " << peer_height << ", your height " << our_height << "). Is your monerod stuck or lagging?");
			}
		}
		else {
			LOGINFO(4, "peer " << static_cast<char*>(m_addrString) << " is mining on an alternative mainchain tip (height " << peer_height << ")");
		}
	}

	server->m_block->m_wantBroadcast = true;

	m_lastBroadcastTimestamp = seconds_since_epoch();

	return handle_incoming_block_async(server->m_block);
}

bool P2PServer::P2PClient::on_peer_list_request(const uint8_t*)
{
	P2PServer* server = static_cast<P2PServer*>(m_owner);
	const uint64_t cur_time = seconds_since_epoch();

	// Allow peer list requests no more than once every 30 seconds
	if (cur_time - m_prevIncomingPeerListRequest < 30) {
		++m_fastPeerListRequestCount;
		if (m_fastPeerListRequestCount >= 3) {
			LOGWARN(4, "peer " << static_cast<char*>(m_addrString) << " is sending PEER_LIST_REQUEST too often");
			return false;
		}
	}

	m_prevIncomingPeerListRequest = cur_time;

	Peer peers[PEER_LIST_RESPONSE_MAX_PEERS];
	uint32_t num_selected_peers = 0;
	{
		MutexLock lock(server->m_clientsListLock);

		// Send every 4th peer on average, selected at random
		const uint32_t peers_to_send_target = std::min<uint32_t>(PEER_LIST_RESPONSE_MAX_PEERS, std::max<uint32_t>(1, server->m_numConnections / 4));
		uint32_t n = 0;

		for (P2PClient* client = static_cast<P2PClient*>(server->m_connectedClientsList->m_next); client != server->m_connectedClientsList; client = static_cast<P2PClient*>(client->m_next)) {
			if ((client->m_listenPort < 0) || (client->m_addr == m_addr)) {
				continue;
			}

			const Peer p{ client->m_isV6, client->m_addr, client->m_listenPort, 0, 0 };
			++n;

			// Use https://en.wikipedia.org/wiki/Reservoir_sampling algorithm
			if (num_selected_peers < peers_to_send_target) {
				peers[num_selected_peers++] = p;
				continue;
			}

			uint64_t k;
			umul128(server->get_random64(), n, &k);

			if (k < peers_to_send_target) {
				peers[k] = p;
			}
		}
	}

	return server->send(this,
		[&peers, num_selected_peers](void* buf, size_t buf_size) -> size_t
		{
			LOGINFO(5, "sending PEER_LIST_RESPONSE");

			if (buf_size < SEND_BUF_MIN_SIZE + 2 + num_selected_peers * 19) {
				return 0;
			}

			uint8_t* p0 = reinterpret_cast<uint8_t*>(buf);
			uint8_t* p = p0;

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
	const uint64_t cur_time = seconds_since_epoch();

	MutexLock lock(server->m_peerListLock);

	const uint32_t num_peers = *(buf++);
	for (uint32_t i = 0; i < num_peers; ++i) {
		const bool is_v6 = *(buf++) != 0;

		raw_ip ip;
		memcpy(ip.data, buf, sizeof(ip.data));
		buf += sizeof(ip.data);

		// Fill in default bytes for IPv4 addresses
		if (!is_v6) {
			memset(ip.data, 0, 10);
			ip.data[10] = 0xFF;
			ip.data[11] = 0xFF;
		}

		int port = 0;
		memcpy(&port, buf, 2);
		buf += 2;

		bool already_added = false;
		for (Peer& p : server->m_peerList) {
			if ((p.m_isV6 == is_v6) && (p.m_addr == ip)) {
				already_added = true;
				p.m_lastSeen = cur_time;
				break;
			}
		}

		if (!already_added && !server->is_banned(ip)) {
			server->m_peerList.emplace_back(Peer{ is_v6, ip, port, 0, cur_time });
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
		raw_ip client_ip;
		std::vector<hash> missing_blocks;
	};

	Work* work = new Work{ {}, *block, this, server, m_resetCounter.load(), m_addr, {} };
	work->req.data = work;

	const int err = uv_queue_work(&server->m_loop, &work->req,
		[](uv_work_t* req)
		{
			bkg_jobs_tracker.start("P2PServer::handle_incoming_block_async");
			Work* work = reinterpret_cast<Work*>(req->data);
			work->client->handle_incoming_block(work->server->m_pool, work->block, work->client_reset_counter, work->client_ip, work->missing_blocks);
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

void P2PServer::P2PClient::handle_incoming_block(p2pool* pool, PoolBlock& block, const uint32_t reset_counter, const raw_ip& addr, std::vector<hash>& missing_blocks)
{
	if (!pool->side_chain().add_external_block(block, missing_blocks)) {
		// Client sent bad data, disconnect and ban it
		if (reset_counter == m_resetCounter.load()) {
			close();
			LOGWARN(3, "peer " << static_cast<char*>(m_addrString) << " banned for " << DEFAULT_BAN_TIME << " seconds");
		}
		else {
			const log::hex_buf addr_hex(addr.data, sizeof(addr.data));
			LOGWARN(3, "IP " << addr_hex << " banned for " << DEFAULT_BAN_TIME << " seconds");
		}

		P2PServer* server = pool->p2p_server();
		server->ban(addr, DEFAULT_BAN_TIME);
		server->remove_peer_from_list(addr);
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
		if (server->m_cachedBlocks) {
			auto it = server->m_cachedBlocks->find(id);
			if (it != server->m_cachedBlocks->end()) {
				LOGINFO(5, "using cached block for id = " << id);
				handle_incoming_block_async(it->second);
				continue;
			}
		}

		const bool result = m_owner->send(this,
			[&id](void* buf, size_t buf_size) -> size_t
			{
				LOGINFO(5, "sending BLOCK_REQUEST for id = " << id);

				if (buf_size < SEND_BUF_MIN_SIZE + 1 + HASH_SIZE) {
					return 0;
				}

				uint8_t* p0 = reinterpret_cast<uint8_t*>(buf);
				uint8_t* p = p0;

				*(p++) = static_cast<uint8_t>(MessageId::BLOCK_REQUEST);

				memcpy(p, id.h, HASH_SIZE);
				p += HASH_SIZE;

				return p - p0;
			});

		if (!result) {
			return;
		}

		++m_blockPendingRequests;
	}
}

} // namespace p2pool
