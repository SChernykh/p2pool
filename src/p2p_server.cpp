/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2023 SChernykh <https://github.com/SChernykh>
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
#include "block_template.h"
#include "p2pool_api.h"
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
	, m_blockDeserializeResult(0)
	, m_timer{}
	, m_timerCounter(0)
	, m_timerInterval(2)
	, m_peerListLastSaved(0)
	, m_lookForMissingBlocks(true)
	, m_fastestPeer(nullptr)
{
	m_blockDeserializeBuf.reserve(131072);

	// Diffuse the initial state in case it has low quality
	m_rng.discard(10000);

	m_peerId = m_rng();

	const Params& params = pool->params();

	if (!params.m_socks5Proxy.empty()) {
		parse_address_list(params.m_socks5Proxy,
			[this](bool is_v6, const std::string& /*address*/, const std::string& ip, int port)
			{
				if (!str_to_ip(is_v6, ip.c_str(), m_socks5ProxyIP)) {
					PANIC_STOP();
				}
				m_socks5ProxyV6 = is_v6;
				m_socks5ProxyPort = port;
			});
		m_socks5Proxy = params.m_socks5Proxy;
	}

	set_max_outgoing_peers(params.m_maxOutgoingPeers);
	set_max_incoming_peers(params.m_maxIncomingPeers);

	uv_mutex_init_checked(&m_blockLock);
	uv_mutex_init_checked(&m_peerListLock);
	uv_mutex_init_checked(&m_broadcastLock);
	uv_rwlock_init_checked(&m_cachedBlocksLock);
	uv_mutex_init_checked(&m_connectToPeersLock);

	int err = uv_async_init(&m_loop, &m_broadcastAsync, on_broadcast);
	if (err) {
		LOGERR(1, "uv_async_init failed, error " << uv_err_name(err));
		PANIC_STOP();
	}
	m_broadcastAsync.data = this;
	m_broadcastQueue.reserve(2);

	err = uv_async_init(&m_loop, &m_connectToPeersAsync, on_connect_to_peers);
	if (err) {
		LOGERR(1, "uv_async_init failed, error " << uv_err_name(err));
		PANIC_STOP();
	}
	m_connectToPeersAsync.data = this;

	err = uv_async_init(&m_loop, &m_showPeersAsync, on_show_peers);
	if (err) {
		LOGERR(1, "uv_async_init failed, error " << uv_err_name(err));
		PANIC_STOP();
	}
	m_showPeersAsync.data = this;

	err = uv_timer_init(&m_loop, &m_timer);
	if (err) {
		LOGERR(1, "failed to create timer, error " << uv_err_name(err));
		PANIC_STOP();
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
		PANIC_STOP();
	}

	load_peer_list();
	start_listening(params.m_p2pAddresses, params.m_upnp);
}

P2PServer::~P2PServer()
{
	shutdown_tcp();

	uv_mutex_destroy(&m_blockLock);
	uv_mutex_destroy(&m_peerListLock);
	uv_mutex_destroy(&m_broadcastLock);

	clear_cached_blocks();
	uv_rwlock_destroy(&m_cachedBlocksLock);

	uv_mutex_destroy(&m_connectToPeersLock);

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

void P2PServer::connect_to_peers_async(const char* peer_list)
{
	{
		MutexLock lock(m_connectToPeersLock);
		if (!m_connectToPeersData.empty()) {
			m_connectToPeersData.append(1, ',');
		}
		m_connectToPeersData.append(peer_list);
	}

	if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(&m_connectToPeersAsync))) {
		uv_async_send(&m_connectToPeersAsync);
	}
}

void P2PServer::on_connect_to_peers(uv_async_t* handle)
{
	P2PServer* server = reinterpret_cast<P2PServer*>(handle->data);

	std::string peer_list;
	{
		MutexLock lock(server->m_connectToPeersLock);
		peer_list = std::move(server->m_connectToPeersData);
	}

	if (!peer_list.empty()) {
		server->connect_to_peers(peer_list);
	}
}

void P2PServer::connect_to_peers(const std::string& peer_list)
{
	parse_address_list(peer_list,
		[this](bool is_v6, const std::string& /*address*/, std::string ip, int port)
		{
			if (!m_pool->params().m_dns || resolve_host(ip, is_v6)) {
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
	check_event_loop_thread(__func__);

	const uint64_t cur_time = seconds_since_epoch();
	const uint64_t last_updated = m_pool->side_chain().last_updated();

	bool has_good_peers = false;
	m_fastestPeer = nullptr;

	unordered_set<raw_ip> connected_clients;

	connected_clients.reserve(m_numConnections);
	for (P2PClient* client = static_cast<P2PClient*>(m_connectedClientsList->m_next); client != m_connectedClientsList; client = static_cast<P2PClient*>(client->m_next)) {
		const int timeout = client->m_handshakeComplete ? 300 : 10;
		if ((cur_time >= client->m_lastAlive + timeout) && (client->m_socks5ProxyState == Client::Socks5ProxyState::Default)) {
			const uint64_t idle_time = static_cast<uint64_t>(cur_time - client->m_lastAlive);
			LOGWARN(5, "peer " << static_cast<char*>(client->m_addrString) << " has been idle for " << idle_time << " seconds, disconnecting");
			client->close();
			continue;
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
				continue;
			}
		}

		connected_clients.insert(client->m_addr);
		if (client->is_good()) {
			has_good_peers = true;
			if ((client->m_pingTime >= 0) && (!m_fastestPeer || (m_fastestPeer->m_pingTime > client->m_pingTime))) {
				m_fastestPeer = client;
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

	if (!has_good_peers && ((m_timerCounter % 10) == 0)) {
		LOGERR(1, "no connections to other p2pool nodes, check your monerod/p2pool/network/firewall setup!!!");
		load_peer_list();
		if (m_peerListMonero.empty()) {
			load_monerod_peer_list();
		}
	}
}

void P2PServer::update_peer_list()
{
	check_event_loop_thread(__func__);

	const uint64_t cur_time = seconds_since_epoch();
	for (P2PClient* client = static_cast<P2PClient*>(m_connectedClientsList->m_next); client != m_connectedClientsList; client = static_cast<P2PClient*>(client->m_next)) {
		if (client->is_good() && (cur_time >= client->m_nextOutgoingPeerListRequest)) {
			send_peer_list_request(client, cur_time);
		}
	}
}

void P2PServer::send_peer_list_request(P2PClient* client, uint64_t cur_time)
{
	// Send peer list requests at random intervals (60-120 seconds)
	client->m_nextOutgoingPeerListRequest = cur_time + (60 + (get_random64() % 61));

	const bool result = send(client,
		[client](void* buf, size_t buf_size)
		{
			LOGINFO(6, "sending PEER_LIST_REQUEST to " << static_cast<char*>(client->m_addrString));

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
			BACKGROUND_JOB_START(P2PServer::save_peer_list_async);
			reinterpret_cast<Work*>(req->data)->server->save_peer_list();
		},
		[](uv_work_t* req, int /*status*/)
		{
			delete reinterpret_cast<Work*>(req->data);
			BACKGROUND_JOB_STOP(P2PServer::save_peer_list_async);
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

	f.flush();
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
			int err = getaddrinfo(nodes[i], nullptr, &hints, &result);
			if (err) {
				LOGWARN(4, "getaddrinfo failed for " << nodes[i] << ": " << gai_strerror(err) << ", retrying with IPv4 only");
				hints.ai_family = AF_INET;
				err = getaddrinfo(nodes[i], nullptr, &hints, &result);
			}
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

	if (m_pool->params().m_dns) {
		if (m_pool->side_chain().is_default()) {
			load_from_seed_nodes(seed_nodes, DEFAULT_P2P_PORT);
		}
		else if (m_pool->side_chain().is_mini()) {
			load_from_seed_nodes(seed_nodes_mini, DEFAULT_P2P_PORT_MINI);
		}
	}

	// Finally load peers from p2pool_peers.txt
	std::ifstream f(saved_peer_list_file_name);
	if (f.is_open()) {
		std::string address;
		while (f.good()) {
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
			if (!str_to_ip(is_v6, ip.c_str(), p.m_addr)) {
				return;
			}
			p.m_isV6 = is_v6;

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

	JSONRPCRequest::call(params.m_host, params.m_rpcPort, "/get_peer_list", params.m_rpcLogin, m_socks5Proxy,
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
				p.m_isV6 = (strchr(ip, ':') != 0);

				if (!str_to_ip(p.m_isV6, ip, p.m_addr)) {
					continue;
				}

				p.m_port = port;
				p.m_numFailedConnections = 0;

				if (!is_banned(p.m_addr)) {
					m_peerListMonero.push_back(p);
				}
			}

			// Put recently active peers last in the list (it will be scanned backwards)
			std::sort(m_peerListMonero.begin(), m_peerListMonero.end(), [](const Peer& a, const Peer& b) { return a.m_lastSeen < b.m_lastSeen; });

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

void P2PServer::broadcast(const PoolBlock& block, const PoolBlock* parent)
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

	Broadcast* data = new Broadcast{};

	data->id = block.m_sidechainId;
	data->received_timestamp = block.m_receivedTimestamp;

	int outputs_offset, outputs_blob_size;
	const std::vector<uint8_t> mainchain_data = block.serialize_mainchain_data(nullptr, nullptr, &outputs_offset, &outputs_blob_size);
	const std::vector<uint8_t> sidechain_data = block.serialize_sidechain_data();

	data->blob.reserve(mainchain_data.size() + sidechain_data.size());
	data->blob = mainchain_data;
	data->blob.insert(data->blob.end(), sidechain_data.begin(), sidechain_data.end());

	data->pruned_blob.reserve(mainchain_data.size() + sidechain_data.size() + 16 - outputs_blob_size);
	data->pruned_blob.assign(mainchain_data.begin(), mainchain_data.begin() + outputs_offset);

	// 0 outputs in the pruned blob
	data->pruned_blob.push_back(0);

	const uint64_t total_reward = std::accumulate(block.m_outputs.begin(), block.m_outputs.end(), 0ULL,
		[](uint64_t a, const PoolBlock::TxOutput& b)
		{
			return a + b.m_reward;
		});

	writeVarint(total_reward, data->pruned_blob);
	writeVarint(outputs_blob_size, data->pruned_blob);

	data->pruned_blob.insert(data->pruned_blob.end(), mainchain_data.begin() + outputs_offset + outputs_blob_size, mainchain_data.end());

	const size_t N = block.m_transactions.size();
	if ((N > 1) && parent && (parent->m_transactions.size() > 1)) {
		unordered_map<hash, size_t> parent_transactions;
		parent_transactions.reserve(parent->m_transactions.size());

		for (size_t i = 1; i < parent->m_transactions.size(); ++i) {
			parent_transactions.emplace(parent->m_transactions[i], i);
		}

		// Reserve 1 additional byte per transaction to be ready for the worst case (all transactions are different in the parent block)
		data->compact_blob.reserve(data->pruned_blob.capacity() + (N - 1));

		// Copy pruned_blob without the transaction list
		data->compact_blob.assign(data->pruned_blob.begin(), data->pruned_blob.end() - (N - 1) * HASH_SIZE);

		// Process transaction hashes one by one
		size_t num_found = 0;
		for (size_t i = 1; i < N; ++i) {
			const hash& tx = block.m_transactions[i];
			auto it = parent_transactions.find(tx);
			if (it != parent_transactions.end()) {
				writeVarint(it->second, data->compact_blob);
				++num_found;
			}
			else {
				data->compact_blob.push_back(0);
				data->compact_blob.insert(data->compact_blob.end(), tx.h, tx.h + HASH_SIZE);
			}
		}
		LOGINFO(6, "compact blob: " << num_found << '/' << (N - 1) << " transactions were found in the parent block");

		data->compact_blob.insert(data->compact_blob.end(), sidechain_data.begin(), sidechain_data.end());
	}

	data->pruned_blob.insert(data->pruned_blob.end(), sidechain_data.begin(), sidechain_data.end());

	data->ancestor_hashes.reserve(block.m_uncles.size() + 1);
	data->ancestor_hashes = block.m_uncles;
	data->ancestor_hashes.push_back(block.m_parent);

	LOGINFO(5, "Broadcasting block " << block.m_sidechainId << " (height " << block.m_sidechainHeight << "): " << data->compact_blob.size() << '/' << data->pruned_blob.size() << '/' << data->blob.size() << " bytes (compact/pruned/full)");

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
	check_event_loop_thread(__func__);

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

	for (P2PClient* client = static_cast<P2PClient*>(m_connectedClientsList->m_next); client != m_connectedClientsList; client = static_cast<P2PClient*>(client->m_next)) {
		if (!client->is_good()) {
			continue;
		}

		for (Broadcast* data : broadcast_queue) {
			const bool result = send(client, [client, data](void* buf, size_t buf_size) -> size_t
			{
				uint8_t* p0 = reinterpret_cast<uint8_t*>(buf);
				uint8_t* p = p0;

				bool send_pruned = true;
				bool send_compact = (client->m_protocolVersion >= PROTOCOL_VERSION_1_1) && !data->compact_blob.empty() && (data->compact_blob.size() < data->pruned_blob.size());

				const hash* a = client->m_broadcastedHashes;
				const hash* b = client->m_broadcastedHashes + array_size(&P2PClient::m_broadcastedHashes);

				for (const hash& id : data->ancestor_hashes) {
					if (std::find(a, b, id) == b) {
						send_pruned = false;
						send_compact = false;
						break;
					}
				}

				if (send_pruned) {
					LOGINFO(6, "sending BLOCK_BROADCAST (" << (send_compact ? "compact" : "pruned") << ") to " << log::Gray() << static_cast<char*>(client->m_addrString));
					const std::vector<uint8_t>& blob = send_compact ? data->compact_blob : data->pruned_blob;

					const uint32_t len = static_cast<uint32_t>(blob.size());
					if (buf_size < SEND_BUF_MIN_SIZE + 1 + sizeof(uint32_t) + len) {
						return 0;
					}

					*(p++) = static_cast<uint8_t>(send_compact ? MessageId::BLOCK_BROADCAST_COMPACT : MessageId::BLOCK_BROADCAST);

					memcpy(p, &len, sizeof(uint32_t));
					p += sizeof(uint32_t);

					if (len) {
						memcpy(p, blob.data(), len);
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
			if (!result) {
				LOGWARN(5, "failed to broadcast to " << static_cast<char*>(client->m_addrString) << ", disconnecting");
				client->close();
				break;
			}
		}
	}

	for (const Broadcast* data : broadcast_queue) {
		const double t = static_cast<double>(microseconds_since_epoch() - data->received_timestamp) * 1e-3;
		LOGINFO(5, "Block " << data->id << " took " << t << " ms to process and relay to other peers");
		delete data;
	}
}

uint64_t P2PServer::get_random64()
{
	check_event_loop_thread(__func__);
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

void P2PServer::show_peers_async()
{
	if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(&m_showPeersAsync))) {
		uv_async_send(&m_showPeersAsync);
	}
}

void P2PServer::show_peers() const
{
	check_event_loop_thread(__func__);

	const uint64_t cur_time = seconds_since_epoch();
	size_t n = 0;

	for (P2PClient* client = static_cast<P2PClient*>(m_connectedClientsList->m_next); client != m_connectedClientsList; client = static_cast<P2PClient*>(client->m_next)) {
		if (client->m_listenPort >= 0) {
			char buf[32] = {};
			log::Stream s(buf);
			if (client->m_SoftwareVersion) {
				s << client->software_name() << " v" << (client->m_SoftwareVersion >> 16) << '.' << (client->m_SoftwareVersion & 0xFFFF);
			}
			LOGINFO(0, (client->m_isIncoming ? "I\t" : "O\t")
				<< log::pad_right(log::Duration(cur_time - client->m_connectedTime), 16) << '\t'
				<< log::pad_right(client->m_pingTime, 4) << " ms\t\t"
				<< log::pad_right(static_cast<const char*>(buf), 20) << '\t'
				<< log::pad_right(client->m_broadcastMaxHeight, 10) << '\t'
				<< static_cast<char*>(client->m_addrString));
			++n;
		}
	}

	LOGINFO(0, "Total: " << n << " peers");
}

int P2PServer::external_listen_port() const
{
	const Params& params = m_pool->params();
	return params.m_p2pExternalPort ? params.m_p2pExternalPort : m_listenPort;
}

int P2PServer::deserialize_block(const uint8_t* buf, uint32_t size, bool compact, uint64_t received_timestamp)
{
	int result;

	if ((m_blockDeserializeBuf.size() == size) && (memcmp(m_blockDeserializeBuf.data(), buf, size) == 0)) {
		m_block->reset_offchain_data();
		result = m_blockDeserializeResult;
	}
	else {
		result = m_block->deserialize(buf, size, m_pool->side_chain(), &m_loop, compact);
		m_blockDeserializeBuf.assign(buf, buf + size);
		m_blockDeserializeResult = result;
		m_lookForMissingBlocks = true;
	}

	m_block->m_receivedTimestamp = received_timestamp;
	return result;
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
	check_block_template();
	api_update_local_stats();
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
			BACKGROUND_JOB_START(P2PServer::flush_cache);
			reinterpret_cast<Work*>(req->data)->cache->flush();
		},
		[](uv_work_t* req, int)
		{
			delete reinterpret_cast<Work*>(req->data);
			BACKGROUND_JOB_STOP(P2PServer::flush_cache);
		});

	if (err) {
		LOGERR(1, "flush_cache: uv_queue_work failed, error " << uv_err_name(err));
		delete work;
	}
}

void P2PServer::download_missing_blocks()
{
	check_event_loop_thread(__func__);

	if (!m_lookForMissingBlocks) {
		return;
	}

	std::vector<hash> missing_blocks;
	m_pool->side_chain().get_missing_blocks(missing_blocks);

	if (missing_blocks.empty()) {
		m_lookForMissingBlocks = false;
		m_missingBlockRequests.clear();
		return;
	}

	if (m_numConnections == 0) {
		return;
	}

	std::vector<P2PClient*> clients;
	clients.reserve(m_numConnections);

	for (P2PClient* client = static_cast<P2PClient*>(m_connectedClientsList->m_next); client != m_connectedClientsList; client = static_cast<P2PClient*>(client->m_next)) {
		if (client->is_good()) {
			clients.emplace_back(client);
		}
	}

	if (clients.empty()) {
		return;
	}

	ReadLock lock2(m_cachedBlocksLock);

	// Try to download each block from a random client
	for (const hash& id : missing_blocks) {
		P2PClient* client = clients[get_random64() % clients.size()];

		const uint64_t truncated_block_id = *reinterpret_cast<const uint64_t*>(id.h);
		if (!m_missingBlockRequests.insert({ client->m_peerId, truncated_block_id }).second) {
			// We already asked this peer about this block
			// Don't try to ask another peer, leave it for another timer tick
			continue;
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
			[&id, client](void* buf, size_t buf_size) -> size_t
			{
				LOGINFO(5, "sending BLOCK_REQUEST for id = " << id << " to " << static_cast<char*>(client->m_addrString));

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
			client->m_blockPendingRequests.push_back(id);
		}
	}
}

void P2PServer::check_zmq()
{
	if ((m_timerCounter % 30) != 3) {
		return;
	}

	if (!m_pool->zmq_running()) {
		LOGERR(1, "ZMQ is not running, restarting it");
		m_pool->restart_zmq();
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

void P2PServer::check_block_template()
{
	if (!m_pool->side_chain().precalcFinished()) {
		return;
	}

	// Force update block template every 20 seconds after the initial sync is done
	if (seconds_since_epoch() >= m_pool->block_template().last_updated() + 20) {
		LOGINFO(4, "block template is 20 seconds old, updating it");
		m_pool->update_block_template_async();
	}
}

P2PServer::P2PClient::P2PClient()
	: m_peerId(0)
	, m_connectedTime(0)
	, m_broadcastMaxHeight(0)
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
	, m_protocolVersion(PROTOCOL_VERSION_1_0)
	, m_SoftwareVersion(0)
	, m_SoftwareID(0)
	, m_pingTime(-1)
	, m_lastAlive(0)
	, m_lastBroadcastTimestamp(0)
	, m_lastBlockrequestTimestamp(0)
	, m_broadcastedHashes{}
{
}

void P2PServer::on_shutdown()
{
	uv_timer_stop(&m_timer);
	uv_close(reinterpret_cast<uv_handle_t*>(&m_timer), nullptr);
	uv_close(reinterpret_cast<uv_handle_t*>(&m_broadcastAsync), nullptr);
	uv_close(reinterpret_cast<uv_handle_t*>(&m_connectToPeersAsync), nullptr);
	uv_close(reinterpret_cast<uv_handle_t*>(&m_showPeersAsync), nullptr);
}

void P2PServer::api_update_local_stats()
{
	if (!m_pool->api() || !m_pool->params().m_localStats || ((m_timerCounter % 30) != 5)) {
		return;
	}

	m_pool->api()->set(p2pool_api::Category::LOCAL, "p2p",
		[this](log::Stream& s)
		{
			const uint64_t cur_time = seconds_since_epoch();

			s << "{\"connections\":" << m_numConnections.load()
				<< ",\"incoming_connections\":" << m_numIncomingConnections.load()
				<< ",\"peer_list_size\":" << m_peerList.size()
				<< ",\"peers\":[";

			bool first = true;

			for (P2PClient* client = static_cast<P2PClient*>(m_connectedClientsList->m_next); client != m_connectedClientsList; client = static_cast<P2PClient*>(client->m_next)) {
				if (client->m_listenPort >= 0) {
					char buf[32] = {};
					log::Stream s1(buf);
					if (client->m_SoftwareVersion) {
						s1 << client->software_name() << " v" << (client->m_SoftwareVersion >> 16) << '.' << (client->m_SoftwareVersion & 0xFFFF);
					}

					if (!first) {
						s << ',';
					}

					s << '"'
						<< (client->m_isIncoming ? "I," : "O,")
						<< (cur_time - client->m_connectedTime) << ','
						<< client->m_pingTime << ','
						<< static_cast<const char*>(buf) << ','
						<< client->m_broadcastMaxHeight << ','
						<< static_cast<char*>(client->m_addrString)
						<< '"';
					first = false;
				}
			}

			s << "],\"uptime\":" << cur_time - m_pool->start_time() << '}';
		});
}

P2PServer::P2PClient::~P2PClient()
{
}

void P2PServer::P2PClient::reset()
{
	P2PServer* server = static_cast<P2PServer*>(m_owner);

	if (server && (server->m_fastestPeer == this)) {
		server->m_fastestPeer = nullptr;
	}

	Client::reset();

	m_peerId = 0;
	m_connectedTime = 0;
	m_broadcastMaxHeight = 0;
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
	m_protocolVersion = PROTOCOL_VERSION_1_0;
	m_SoftwareVersion = 0;
	m_SoftwareID = 0;
	m_pingTime = -1;
	m_blockPendingRequests.clear();
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

	// Don't allow multiple connections to/from the same IP (except localhost)
	if (!m_addr.is_localhost()) {
		for (P2PClient* client = static_cast<P2PClient*>(server->m_connectedClientsList->m_next); client != server->m_connectedClientsList; client = static_cast<P2PClient*>(client->m_next)) {
			if ((client != this) && (client->m_addr == m_addr)) {
				LOGINFO(5, "peer " << static_cast<char*>(m_addrString) << " is already connected as " << static_cast<char*>(client->m_addrString));
				return false;
			}
		}
	}

	const uint64_t cur_time = seconds_since_epoch();
	m_connectedTime = cur_time;
	m_lastAlive = cur_time;
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
				LOGWARN(4, "peer " << static_cast<char*>(m_addrString) << " sent an unexpected HANDSHAKE_CHALLENGE");
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
				LOGWARN(4, "peer " << static_cast<char*>(m_addrString) << " sent an unexpected HANDSHAKE_SOLUTION");
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
				LOGWARN(4, "peer " << static_cast<char*>(m_addrString) << " sent too many BLOCK_REQUEST messages at once");
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
			if (m_blockPendingRequests.empty()) {
				LOGWARN(4, "peer " << static_cast<char*>(m_addrString) << " sent an unexpected BLOCK_RESPONSE");
				ban(DEFAULT_BAN_TIME);
				server->remove_peer_from_list(this);
				return false;
			}

			LOGINFO(5, "peer " << log::Gray() << static_cast<char*>(m_addrString) << log::NoColor() << " sent BLOCK_RESPONSE");

			if (bytes_left >= 1 + sizeof(uint32_t)) {
				const uint32_t block_size = read_unaligned(reinterpret_cast<uint32_t*>(buf + 1));
				if (bytes_left >= 1 + sizeof(uint32_t) + block_size) {
					bytes_read = 1 + sizeof(uint32_t) + block_size;

					const hash expected_id = m_blockPendingRequests.front();
					m_blockPendingRequests.pop_front();

					if (!on_block_response(buf + 1 + sizeof(uint32_t), block_size, expected_id)) {
						ban(DEFAULT_BAN_TIME);
						server->remove_peer_from_list(this);
						return false;
					}
				}
			}
			break;

		case MessageId::BLOCK_BROADCAST:
		case MessageId::BLOCK_BROADCAST_COMPACT:
			{
				const bool compact = (id == MessageId::BLOCK_BROADCAST_COMPACT);
				LOGINFO(6, "peer " << log::Gray() << static_cast<char*>(m_addrString) << log::NoColor() << " sent " << (compact ? "BLOCK_BROADCAST_COMPACT" : "BLOCK_BROADCAST"));

				if (bytes_left >= 1 + sizeof(uint32_t)) {
					const uint32_t block_size = read_unaligned(reinterpret_cast<uint32_t*>(buf + 1));
					if (bytes_left >= 1 + sizeof(uint32_t) + block_size) {
						bytes_read = 1 + sizeof(uint32_t) + block_size;
						if (!on_block_broadcast(buf + 1 + sizeof(uint32_t), block_size, compact)) {
							ban(DEFAULT_BAN_TIME);
							server->remove_peer_from_list(this);
							return false;
						}
					}
				}
			}
			break;

		case MessageId::PEER_LIST_REQUEST:
			LOGINFO(6, "peer " << log::Gray() << static_cast<char*>(m_addrString) << log::NoColor() << " sent PEER_LIST_REQUEST");

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
				LOGWARN(4, "peer " << static_cast<char*>(m_addrString) << " sent an unexpected PEER_LIST_RESPONSE");
				ban(DEFAULT_BAN_TIME);
				server->remove_peer_from_list(this);
				return false;
			}

			LOGINFO(6, "peer " << log::Gray() << static_cast<char*>(m_addrString) << log::NoColor() << " sent PEER_LIST_RESPONSE");

			if (bytes_left >= 2) {
				const uint32_t num_peers = buf[1];
				if (num_peers > PEER_LIST_RESPONSE_MAX_PEERS) {
					LOGWARN(5, "peer " << static_cast<char*>(m_addrString) << " sent too long peer list (" << num_peers << ')');
					ban(DEFAULT_BAN_TIME);
					server->remove_peer_from_list(this);
					return false;
				}

				if (bytes_left >= 2u + num_peers * 19u) {
					bytes_read = 2u + num_peers * 19u;

					using namespace std::chrono;
					m_pingTime = std::max<int64_t>(duration_cast<milliseconds>(high_resolution_clock::now() - m_lastPeerListRequestTime).count(), 0);

					--m_peerListPendingRequests;
					on_peer_list_response(buf + 1);
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
	P2PServer* server = static_cast<P2PServer*>(m_owner);

	if (server && (server->m_fastestPeer == this)) {
		server->m_fastestPeer = nullptr;
	}

	m_pingTime = -1;

	if (!m_handshakeComplete) {
		LOGWARN(5, "peer " << static_cast<char*>(m_addrString) << " disconnected before finishing handshake");

		ban(DEFAULT_BAN_TIME);
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
			LOGINFO(5, "sending HANDSHAKE_CHALLENGE to " << static_cast<char*>(m_addrString));

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
		bool is_incoming;

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
	work->is_incoming = m_isIncoming;

	memcpy(work->challenge, challenge, CHALLENGE_SIZE);
	work->salt = server->get_random64();

	const int err = uv_queue_work(&server->m_loop, &work->req,
		[](uv_work_t* req)
		{
			BACKGROUND_JOB_START(P2PServer::send_handshake_solution);

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

				if (work->is_incoming) {
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
					BACKGROUND_JOB_STOP(P2PServer::send_handshake_solution);
				});

			// We might've been disconnected while working on the challenge, do nothing in this case
			if (work->client->m_resetCounter.load() != work->reset_counter) {
				return;
			}

			const bool result = work->server->send(work->client,
				[work](void* buf, size_t buf_size) -> size_t
				{
					LOGINFO(5, "sending HANDSHAKE_SOLUTION to " << static_cast<char*>(work->client->m_addrString));

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
	check_event_loop_thread(__func__);

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

	for (const P2PClient* client = static_cast<P2PClient*>(server->m_connectedClientsList->m_next); client != server->m_connectedClientsList; client = static_cast<P2PClient*>(client->m_next)) {
		if ((client != this) && (client->m_peerId == peer_id)) {
			LOGWARN(5, "tried to connect to the same peer twice: current connection " << static_cast<const char*>(client->m_addrString) << ", new connection " << static_cast<const char*>(m_addrString));
			close();
			return true;
		}
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
				LOGINFO(5, "sending LISTEN_PORT and BLOCK_REQUEST for the chain tip to " << static_cast<char*>(m_addrString));

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
	LOGINFO(5, "sending LISTEN_PORT to " << static_cast<char*>(m_addrString));
	*(p++) = static_cast<uint8_t>(MessageId::LISTEN_PORT);

	const int32_t port = m_owner->external_listen_port();
	memcpy(p, &port, sizeof(port));
	p += sizeof(port);

	LOGINFO(5, "sending BLOCK_REQUEST for the chain tip to " << static_cast<char*>(m_addrString));
	*(p++) = static_cast<uint8_t>(MessageId::BLOCK_REQUEST);

	hash empty;
	memcpy(p, empty.h, HASH_SIZE);
	p += HASH_SIZE;

	m_blockPendingRequests.push_back(empty);
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
		[this, &blob](void* buf, size_t buf_size) -> size_t
		{
			LOGINFO(5, "sending BLOCK_RESPONSE to " << static_cast<char*>(m_addrString));

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

bool P2PServer::P2PClient::on_block_response(const uint8_t* buf, uint32_t size, const hash& expected_id)
{
	if (!size) {
		LOGINFO(5, "peer " << log::Gray() << static_cast<char*>(m_addrString) << log::NoColor() << " sent an empty block response");
		return true;
	}

	const uint64_t received_timestamp = microseconds_since_epoch();

	P2PServer* server = static_cast<P2PServer*>(m_owner);

	MutexLock lock(server->m_blockLock);

	const int result = server->deserialize_block(buf, size, false, received_timestamp);
	if (result != 0) {
		LOGWARN(3, "peer " << static_cast<char*>(m_addrString) << " sent an invalid block, error " << result);
		return false;
	}

	const PoolBlock* block = server->get_block();

	// Chain tip request
	if (expected_id.empty()) {
		const uint64_t peer_height = block->m_txinGenHeight;
		const uint64_t our_height = server->m_pool->miner_data().height;

		if (peer_height + 2 < our_height) {
			LOGWARN(4, "peer " << static_cast<char*>(m_addrString) << " is mining on top of a stale block (mainchain height " << peer_height << ", expected >= " << our_height << ')');
			return false;
		}

		const uint64_t cur_time = seconds_since_epoch();
		if (cur_time >= m_nextOutgoingPeerListRequest) {
			server->send_peer_list_request(this, cur_time);
		}
	}
	else if (block->m_sidechainId != expected_id) {
		LOGWARN(3, "peer " << static_cast<char*>(m_addrString) << " sent a wrong block: expected " << expected_id << ", got " << block->m_sidechainId);
		return false;
	}

	const SideChain& side_chain = server->m_pool->side_chain();
	const uint64_t max_time_delta = side_chain.precalcFinished() ? (side_chain.block_time() * side_chain.chain_window_size() * 4) : 0;

	return handle_incoming_block_async(block, max_time_delta);
}

bool P2PServer::P2PClient::on_block_broadcast(const uint8_t* buf, uint32_t size, bool compact)
{
	if (!size) {
		LOGWARN(3, "peer " << static_cast<char*>(m_addrString) << " broadcasted an empty block");
		return false;
	}

	const uint64_t received_timestamp = microseconds_since_epoch();

	P2PServer* server = static_cast<P2PServer*>(m_owner);

	MutexLock lock(server->m_blockLock);

	const int result = server->deserialize_block(buf, size, compact, received_timestamp);
	if (result != 0) {
		LOGWARN(3, "peer " << static_cast<char*>(m_addrString) << " sent an invalid block, error " << result);
		return false;
	}

	const PoolBlock* block = server->get_block();

	m_broadcastMaxHeight = std::max(m_broadcastMaxHeight, block->m_sidechainHeight);
	m_broadcastedHashes[m_broadcastedHashesIndex.fetch_add(1) % array_size(&P2PClient::m_broadcastedHashes)] = block->m_sidechainId;

	MinerData miner_data = server->m_pool->miner_data();

	if (block->m_prevId != miner_data.prev_id) {
		// This peer is mining on top of a different Monero block, investigate it
		const uint64_t peer_height = block->m_txinGenHeight;
		const uint64_t our_height = miner_data.height;

		if (peer_height < our_height) {
			if (our_height - peer_height < 5) {
				using namespace std::chrono;
				const int64_t elapsed_ms = duration_cast<milliseconds>(high_resolution_clock::now() - miner_data.time_received).count();
				if ((our_height - peer_height > 1) || (elapsed_ms > 10000)) {
					LOGWARN(5, "peer " << static_cast<char*>(m_addrString) << " broadcasted a stale block (" << elapsed_ms << " ms late, mainchain height " << peer_height << ", expected >= " << our_height << "), ignoring it");
					return true;
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

	block->m_wantBroadcast = true;

	m_lastBroadcastTimestamp = seconds_since_epoch();

	return handle_incoming_block_async(block, 1800);
}

bool P2PServer::P2PClient::on_peer_list_request(const uint8_t*)
{
	check_event_loop_thread(__func__);

	P2PServer* server = static_cast<P2PServer*>(m_owner);
	const uint64_t cur_time = seconds_since_epoch();
	const bool first = (m_prevIncomingPeerListRequest == 0);

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

	// Send every 4th peer on average, selected at random
	const uint32_t peers_to_send_target = std::min<uint32_t>(PEER_LIST_RESPONSE_MAX_PEERS, std::max<uint32_t>(1, server->m_numConnections / 4));
	uint32_t n = 0;

	for (P2PClient* client = static_cast<P2PClient*>(server->m_connectedClientsList->m_next); client != server->m_connectedClientsList; client = static_cast<P2PClient*>(client->m_next)) {
		if (!client->is_good() || (client->m_addr == m_addr)) {
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

	// Protocol version message:
	// - IPv4 address = 255.255.255.255
	// - port = 65535
	// - first 12 bytes of the 16-byte raw IP address are ignored by older clients if it's IPv4
	// - use first 8 bytes of the 16-byte raw IP address to send supported protocol version and p2pool version
	if (first) {
		LOGINFO(5, "sending protocol version " << (SUPPORTED_PROTOCOL_VERSION >> 16) << '.' << (SUPPORTED_PROTOCOL_VERSION & 0xFFFF)
			<< ", P2Pool version " << P2POOL_VERSION_MAJOR << '.' << P2POOL_VERSION_MINOR
			<< " to peer " << log::Gray() << static_cast<char*>(m_addrString));

		peers[0] = {};
		*reinterpret_cast<uint32_t*>(peers[0].m_addr.data) = SUPPORTED_PROTOCOL_VERSION;
		*reinterpret_cast<uint32_t*>(peers[0].m_addr.data + 4) = (P2POOL_VERSION_MAJOR << 16) | P2POOL_VERSION_MINOR;
		*reinterpret_cast<uint32_t*>(peers[0].m_addr.data + 12) = 0xFFFFFFFFU;
		peers[0].m_port = 0xFFFF;

		if (num_selected_peers == 0) {
			num_selected_peers = 1;
		}
	}

	return server->send(this,
		[this, &peers, num_selected_peers](void* buf, size_t buf_size) -> size_t
		{
			LOGINFO(6, "sending PEER_LIST_RESPONSE to " << static_cast<char*>(m_addrString));

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

void P2PServer::P2PClient::on_peer_list_response(const uint8_t* buf)
{
	P2PServer* server = static_cast<P2PServer*>(m_owner);
	const uint64_t cur_time = seconds_since_epoch();

	MutexLock lock(server->m_peerListLock);

	const uint32_t num_peers = *(buf++);
	for (uint32_t i = 0; i < num_peers; ++i) {
		bool is_v6 = *(buf++) != 0;

		raw_ip ip;
		memcpy(ip.data, buf, sizeof(ip.data));
		buf += sizeof(ip.data);

		int port = 0;
		memcpy(&port, buf, 2);
		buf += 2;

		// Treat IPv4-mapped addresses as regular IPv4 addresses
		if (is_v6 && ip.is_ipv4_prefix()) {
			is_v6 = false;
		}

		if (!is_v6) {
			const uint32_t b = ip.data[12];
			if ((b == 0) || (b >= 224)) {
				// Ignore 0.0.0.0/8 (special-purpose range for "this network") and 224.0.0.0/3 (IP multicast and reserved ranges)

				// Check for protocol version message
				if ((*reinterpret_cast<uint32_t*>(ip.data + 12) == 0xFFFFFFFFU) && (port == 0xFFFF)) {
					m_protocolVersion = *reinterpret_cast<uint32_t*>(ip.data);
					m_SoftwareVersion = *reinterpret_cast<uint32_t*>(ip.data + 4);
					m_SoftwareID = *reinterpret_cast<uint32_t*>(ip.data + 8);
					LOGINFO(5, "peer " << log::Gray() << static_cast<char*>(m_addrString) << log::NoColor()
						<< " supports protocol version " << (m_protocolVersion >> 16) << '.' << (m_protocolVersion & 0xFFFF)
						<< ", runs " << software_name() << " v" << (m_SoftwareVersion >> 16) << '.' << (m_SoftwareVersion & 0xFFFF)
					);
				}
				continue;
			}

			// Fill in default bytes for IPv4 addresses
			memset(ip.data, 0, 10);
			ip.data[10] = 0xFF;
			ip.data[11] = 0xFF;
		}

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
}

bool P2PServer::P2PClient::handle_incoming_block_async(const PoolBlock* block, uint64_t max_time_delta)
{
	P2PServer* server = static_cast<P2PServer*>(m_owner);
	SideChain& side_chain = server->m_pool->side_chain();

	// Limit system clock difference between connected peers
	// Check only new blocks (not added to side_chain yet)
	if (max_time_delta && !side_chain.find_block(block->m_sidechainId)) {
		static hash prev_checked_blocks[2];
		const bool is_new = (block->m_sidechainId != prev_checked_blocks[0]) && (block->m_sidechainId != prev_checked_blocks[1]);
		if (is_new) {
			prev_checked_blocks[1] = prev_checked_blocks[0];
			prev_checked_blocks[0] = block->m_sidechainId;
		}

		const uint64_t t = time(nullptr);
		const uint32_t failed = ((block->m_timestamp + max_time_delta < t) || (block->m_timestamp > t + max_time_delta)) ? 1 : 0;

		static uint32_t failed_history = 0;
		if (is_new) {
			failed_history = (failed_history << 1) | failed;
		}

		if (failed) {
			if (is_new) {
				int64_t dt = static_cast<int64_t>(block->m_timestamp - t);
				char sign = '+';
				if (dt < 0) {
					sign = '-';
					dt = -dt;
				}
				LOGWARN(4, "peer " << static_cast<char*>(m_addrString)
					<< " sent a block " << block->m_sidechainId << " (mined by " << block->m_minerWallet << ") with an invalid timestamp " << block->m_timestamp
					<< " (" << sign << dt << " seconds)");

				uint32_t failed_checks = 0;

				for (uint32_t k = 1; k != 0; k <<= 1) {
					if (failed_history & k) {
						++failed_checks;
					}
				}

				if (failed_checks > 16) {
					LOGWARN(1, "Your system clock might be invalid: " << failed_checks << " of 32 last blocks were rejected due to high timestamp diff");
				}
			}
			return true;
		}
	}

	if (side_chain.block_seen(*block)) {
		LOGINFO(6, "block " << block->m_sidechainId << " (nonce " << block->m_nonce << ", extra_nonce " << block->m_extraNonce << ") was received before, skipping it");
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
			BACKGROUND_JOB_START(P2PServer::handle_incoming_block_async);
			Work* work = reinterpret_cast<Work*>(req->data);
			work->client->handle_incoming_block(work->server->m_pool, work->block, work->client_reset_counter, work->client_ip, work->missing_blocks);
		},
		[](uv_work_t* req, int /*status*/)
		{
			Work* work = reinterpret_cast<Work*>(req->data);
			work->client->post_handle_incoming_block(work->client_reset_counter, work->missing_blocks);
			delete work;
			BACKGROUND_JOB_STOP(P2PServer::handle_incoming_block_async);
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

	// If the initial sync is not finished yet, try to ask the fastest peer too
	P2PClient* c = server->m_fastestPeer;
	if (c && (c != this) && !server->m_pool->side_chain().precalcFinished()) {
		LOGINFO(5, "peer " << static_cast<char*>(c->m_addrString) << " is faster, sending BLOCK_REQUEST to it too");
		c->post_handle_incoming_block(c->m_resetCounter.load(), missing_blocks);
	}

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

		const bool result = server->send(this,
			[this, &id](void* buf, size_t buf_size) -> size_t
			{
				LOGINFO(5, "sending BLOCK_REQUEST for id = " << id << " to " << static_cast<char*>(m_addrString));

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

		m_blockPendingRequests.push_back(id);
	}
}

const char* P2PServer::P2PClient::software_name() const
{
	switch (m_SoftwareID) {
	case 0:
		return "P2Pool";
	case 0x624F6F47UL:
		return "GoObserver";
	default:
		return "Unknown";
	}
}

} // namespace p2pool
