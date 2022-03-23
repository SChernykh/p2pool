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

#pragma once

#include "tcp_server.h"

namespace p2pool {

class p2pool;
struct PoolBlock;
class BlockCache;

static constexpr size_t P2P_BUF_SIZE = 128 * 1024;
static constexpr size_t PEER_LIST_RESPONSE_MAX_PEERS = 16;
static constexpr int DEFAULT_P2P_PORT = 37889;
static constexpr int DEFAULT_P2P_PORT_MINI = 37888;

class P2PServer : public TCPServer<P2P_BUF_SIZE, P2P_BUF_SIZE>
{
public:
	enum class MessageId {
		HANDSHAKE_CHALLENGE = 0,
		HANDSHAKE_SOLUTION = 1,
		LISTEN_PORT = 2,
		BLOCK_REQUEST = 3,
		BLOCK_RESPONSE = 4,
		BLOCK_BROADCAST = 5,
		PEER_LIST_REQUEST = 6,
		PEER_LIST_RESPONSE = 7,
	};

	explicit P2PServer(p2pool *pool);
	~P2PServer();

	void add_cached_block(const PoolBlock& block);
	void clear_cached_blocks();
	void store_in_cache(const PoolBlock& block);

	void connect_to_peers(const std::string& peer_list);
	void on_connect_failed(bool is_v6, const raw_ip& ip, int port) override;

	struct P2PClient : public Client
	{
		P2PClient();
		~P2PClient();

		static Client* allocate() { return new P2PClient(); }

		void reset() override;
		bool on_connect() override;
		bool on_read(char* data, uint32_t size) override;
		void on_read_failed(int err) override;
		void on_disconnected() override;

		// Both peers send handshake challenge immediately after a connection is established
		// Both peers must have the same consensus ID for handshake to succeed
		// Consensus ID is never sent over the network
		// 
		// Handshake sequence:
		// 
		// - Both peers send 8-byte random challenges (and 8 bytes of peer ID) to each other
		// - Each peer receives 8-byte challenge, chooses 8-byte random SALT and calculates H = KECCAK(CHALLENGE|CONSENSUS_ID|SALT)
		// - Both peers send their H and SALT, calculate H of the other peer and check if it matches with what other peer calculated
		// - Peer that initiated the connection must also provide enough PoW in H (difficulty = 10000, 5-10 ms on modern CPU)
		// - If H doesn't match or doesn't have enough PoW, connection is closed immediately
		enum {
			CHALLENGE_SIZE = 8,
			CHALLENGE_DIFFICULTY = 10000,
		};

		bool send_handshake_challenge();
		void send_handshake_solution(const uint8_t (&challenge)[CHALLENGE_SIZE]);
		bool check_handshake_solution(const hash& solution, const uint8_t (&solution_salt)[CHALLENGE_SIZE]);

		bool on_handshake_challenge(const uint8_t* buf);
		bool on_handshake_solution(const uint8_t* buf);
		void on_after_handshake(uint8_t* &p);
		bool on_listen_port(const uint8_t* buf);
		bool on_block_request(const uint8_t* buf);
		bool on_block_response(const uint8_t* buf, uint32_t size);
		bool on_block_broadcast(const uint8_t* buf, uint32_t size);
		bool on_peer_list_request(const uint8_t* buf);
		bool on_peer_list_response(const uint8_t* buf) const;

		bool handle_incoming_block_async(PoolBlock* block);
		void handle_incoming_block(p2pool* pool, PoolBlock& block, const uint32_t reset_counter, const raw_ip& addr, std::vector<hash>& missing_blocks);
		void post_handle_incoming_block(const uint32_t reset_counter, std::vector<hash>& missing_blocks);

		uint64_t m_peerId;
		MessageId m_expectedMessage;
		uint64_t m_handshakeChallenge;
		bool m_handshakeSolutionSent;
		bool m_handshakeComplete;
		bool m_handshakeInvalid;
		int m_listenPort;

		uint32_t m_fastPeerListRequestCount;
		uint64_t m_prevIncomingPeerListRequest;
		uint64_t m_nextOutgoingPeerListRequest;
		std::chrono::high_resolution_clock::time_point m_lastPeerListRequestTime;
		int m_peerListPendingRequests;
		int64_t m_pingTime;

		int m_blockPendingRequests;

		uint64_t m_lastAlive;
		uint64_t m_lastBroadcastTimestamp;
		uint64_t m_lastBlockrequestTimestamp;

		hash m_broadcastedHashes[8];
		std::atomic<uint32_t> m_broadcastedHashesIndex{ 0 };
	};

	void broadcast(const PoolBlock& block);
	uint64_t get_random64();
	uint64_t get_peerId() const { return m_peerId; }

	void print_status() override;
	void show_peers();
	size_t peer_list_size() const { return m_peerList.size(); }

	uint32_t max_outgoing_peers() const { return m_maxOutgoingPeers; }
	uint32_t max_incoming_peers() const { return m_maxIncomingPeers; }

	void set_max_outgoing_peers(uint32_t n) { m_maxOutgoingPeers = std::min(std::max(n, 10U), 1000U); }
	void set_max_incoming_peers(uint32_t n) { m_maxIncomingPeers = std::min(std::max(n, 10U), 1000U); }

private:
	p2pool* m_pool;
	BlockCache* m_cache;
	bool m_cacheLoaded;
	std::string m_initialPeerList;
	uint32_t m_maxOutgoingPeers;
	uint32_t m_maxIncomingPeers;

	uv_rwlock_t m_cachedBlocksLock;
	unordered_map<hash, PoolBlock*> m_cachedBlocks;

private:
	static void on_timer(uv_timer_t* timer) { reinterpret_cast<P2PServer*>(timer->data)->on_timer(); }
	void on_timer();

	void flush_cache();
	void download_missing_blocks();
	void check_zmq();
	void update_peer_connections();
	void update_peer_list();
	void save_peer_list_async();
	void save_peer_list();
	void load_peer_list();
	void load_monerod_peer_list();
	void update_peer_in_list(bool is_v6, const raw_ip& ip, int port);
	void remove_peer_from_list(P2PClient* client);
	void remove_peer_from_list(const raw_ip& ip);

	uv_mutex_t m_rngLock;
	std::mt19937_64 m_rng;

	uv_mutex_t m_blockLock;
	PoolBlock* m_block;

	uv_timer_t m_timer;
	uint64_t m_timerCounter;
	uint64_t m_timerInterval;

	uint64_t m_peerId;

	uv_mutex_t m_peerListLock;

	struct Peer
	{
		bool m_isV6;
		raw_ip m_addr;
		int m_port;
		uint32_t m_numFailedConnections;
		uint64_t m_lastSeen;
	};

	std::vector<Peer> m_peerList;
	std::vector<Peer> m_peerListMonero;
	uint64_t m_peerListLastSaved;

	struct Broadcast
	{
		std::vector<uint8_t> blob;
		std::vector<uint8_t> pruned_blob;
		std::vector<hash> ancestor_hashes;
	};

	uv_mutex_t m_broadcastLock;
	uv_async_t m_broadcastAsync;
	std::vector<Broadcast*> m_broadcastQueue;

	uv_mutex_t m_missingBlockRequestsLock;
	unordered_set<std::pair<uint64_t, uint64_t>> m_missingBlockRequests;

	static void on_broadcast(uv_async_t* handle) { reinterpret_cast<P2PServer*>(handle->data)->on_broadcast(); }
	void on_broadcast();
};

} // namespace p2pool
