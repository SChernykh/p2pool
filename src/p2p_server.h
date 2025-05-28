/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2024 SChernykh <https://github.com/SChernykh>
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
#include "pool_block.h"
#include <deque>

namespace p2pool {

class p2pool;
struct PoolBlock;
class BlockCache;

// Max block size plus BLOCK_RESPONSE header (5 bytes)
static constexpr uint64_t P2P_BUF_SIZE = MAX_BLOCK_SIZE + (1 + sizeof(uint32_t));
static_assert((P2P_BUF_SIZE & (P2P_BUF_SIZE - 1)) == 0, "P2P_BUF_SIZE is not a power of 2, fix MAX_BLOCK_SIZE");

static constexpr size_t PEER_LIST_RESPONSE_MAX_PEERS = 16;
static constexpr int DEFAULT_P2P_PORT = 37889;
static constexpr int DEFAULT_P2P_PORT_MINI = 37888;
static constexpr int DEFAULT_P2P_PORT_NANO = 37890;

static constexpr uint32_t PROTOCOL_VERSION_1_0 = 0x00010000UL;
static constexpr uint32_t PROTOCOL_VERSION_1_1 = 0x00010001UL;
static constexpr uint32_t PROTOCOL_VERSION_1_2 = 0x00010002UL;
static constexpr uint32_t PROTOCOL_VERSION_1_3 = 0x00010003UL;

static constexpr uint32_t SUPPORTED_PROTOCOL_VERSION = PROTOCOL_VERSION_1_3;

class P2PServer : public TCPServer
{
public:
	enum class MessageId {
		HANDSHAKE_CHALLENGE,
		HANDSHAKE_SOLUTION,
		LISTEN_PORT,
		BLOCK_REQUEST,
		BLOCK_RESPONSE,
		BLOCK_BROADCAST,
		PEER_LIST_REQUEST,
		PEER_LIST_RESPONSE,
		BLOCK_BROADCAST_COMPACT,
		BLOCK_NOTIFY,
		// Donation messages are signed by author's private keys to prevent their abuse/misuse.
		AUX_JOB_DONATION,
		LAST = AUX_JOB_DONATION,
	};

	explicit P2PServer(p2pool *pool);
	~P2PServer() override;

	void add_cached_block(const PoolBlock& block);
	void clear_cached_blocks();
	void store_in_cache(const PoolBlock& block);

	void connect_to_peers_async(const char* peer_list);
	void connect_to_peers(const std::string& peer_list);
	void on_connect_failed(bool is_v6, const raw_ip& ip, int port) override;

	struct P2PClient : public Client
	{
		P2PClient();
		~P2PClient() override;

		static Client* allocate() { return new P2PClient(); }
		virtual size_t size() const override { return sizeof(P2PClient); }

		void reset() override;
		[[nodiscard]] bool on_connect() override;
		[[nodiscard]] bool on_read(const char* data, uint32_t size) override;
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

		[[nodiscard]] bool send_handshake_challenge();
		void send_handshake_solution(const uint8_t (&challenge)[CHALLENGE_SIZE]);
		[[nodiscard]] bool check_handshake_solution(const hash& solution, const uint8_t (&solution_salt)[CHALLENGE_SIZE]) const;

		[[nodiscard]] bool on_handshake_challenge(const uint8_t* buf);
		[[nodiscard]] bool on_handshake_solution(const uint8_t* buf);
		void on_after_handshake(uint8_t* &p);
		[[nodiscard]] bool on_listen_port(const uint8_t* buf);
		[[nodiscard]] bool on_block_request(const uint8_t* buf);
		[[nodiscard]] bool on_block_response(const uint8_t* buf, uint32_t size, uint64_t expected_id);
		[[nodiscard]] bool on_block_broadcast(const uint8_t* buf, uint32_t size, bool compact);
		[[nodiscard]] bool on_peer_list_request(const uint8_t* buf);
		void on_peer_list_response(const uint8_t* buf);
		void on_block_notify(const uint8_t* buf);
		[[nodiscard]] bool on_aux_job_donation(const uint8_t* buf, uint32_t size);

		[[nodiscard]] bool handle_incoming_block_async(const PoolBlock* block, uint64_t max_time_delta = 0);
		static void handle_incoming_block(p2pool* pool, PoolBlock& block, std::vector<hash>& missing_blocks, bool& result);
		void post_handle_incoming_block(p2pool* pool, const PoolBlock& block, const uint32_t reset_counter, bool is_v6, const raw_ip& addr, std::vector<hash>& missing_blocks, const bool result);

		[[nodiscard]] bool is_good() const { return m_handshakeComplete && !m_handshakeInvalid && (m_listenPort >= 0); }

		alignas(8) char m_p2pReadBuf[P2P_BUF_SIZE];

		uint64_t m_peerId;
		uint64_t m_connectedTime;
		uint64_t m_broadcastMaxHeight;

		MessageId m_expectedMessage;
		uint64_t m_handshakeChallenge;
		bool m_handshakeSolutionSent;
		bool m_handshakeComplete;
		bool m_handshakeInvalid;
		int m_listenPort;

		uint64_t m_prevPeersSent;
		uint64_t m_nextOutgoingPeerListRequest;
		std::chrono::high_resolution_clock::time_point m_lastPeerListRequestTime;
		int m_peerListPendingRequests;

		uint32_t m_protocolVersion;
		uint32_t m_SoftwareVersion;
		SoftwareID m_SoftwareID;

		int64_t m_pingTime;

		std::deque<uint64_t> m_blockPendingRequests;

		uint64_t m_lastAlive;
		uint64_t m_lastBroadcastTimestamp;
		uint64_t m_lastBlockrequestTimestamp;

		hash m_broadcastedHashes[8];
		uint32_t m_broadcastedHashesIndex;

		// log::Stream wrapper
		struct SoftwareDisplayName
		{
			FORCEINLINE SoftwareDisplayName(SoftwareID id, uint32_t version) : m_id(id), m_version(version) {}

			SoftwareID m_id;
			uint32_t m_version;
		};
	};

	void broadcast(const PoolBlock& block, const PoolBlock* parent);
	[[nodiscard]] uint64_t get_random64();
	[[nodiscard]] uint64_t get_peerId() const { return m_peerId; }

	void print_status() override;
	void show_peers_async();
	[[nodiscard]] size_t peer_list_size() const { MutexLock lock(m_peerListLock); return m_peerList.size(); }

	[[nodiscard]] int external_listen_port() const override;

	[[nodiscard]] uint32_t max_outgoing_peers() const { return m_maxOutgoingPeers; }
	[[nodiscard]] uint32_t max_incoming_peers() const { return m_maxIncomingPeers; }

	void set_max_outgoing_peers(uint32_t n) { m_maxOutgoingPeers = std::min(std::max(n, 10U), 450U); }
	void set_max_incoming_peers(uint32_t n) { m_maxIncomingPeers = std::min(std::max(n, 10U), 450U); }

	[[nodiscard]] int deserialize_block(const uint8_t* buf, uint32_t size, bool compact, uint64_t received_timestamp);
	[[nodiscard]] const PoolBlock* get_block() const { return m_block; }

	[[nodiscard]] const PoolBlock* find_block(const hash& id) const;

	void check_for_updates(bool forced = false) const;

	bool disconnected() const { return m_seenGoodPeers && (m_numConnections == 0); };

#ifdef WITH_MERGE_MINING_DONATION
	void broadcast_aux_job_donation_async(const uint8_t* data, uint32_t data_size, uint64_t timestamp);
#endif

	void broadcast_aux_job_donation(const uint8_t* data, uint32_t data_size, uint64_t timestamp, const P2PClient* source, bool duplicate_check_done);

private:
	[[nodiscard]] const char* get_log_category() const override;

	p2pool* m_pool;
	BlockCache* m_cache;
	bool m_cacheLoaded;
	std::string m_initialPeerList;
	uint32_t m_maxOutgoingPeers;
	uint32_t m_maxIncomingPeers;

	uv_rwlock_t m_cachedBlocksLock;
	unordered_map<hash, PoolBlock*>* m_cachedBlocks;

private:
	static void on_timer(uv_timer_t* timer) { reinterpret_cast<P2PServer*>(timer->data)->on_timer(); }
	void on_timer();

	void flush_cache();
	void download_missing_blocks();
	void check_host();
	void check_block_template();
	void update_peer_connections();
	void update_peer_list();
	void send_peer_list_request(P2PClient* client, uint64_t cur_time);
	void save_peer_list_async();
	void save_peer_list();
	void load_peer_list();
	void load_monerod_peer_list();
	void update_peer_in_list(bool is_v6, const raw_ip& ip, int port);
	void remove_peer_from_list(const P2PClient* client);
	void remove_peer_from_list(const raw_ip& ip);

	std::mt19937_64 m_rng;

	uv_mutex_t m_blockLock;
	PoolBlock* m_block;
	std::vector<uint8_t> m_blockDeserializeBuf;
	int m_blockDeserializeResult;

	uv_timer_t m_timer;
	uint64_t m_timerCounter;
	uint64_t m_timerInterval;

	uint64_t m_peerId;

	mutable uv_mutex_t m_peerListLock;

	struct Peer
	{
		void normalize();

		bool m_isV6;
		raw_ip m_addr;
		int m_port;
		uint32_t m_numFailedConnections;
		uint64_t m_lastSeen;
	};

	std::atomic<bool> m_seenGoodPeers;
	std::vector<Peer> m_peerList;
	std::vector<Peer> m_peerListMonero;
	std::atomic<uint64_t> m_peerListLastSaved;

	struct Broadcast
	{
		hash id;
		uint64_t received_timestamp;

		std::vector<uint8_t> blob;
		std::vector<uint8_t> pruned_blob;
		std::vector<uint8_t> compact_blob;
		std::vector<hash> ancestor_hashes;
	};

	uv_mutex_t m_broadcastLock;
	uv_async_t m_broadcastAsync;
	std::vector<Broadcast*> m_broadcastQueue;

	bool m_lookForMissingBlocks;
	unordered_set<std::pair<uint64_t, uint64_t>> m_missingBlockRequests;
	unordered_set<uint64_t> m_blockNotifyRequests;

	P2PClient* m_fastestPeer;
	std::atomic<bool> m_newP2PoolVersionDetected;

	static void on_broadcast(uv_async_t* handle) { reinterpret_cast<P2PServer*>(handle->data)->on_broadcast(); }
	void on_broadcast();

	uv_mutex_t m_connectToPeersLock;
	uv_async_t m_connectToPeersAsync;
	std::string m_connectToPeersData;

	static void on_connect_to_peers(uv_async_t* handle);

	uv_mutex_t m_showPeersLock;
	uv_async_t m_showPeersAsync;

	static void on_show_peers(uv_async_t* handle) { reinterpret_cast<P2PServer*>(handle->data)->show_peers(); }
	void show_peers() const;

	void on_shutdown() override;

	void api_update_local_stats();

	enum {
		AUX_JOB_TIMEOUT = 3600,
	};

	unordered_set<std::pair<uint64_t, uint64_t>> m_auxJobMessages;
	std::vector<uint8_t> m_auxJobLastMessage;
	uint64_t m_auxJobLastMessageTimestamp;

	void send_aux_job_donation(P2PServer::P2PClient* client, const uint8_t* data, uint32_t data_size);

	void clean_aux_job_messages();

#ifdef WITH_MERGE_MINING_DONATION
	struct AuxJobBroadcast
	{
		std::vector<uint8_t> job;
		uint64_t timestamp = 0;
	};

	uv_mutex_t m_AuxJobBroadcastLock;
	AuxJobBroadcast m_AuxJobBroadcast;

	uv_async_t m_AuxJobBroadcastAsync;

	static void on_aux_job_broadcast(uv_async_t* handle) { reinterpret_cast<P2PServer*>(handle->data)->broadcast_aux_job_donation_handler(); }
	void broadcast_aux_job_donation_handler();
#endif
};

} // namespace p2pool
