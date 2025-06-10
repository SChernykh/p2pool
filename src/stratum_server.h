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

namespace p2pool {

class p2pool;
class BlockTemplate;

static constexpr size_t STRATUM_BUF_SIZE = log::Stream::BUF_SIZE + 1;
static constexpr size_t STRATUM_CALLBACK_BUF_SIZE = 16384;
static constexpr int DEFAULT_STRATUM_PORT = 3333;

class StratumServer : public TCPServer
{
public:
	explicit StratumServer(p2pool *pool);
	~StratumServer() override;

	void on_block(const BlockTemplate& block);

	struct StratumClient : public Client
	{
		StratumClient();
		FORCEINLINE ~StratumClient() override {}

		static Client* allocate() { return new StratumClient(); }
		virtual size_t size() const override { return sizeof(StratumClient); }

		void reset() override;
		[[nodiscard]] bool on_connect() override;
		[[nodiscard]] bool on_read(const char* data, uint32_t size) override;

		[[nodiscard]] bool process_request(char* data, uint32_t size);
		template<typename T> [[nodiscard]] bool process_login(T& doc, uint32_t id);
		template<typename T> [[nodiscard]] bool process_submit(T& doc, uint32_t id);

		bool send_http_response(bool send_content);

		alignas(8) char m_rawReadBuf[STRATUM_BUF_SIZE];

		alignas(8) char m_stratumReadBuf[STRATUM_BUF_SIZE];
		uint32_t m_stratumReadBufBytes;

		uint32_t m_rpcId;
		uint32_t m_perConnectionJobId;
		uint64_t m_connectedTime;

		enum { 
			JOBS_SIZE = 4,
			AUTO_DIFF_SIZE = 64,
			CUSTOM_USER_SIZE = 32,
		};

		struct SavedJob {
			uint32_t job_id;
			uint32_t extra_nonce;
			uint32_t template_id;
			uint64_t target;
		} m_jobs[JOBS_SIZE];

		struct AutoDiffData {
			uint16_t m_timestamp;
			uint16_t m_hashes;
		} m_autoDiffData[AUTO_DIFF_SIZE];

		uint64_t m_autoDiffWindowHashes;
		uint32_t m_autoDiffIndex;

		difficulty_type m_customDiff;
		difficulty_type m_autoDiff;
		char m_customUser[CUSTOM_USER_SIZE];

		uint64_t m_lastJobTarget;

		int32_t m_score;
	};

	[[nodiscard]] bool on_login(StratumClient* client, uint32_t id, const char* login);
	[[nodiscard]] bool on_submit(StratumClient* client, uint32_t id, const char* job_id_str, const char* nonce_str, const char* result_str);
	[[nodiscard]] uint32_t get_random32();

	void print_status() override;
	void show_workers_async();

	void reset_share_counters();

	bool http_enabled() const;

private:
	[[nodiscard]] const char* get_log_category() const override;

	void print_stratum_status() const;
	void update_auto_diff(StratumClient* client, const uint64_t timestamp, const uint64_t hashes);

	static void on_share_found(uv_work_t* req);
	static void on_after_share_found(uv_work_t* req, int status);

	p2pool* m_pool;
	bool m_autoDiff;

	struct BlobsData
	{
		uint32_t m_extraNonceStart;
		std::vector<uint8_t> m_blobs;
		size_t m_blobSize;
		uint64_t m_target;
		uint32_t m_numClientsExpected;
		uint32_t m_templateId;
		uint64_t m_height;
		hash m_seedHash;
	};

	uv_mutex_t m_blobsQueueLock;
	uv_async_t m_blobsAsync;
	std::vector<BlobsData*> m_blobsQueue;

	static void on_blobs_ready(uv_async_t* handle) { reinterpret_cast<StratumServer*>(handle->data)->on_blobs_ready(); }
	void on_blobs_ready();

	uv_mutex_t m_showWorkersLock;
	uv_async_t m_showWorkersAsync;

	static void on_show_workers(uv_async_t* handle) { reinterpret_cast<StratumServer*>(handle->data)->show_workers(); }
	void show_workers();

	std::atomic<uint32_t> m_extraNonce;

	uv_mutex_t m_rngLock;
	std::mt19937_64 m_rng;

	struct SubmittedShare
	{
		uv_work_t m_req;
		bool m_allocated;

		StratumServer* m_server;
		StratumClient* m_client;
		bool m_clientIPv6;
		raw_ip m_clientAddr;
		char m_clientAddrString[Client::ADDR_STRING_SIZE];
		char m_clientCustomUser[StratumClient::CUSTOM_USER_SIZE];
		uint32_t m_clientResetCounter;
		uint32_t m_rpcId;
		uint32_t m_id;
		uint32_t m_templateId;
		uint32_t m_nonce;
		uint32_t m_extraNonce;
		uint64_t m_target;
		hash m_resultHash;
		difficulty_type m_sidechainDifficulty;
		uint64_t m_mainchainHeight;
		uint64_t m_sidechainHeight;
		double m_effort;
		uint64_t m_timestamp;
		uint64_t m_hashes;
		bool m_highEnoughDifficulty;
		int32_t m_score;

		enum class Result {
			STALE,
			COULDNT_CHECK_POW,
			LOW_DIFF,
			INVALID_POW,
			BANNED,
			OK
		} m_result;
	};

	struct HashrateData
	{
		uint64_t m_timestamp;
		uint64_t m_cumulativeHashes;
	};

	mutable uv_rwlock_t m_hashrateDataLock;

	HashrateData m_hashrateData[131072];
	uint64_t m_cumulativeHashes;
	uint64_t m_cumulativeHashesAtLastShare;
	uint64_t m_hashrateDataHead;
	uint64_t m_hashrateDataTail_15m;
	uint64_t m_hashrateDataTail_1h;
	uint64_t m_hashrateDataTail_24h;

	double m_cumulativeFoundSharesDiff;
	uint32_t m_totalFoundSidechainShares;
	uint32_t m_totalFailedSidechainShares;
	uint64_t m_totalStratumShares;

	uint64_t m_banTime;

	std::atomic<uint64_t> m_apiLastUpdateTime;

	std::deque<SubmittedShare*> m_pendingShareChecks;

	void update_hashrate_data(uint64_t hashes, uint64_t timestamp);
	void api_update_local_stats(uint64_t timestamp);

	void on_shutdown() override;
};

} // namespace p2pool
