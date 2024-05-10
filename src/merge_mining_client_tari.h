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
#include "Tari/proto.h"

namespace p2pool {

class p2pool;

class MergeMiningClientTari : public IMergeMiningClient, public nocopy_nomove
{
public:
	MergeMiningClientTari(p2pool* pool, std::string host, const std::string& wallet);
	~MergeMiningClientTari() override;

	bool get_params(ChainParameters& out_params) const override;
	void submit_solution(const BlockTemplate* block_tpl, const uint8_t (&hashing_blob)[128], size_t nonce_offset, const hash& seed_hash, const std::vector<uint8_t>& blob, const std::vector<hash>& merkle_proof, uint32_t merkle_proof_path) override;

	static constexpr char TARI_PREFIX[] = "tari://";

private:
	mutable uv_rwlock_t m_chainParamsLock;
	ChainParameters m_chainParams;
	tari::rpc::Block m_tariBlock;

	std::string m_auxWallet;
	p2pool* m_pool;

	struct TariJobParams
	{
		uint64_t height;
		uint64_t diff;
		uint64_t reward;
		uint64_t fees;

		FORCEINLINE bool operator!=(const TariJobParams& job) const {
			static_assert(sizeof(TariJobParams) == sizeof(uint64_t) * 4, "Invalid TariJobParams size");
			return memcmp(this, &job, sizeof(TariJobParams)) != 0;
		}
	};

	TariJobParams m_tariJobParams;

private:
	static constexpr uint64_t BUF_SIZE = 16384;

	struct TariClient;

	struct TariServer : public TCPServer
	{
		explicit TariServer(const std::string& socks5Proxy);
		~TariServer() {}

		[[nodiscard]] bool start();
		[[nodiscard]] bool connect_upstream(TariClient* downstream);

		void on_shutdown() override;

		[[nodiscard]] const char* get_log_category() const override;

		bool m_TariNodeIsV6;
		std::string m_TariNodeHost;
		int m_TariNodePort;

		int m_internalPort;
	} *m_server;

	const std::string m_hostStr;

	tari::rpc::BaseNode::Stub* m_TariNode;

	struct TariClient : public TCPServer::Client
	{
		TariClient();
		~TariClient() override {}

		static Client* allocate() { return new TariClient(); }
		virtual size_t size() const override { return sizeof(TariClient); }

		void reset() override;
		[[nodiscard]] bool on_connect() override;
		[[nodiscard]] bool on_read(char* data, uint32_t size) override;

		char m_buf[BUF_SIZE];
		std::vector<uint8_t> m_pendingData;

		bool is_paired() const { return m_pairedClient && (m_pairedClient->m_resetCounter == m_pairedClientSavedResetCounter); }

		TariClient* m_pairedClient;
		uint32_t m_pairedClientSavedResetCounter;
	};

	uv_thread_t m_worker;

	uv_mutex_t m_workerLock;
	uv_cond_t m_workerCond;
	std::atomic<uint32_t> m_workerStop;

	static void run_wrapper(void* arg);
	void run();
};

} // namespace p2pool
