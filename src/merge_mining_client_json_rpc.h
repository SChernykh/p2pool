/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2025 SChernykh <https://github.com/SChernykh>
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

#include "uv_util.h"

namespace p2pool {

class p2pool;
struct PoolBlock;

class MergeMiningClientJSON_RPC : public IMergeMiningClient
{
public:
	MergeMiningClientJSON_RPC(p2pool* pool, const std::string& host, const std::string& wallet);
	~MergeMiningClientJSON_RPC() override;

	bool get_params(ChainParameters& out_params) const override;
	void on_external_block(const PoolBlock& /*block*/) override {}
	void submit_solution(const std::vector<uint8_t>& coinbase_merkle_proof, const uint8_t (&hashing_blob)[128], size_t nonce_offset, const hash& seed_hash, const std::vector<uint8_t>& blob, const std::vector<hash>& merkle_proof, uint32_t merkle_proof_path) override;

	void print_status() const override;
	void api_status(log::Stream&) const override;

private:
	static void loop(void* data);

	static void on_timer(uv_timer_t* timer) { reinterpret_cast<MergeMiningClientJSON_RPC*>(timer->data)->on_timer(); }
	void on_timer();

	void merge_mining_get_chain_id();
	bool parse_merge_mining_get_chain_id(const char* data, size_t size);

	void merge_mining_get_aux_block(uint64_t height, const hash& prev_id, const std::string& wallet);
	bool parse_merge_mining_get_aux_block(const char* data, size_t size, bool& changed);

	bool parse_merge_mining_submit_solution(const char* data, size_t size) const;

	std::string m_host;
	uint32_t m_port;

	mutable uv_rwlock_t m_lock;
	ChainParameters m_chainParams;

	uint64_t m_chainParamsTimestamp;

	std::string m_auxWallet;

	double m_ping;

	p2pool* m_pool;

	uv_loop_t m_loop;
	uv_thread_t m_loopThread;

	uv_timer_t m_timer;

	bool m_getJobRunning;

	uv_async_t m_shutdownAsync;

	static void on_shutdown(uv_async_t* async)
	{
		MergeMiningClientJSON_RPC* client = reinterpret_cast<MergeMiningClientJSON_RPC*>(async->data);
		client->on_shutdown();

		uv_close(reinterpret_cast<uv_handle_t*>(&client->m_shutdownAsync), nullptr);

		DeleteLoopUserData(&client->m_loop);
	}

	void on_shutdown();
};

} // namespace p2pool
