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

#pragma once

#include "uv_util.h"

namespace p2pool {

class p2pool;

class MergeMiningClient
{
public:
	MergeMiningClient(p2pool* pool, const std::string& host, const std::string& address);
	~MergeMiningClient();

private:
	static void loop(void* data);

	static void on_timer(uv_timer_t* timer) { reinterpret_cast<MergeMiningClient*>(timer->data)->on_timer(); }
	void on_timer();

	void merge_mining_get_chain_id();
	bool parse_merge_mining_get_chain_id(const char* data, size_t size);

	void merge_mining_get_job(uint64_t height, const hash& prev_id, const std::string& address, const hash& aux_hash);
	bool parse_merge_mining_get_job(const char* data, size_t size);

	std::string m_host;
	uint32_t m_port;

	std::string m_auxAddress;
	std::string m_auxBlob;
	hash m_auxHash;
	difficulty_type m_auxDiff;

	hash m_chainID;

	p2pool* m_pool;

	uv_loop_t m_loop;
	uv_thread_t m_loopThread;

	uv_timer_t m_timer;

	bool m_getJobRunning;

	uv_async_t m_shutdownAsync;

	static void on_shutdown(uv_async_t* async)
	{
		MergeMiningClient* client = reinterpret_cast<MergeMiningClient*>(async->data);
		client->on_shutdown();

		uv_close(reinterpret_cast<uv_handle_t*>(&client->m_shutdownAsync), nullptr);

		delete GetLoopUserData(&client->m_loop, false);
	}

	void on_shutdown();
};

} // namespace p2pool
