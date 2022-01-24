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

#include "uv_util.h"
#include <chrono>

namespace p2pool {

class p2pool;
class BlockTemplate;

class Miner
{
public:
	Miner(p2pool* pool, uint32_t threads);
	~Miner();

	void print_status();
	void on_block(const BlockTemplate& block);

private:
	static void run(void* data);

	p2pool* m_pool;
	uint32_t m_threads;

	struct WorkerData
	{
		Miner* m_miner;
		uint32_t m_index;
		uint32_t m_count;
		uv_thread_t m_worker;
	};

	std::vector<WorkerData*> m_minerThreads;
	volatile bool m_stopped;

	std::chrono::time_point<std::chrono::high_resolution_clock> m_startTimestamp;

	std::atomic<uint32_t> m_nonce;
	std::chrono::time_point<std::chrono::high_resolution_clock> m_nonceTimestamp;
	const uint32_t m_extraNonce;

	uint64_t m_totalHashes;
	std::atomic<uint32_t> m_sharesFound;

	struct Job
	{
		uint8_t m_blob[128] = {};
		uint32_t m_blobSize = 0;
		uint32_t m_templateId = 0;
		difficulty_type m_diff = {};
		difficulty_type m_sidechainDiff = {};
		uint64_t m_height = 0;
		size_t m_nonceOffset = 0;
		uint32_t m_nonce = 0;
		uint32_t m_extraNonce = 0;

		void set_nonce(uint32_t nonce, uint32_t extra_nonce);
	};
	Job m_job[2];
	volatile uint32_t m_jobIndex;

	void run(WorkerData* data);
};

} // namespace p2pool
