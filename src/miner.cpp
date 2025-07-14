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

#include "common.h"
#include "miner.h"
#include "p2pool.h"
#include "stratum_server.h"
#include "block_template.h"
#include "pow_hash.h"
#include "randomx.h"
#include "params.h"
#include "p2pool_api.h"
#include "side_chain.h"
#include "p2p_server.h"
#include <thread>

LOG_CATEGORY(Miner)

using namespace std::chrono;

namespace p2pool {

Miner::Miner(p2pool* pool, uint32_t threads)
	: m_pool(pool)
	, m_threads(threads)
	, m_stopped{ false }
	, m_startTimestamp(high_resolution_clock::now())
	, m_rng(RandomDeviceSeed::instance)
	, m_fullNonce(std::numeric_limits<uint64_t>::max())
	, m_nonceTimestamp(m_startTimestamp)
	, m_totalHashes(0)
	, m_sharesFound(0)
	, m_sharesFailed(0)
	, m_job{}
	, m_jobIndex{ 0 }
{
	// Diffuse the initial state in case it has low quality
	m_rng.discard(10000);

	on_block(m_pool->block_template());

	m_minerThreads.reserve(threads);

	for (uint32_t i = 0; i < threads; ++i) {
		WorkerData* data = new WorkerData{ this, i + 1, threads, {} };
		const int err = uv_thread_create(&data->m_worker, run, data);
		if (err) {
			LOGERR(1, "failed to start worker thread " << data->m_index << '/' << threads << ", error " << uv_err_name(err));
			delete data;
			continue;
		}
		m_minerThreads.push_back(data);
	}
}

Miner::~Miner()
{
	m_stopped = true;

	for (WorkerData* data : m_minerThreads) {
		uv_thread_join(&data->m_worker);
		delete data;
	}
}

void Miner::print_status()
{
	const uint32_t hash_count = std::numeric_limits<uint32_t>::max() - static_cast<uint32_t>(m_fullNonce.load());

	const double dt = static_cast<double>(duration_cast<nanoseconds>(high_resolution_clock::now() - m_nonceTimestamp).count()) / 1e9;
	const uint64_t hr = (dt > 0.0) ? static_cast<uint64_t>(hash_count / dt) : 0;

	char shares_failed_buf[64] = {};

	const uint32_t shares_found = m_sharesFound;
	const uint32_t shares_failed = m_sharesFailed;
	if (shares_failed) {
		log::Stream s(shares_failed_buf);
		s << log::Yellow() << "\nShares failed = " << shares_failed << log::NoColor();
	}

	LOGINFO(0, "status" <<
		"\nThreads       = " << m_threads <<
		"\nHashrate      = " << log::Hashrate(hr) <<
		"\nShares found  = " << shares_found << static_cast<const char*>(shares_failed_buf)
	);
}

void Miner::on_block(const BlockTemplate& block)
{
	const uint32_t next_index = m_jobIndex ^ 1;
	Job& j = m_job[next_index];
	hash seed;

	const uint32_t extra_nonce = static_cast<uint32_t>(m_rng() >> 32);
	j.m_blobSize = block.get_hashing_blob(extra_nonce, j.m_blob, j.m_height, j.m_sidechainHeight, j.m_diff, j.m_auxDiff, j.m_sidechainDiff, seed, j.m_nonceOffset, j.m_templateId);
	j.m_auxChains = block.get_aux_chains(j.m_templateId);

	const uint64_t next_full_nonce = (static_cast<uint64_t>(extra_nonce) << 32) | std::numeric_limits<uint32_t>::max();
	const uint32_t hash_count = std::numeric_limits<uint32_t>::max() - static_cast<uint32_t>(m_fullNonce.exchange(next_full_nonce));
	m_jobIndex = next_index;

	const auto cur_ts = high_resolution_clock::now();
	const double dt = static_cast<double>(duration_cast<nanoseconds>(cur_ts - m_nonceTimestamp).count()) / 1e9;

	m_nonceTimestamp = cur_ts;
	m_totalHashes += hash_count;

	if (m_pool->api() && m_pool->params().m_localStats && !m_pool->stopped()) {
		const double block_reward_share_percent = m_pool->side_chain().get_reward_share(m_pool->params().m_wallet) * 100.0;

		m_pool->api()->set(p2pool_api::Category::LOCAL, "miner",
			[cur_ts, hash_count, dt, block_reward_share_percent, this](log::Stream& s)
			{
				const uint64_t hr = (dt > 0.0) ? static_cast<uint64_t>(hash_count / dt) : 0;
				const double time_running = static_cast<double>(duration_cast<milliseconds>(cur_ts - m_startTimestamp).count()) / 1e3;

				s << "{\"current_hashrate\":" << hr
					<< ",\"total_hashes\":" << m_totalHashes.load()
					<< ",\"time_running\":" << time_running
					<< ",\"shares_found\":" << m_sharesFound.load()
					<< ",\"shares_failed\":" << m_sharesFailed.load()
					<< ",\"block_reward_share_percent\":" << block_reward_share_percent
					<< ",\"threads\":" << m_threads
					<< "}";
			});
	}
}

void Miner::reset_share_counters()
{
	m_totalHashes = 0;
	m_sharesFound = 0;
	m_sharesFailed = 0;
}

void Miner::run(void* data)
{
	WorkerData* d = static_cast<WorkerData*>(data);
	LOGINFO(1, "worker thread " << d->m_index << '/' << d->m_count << " started");

	char buf[16] = {};
	log::Stream s(buf);
	s << "Miner " << d->m_index << '/' << d->m_count;

	set_thread_name(buf);

	make_thread_background();
	d->m_miner->run(d);
	
	LOGINFO(1, "worker thread " << d->m_index << '/' << d->m_count << " stopped");
}

void Miner::run(WorkerData* data)
{
	RandomX_Hasher_Base* hasher = m_pool->hasher();
	randomx_cache* cache = hasher->cache();
	randomx_dataset* dataset = hasher->dataset();

	if (!cache && !dataset) {
		LOGERR(1, "worker thread " << data->m_index << '/' << data->m_count << ": RandomX cache and dataset are not ready");
		return;
	}

	randomx_flags flags = randomx_get_flags();
	if (dataset) {
		flags |= RANDOMX_FLAG_FULL_MEM;
	}

	randomx_vm* vm = randomx_create_vm(flags | RANDOMX_FLAG_LARGE_PAGES, dataset ? nullptr : cache, dataset);
	if (!vm) {
		LOGWARN(1, "couldn't allocate RandomX VM using large pages");
		vm = randomx_create_vm(flags, dataset ? nullptr : cache, dataset);
		if (!vm) {
			LOGERR(1, "couldn't allocate RandomX VM");
			return;
		}
	}

	uint32_t index = 0;
	Job job[2];

	uint32_t seed_counter = 0;
	bool first = true;

	Miner* miner = data->m_miner;

	while (!m_stopped) {
		if (hasher->seed_counter() != seed_counter) {
			LOGINFO(5, "worker thread " << data->m_index << '/' << data->m_count << " paused (waiting for RandomX cache/dataset update)");
			hasher->sync_wait();
			seed_counter = hasher->seed_counter();
			if (flags & RANDOMX_FLAG_FULL_MEM) {
				dataset = hasher->dataset();
				randomx_vm_set_dataset(vm, dataset);
			}
			else {
				cache = hasher->cache();
				randomx_vm_set_cache(vm, cache);
			}
			LOGINFO(5, "worker thread " << data->m_index << '/' << data->m_count << " resumed");
		}

		if (first) {
			first = false;
			job[index] = miner->m_job[miner->m_jobIndex];

			const uint64_t full_nonce = miner->m_fullNonce.fetch_sub(1);
			job[index].set_nonce(static_cast<uint32_t>(full_nonce), static_cast<uint32_t>(full_nonce >> 32));

			randomx_calculate_hash_first(vm, job[index].m_blob, job[index].m_blobSize);
		}

		const Job& j = job[index];
		index ^= 1;
		job[index] = miner->m_job[miner->m_jobIndex];

		const uint64_t full_nonce = miner->m_fullNonce.fetch_sub(1);
		job[index].set_nonce(static_cast<uint32_t>(full_nonce), static_cast<uint32_t>(full_nonce >> 32));

		hash h;
		try {
			randomx_calculate_hash_next(vm, job[index].m_blob, job[index].m_blobSize, &h);
		}
		catch (const std::exception& e) {
			LOGERR(0, "Failed to calculate RandomX hash: exception \"" << e.what() << "\". Is your CPU/RAM unstable?" <<
				"\nFailed RandomX hash input: " << log::hex_buf(j.m_blob, j.m_blobSize));

			// Make the result hash all FF's to fail difficulty checks
			memset(h.h, -1, HASH_SIZE);
		}

		if (j.m_diff.check_pow(h)) {
			LOGINFO(0, log::Green() << "worker thread " << data->m_index << '/' << data->m_count << " found a mainchain block at height " << j.m_height << ", submitting it");
			m_pool->submit_block_async(j.m_templateId, j.m_nonce, j.m_extraNonce);
		}

		if (j.m_auxDiff.check_pow(h)) {
			std::vector<p2pool::SubmitAuxBlockData> aux_blocks;
			aux_blocks.reserve(j.m_auxChains.size());

			for (const AuxChainData& aux_data : j.m_auxChains) {
				if (aux_data.difficulty.check_pow(h)) {
					LOGINFO(0, log::Green() << "AUX BLOCK FOUND: chain_id " << aux_data.unique_id << ", diff " << aux_data.difficulty << ", worker thread " << data->m_index << '/' << data->m_count);
					aux_blocks.emplace_back(p2pool::SubmitAuxBlockData{ aux_data.unique_id, j.m_templateId, j.m_nonce, j.m_extraNonce });
				}
			}

			if (!aux_blocks.empty()) {
				m_pool->submit_aux_block_async(aux_blocks);
			}
		}

		if (j.m_sidechainDiff.check_pow(h)) {
			LOGINFO(0, log::Green() << "SHARE FOUND: mainchain height " << j.m_height << ", sidechain height " << j.m_sidechainHeight << ", diff " << j.m_sidechainDiff << ", worker thread " << data->m_index << '/' << data->m_count);
			++m_sharesFound;
			if (!m_pool->submit_sidechain_block(j.m_templateId, j.m_nonce, j.m_extraNonce)) {
				if (m_sharesFound > 0) {
					--m_sharesFound;
				}
				++m_sharesFailed;
			}
		}

		std::this_thread::yield();
	}

	randomx_destroy_vm(vm);
}

void Miner::Job::set_nonce(uint32_t nonce, uint32_t extra_nonce)
{
	m_nonce = nonce;
	m_extraNonce = extra_nonce;

	uint8_t* p = m_blob + m_nonceOffset;
	p[0] = static_cast<uint8_t>(nonce);
	p[1] = static_cast<uint8_t>(nonce >> 8);
	p[2] = static_cast<uint8_t>(nonce >> 16);
	p[3] = static_cast<uint8_t>(nonce >> 24);
}

} // namespace p2pool
