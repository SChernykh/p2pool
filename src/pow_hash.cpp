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
#include "pow_hash.h"
#include "p2pool.h"
#include "params.h"
#ifdef WITH_RANDOMX
#include "randomx.h"
#include "configuration.h"
#include "virtual_machine.hpp"
#endif
#include "json_rpc_request.h"
#include "json_parsers.h"
#include <rapidjson/document.h>
#include <thread>

LOG_CATEGORY(RandomX_Hasher)

namespace p2pool {

#ifdef WITH_RANDOMX
RandomX_Hasher::RandomX_Hasher(p2pool* pool)
	: m_pool(pool)
	, m_cache{}
	, m_dataset(nullptr)
	, m_seed{}
	, m_index(0)
	, m_seedCounter(0)
	, m_oldSeedCounter(0)
{
	uint64_t memory_allocated = 0;

	if (m_pool && !m_pool->params().m_lightMode) {
		m_dataset = randomx_alloc_dataset(RANDOMX_FLAG_LARGE_PAGES);
		if (!m_dataset) {
			LOGWARN(1, "couldn't allocate RandomX dataset using large pages");
			m_dataset = randomx_alloc_dataset(RANDOMX_FLAG_DEFAULT);
			if (!m_dataset) {
				LOGERR(1, "couldn't allocate RandomX dataset");
			}
		}
		if (m_dataset) {
			memory_allocated += RANDOMX_DATASET_BASE_SIZE + RANDOMX_DATASET_EXTRA_SIZE;
		}
	}

	const randomx_flags flags = randomx_get_flags();

	for (size_t i = 0; i < array_size(&RandomX_Hasher::m_cache); ++i) {
		m_cache[i] = randomx_alloc_cache(flags | RANDOMX_FLAG_LARGE_PAGES);
		if (!m_cache[i]) {
			LOGWARN(1, "couldn't allocate RandomX cache using large pages");
			m_cache[i] = randomx_alloc_cache(flags);
			if (!m_cache[i]) {
				LOGERR(1, "couldn't allocate RandomX cache, aborting");
				PANIC_STOP();
			}
		}
		memory_allocated += RANDOMX_ARGON_MEMORY * 1024;
	}

	uv_rwlock_init_checked(&m_datasetLock);
	uv_rwlock_init_checked(&m_cacheLock);

	for (size_t i = 0; i < array_size(&RandomX_Hasher::m_vm); ++i) {
		uv_mutex_init_checked(&m_vm[i].mutex);
		m_vm[i].vm = nullptr;
	}


	memory_allocated = (memory_allocated + (1 << 20) - 1) >> 20;
	LOGINFO(1, "allocated " << memory_allocated << " MB");
}

RandomX_Hasher::~RandomX_Hasher()
{
	m_stopped.exchange(1);
	{
		WriteLock lock(m_datasetLock);
		WriteLock lock2(m_cacheLock);
	}

	uv_rwlock_destroy(&m_datasetLock);
	uv_rwlock_destroy(&m_cacheLock);

	for (size_t i = 0; i < array_size(&RandomX_Hasher::m_vm); ++i) {
		{
			MutexLock lock(m_vm[i].mutex);
			if (m_vm[i].vm) {
				randomx_destroy_vm(m_vm[i].vm);
			}
		}
		uv_mutex_destroy(&m_vm[i].mutex);
	}

	if (m_dataset) {
		randomx_release_dataset(m_dataset);
	}

	for (size_t i = 0; i < array_size(&RandomX_Hasher::m_cache); ++i) {
		if (m_cache[i]) {
			randomx_release_cache(m_cache[i]);
		}
	}

	LOGINFO(1, "stopped");
}

void RandomX_Hasher::set_seed_async(const hash& seed)
{
	if (m_seed[m_index] == seed) {
		return;
	}

	struct Work
	{
		p2pool* pool;
		RandomX_Hasher* hasher;
		hash seed;
		uv_work_t req;
	};

	Work* work = new Work{ m_pool, this, seed, {} };
	work->req.data = work;

	const int err = uv_queue_work(uv_default_loop_checked(), &work->req,
		[](uv_work_t* req)
		{
			BACKGROUND_JOB_START(RandomX_Hasher::set_seed_async);
			Work* work = reinterpret_cast<Work*>(req->data);
			if (!work->pool->stopped()) {
				work->hasher->set_seed(work->seed);
			}
		},
		[](uv_work_t* req, int)
		{
			delete reinterpret_cast<Work*>(req->data);
			BACKGROUND_JOB_STOP(RandomX_Hasher::set_seed_async);
		}
	);

	if (err) {
		LOGERR(1, "uv_queue_work failed, error " << uv_err_name(err));
		if (!work->pool->stopped()) {
			work->hasher->set_seed(work->seed);
		}
		delete work;
	}
}

void RandomX_Hasher::set_seed(const hash& seed)
{
	if (m_stopped.load()) {
		return;
	}

	WriteLock lock(m_datasetLock);
	uv_rwlock_wrlock(&m_cacheLock);

	m_seedCounter.fetch_add(1);

	if (m_seed[m_index] == seed) {
		uv_rwlock_wrunlock(&m_cacheLock);
		return;
	}

	{
		ON_SCOPE_LEAVE([this]() { uv_rwlock_wrunlock(&m_cacheLock); });

		if (m_stopped.load()) {
			return;
		}

		m_index ^= 1;
		m_seed[m_index] = seed;

		LOGINFO(1, "new seed " << log::LightBlue() << seed);
		randomx_init_cache(m_cache[m_index], m_seed[m_index].h, HASH_SIZE);

		MutexLock lock2(m_vm[m_index].mutex);

		if (m_vm[m_index].vm) {
			m_vm[m_index].vm->setCache(m_cache[m_index]);
		}
		else {
			const randomx_flags flags = randomx_get_flags();

			m_vm[m_index].vm = randomx_create_vm(flags | RANDOMX_FLAG_LARGE_PAGES, m_cache[m_index], nullptr);
			if (!m_vm[m_index].vm) {
				LOGWARN(1, "couldn't allocate RandomX light VM using large pages");
				m_vm[m_index].vm = randomx_create_vm(flags, m_cache[m_index], nullptr);
				if (!m_vm[m_index].vm) {
					LOGERR(1, "couldn't allocate RandomX light VM, aborting");
					PANIC_STOP();
				}
			}
		}
	}

	LOGINFO(1, log::LightCyan() << "cache updated");

	if (m_dataset) {
		const uint32_t numItems = randomx_dataset_item_count();
		uint32_t numThreads = std::thread::hardware_concurrency();

		// Use only half the cores to let other threads do their stuff in the meantime
		if (numThreads > 1) {
			numThreads /= 2;
		}

		// wait for set_old_seed() before initializing dataset
		while (m_oldSeedCounter.load() == 0) {
			std::this_thread::yield();
		}

		LOGINFO(1, log::LightCyan() << "running " << numThreads << " threads to update dataset");

		ReadLock lock2(m_cacheLock);

		if (numThreads > 1) {
			std::vector<std::thread> threads;
			threads.reserve(numThreads);

			for (uint32_t i = 0; i < numThreads; ++i) {
				const uint32_t a = (numItems * i) / numThreads;
				const uint32_t b = (numItems * (i + 1)) / numThreads;

				threads.emplace_back([this, a, b]()
					{
						// Background doesn't work very well with xmrig mining on all cores
						//make_thread_background();
						randomx_init_dataset(m_dataset, m_cache[m_index], a, b - a);
					});
			}

			for (std::thread& t : threads) {
				t.join();
			}
		}
		else {
			randomx_init_dataset(m_dataset, m_cache[m_index], 0, numItems);
		}

		MutexLock lock3(m_vm[FULL_DATASET_VM].mutex);

		if (!m_vm[FULL_DATASET_VM].vm) {
			const randomx_flags flags = randomx_get_flags() | RANDOMX_FLAG_FULL_MEM;

			m_vm[FULL_DATASET_VM].vm = randomx_create_vm(flags | RANDOMX_FLAG_LARGE_PAGES, nullptr, m_dataset);
			if (!m_vm[FULL_DATASET_VM].vm) {
				LOGWARN(1, "couldn't allocate RandomX VM using large pages");
				m_vm[FULL_DATASET_VM].vm = randomx_create_vm(flags, nullptr, m_dataset);
				if (!m_vm[FULL_DATASET_VM].vm) {
					LOGERR(1, "couldn't allocate RandomX VM");
				}
			}
		}

		LOGINFO(1, log::LightCyan() << "dataset updated");
	}
}

void RandomX_Hasher::set_old_seed(const hash& seed)
{
	// set_seed() must go first, wait for it
	while (m_seedCounter.load() == 0) {
		std::this_thread::yield();
	}

	LOGINFO(1, "old seed " << log::LightBlue() << seed);

	{
		WriteLock lock(m_cacheLock);

		m_oldSeedCounter.fetch_add(1);

		const uint32_t old_index = m_index ^ 1;
		m_seed[old_index] = seed;

		randomx_init_cache(m_cache[old_index], m_seed[old_index].h, HASH_SIZE);

		MutexLock lock2(m_vm[old_index].mutex);

		if (m_vm[old_index].vm) {
			m_vm[old_index].vm->setCache(m_cache[old_index]);
		}
		else {
			const randomx_flags flags = randomx_get_flags();

			m_vm[old_index].vm = randomx_create_vm(flags | RANDOMX_FLAG_LARGE_PAGES, m_cache[old_index], nullptr);
			if (!m_vm[old_index].vm) {
				LOGWARN(1, "couldn't allocate RandomX light VM using large pages");
				m_vm[old_index].vm = randomx_create_vm(flags, m_cache[old_index], nullptr);
				if (!m_vm[old_index].vm) {
					LOGERR(1, "couldn't allocate RandomX light VM, aborting");
					PANIC_STOP();
				}
			}
		}
	}
	LOGINFO(1, log::LightCyan() << "old cache updated");
}

void RandomX_Hasher::sync_wait()
{
	ReadLock lock(m_datasetLock);
	ReadLock lock2(m_cacheLock);
}

static bool randomx_calculate_hash_safe(randomx_vm* machine, const void* input, size_t inputSize, void* output)
{
	// Try to calculate the hash again if something went wrong the first time (for example, because of an unstable CPU)
	for (size_t i = 0; i < 2; ++i) {
		try {
			randomx_calculate_hash(machine, input, inputSize, output);
			return true;
		}
		catch (const std::exception& e) {
			LOGERR(0, "Failed to calculate RandomX hash: exception \"" << e.what() << "\". Is your CPU/RAM unstable?" <<
				"\nFailed RandomX hash input: " << log::hex_buf(input, inputSize));
		}
	}
	return false;
}

bool RandomX_Hasher::calculate(const void* data, size_t size, uint64_t /*height*/, const hash& seed, hash& result, bool force_light_mode)
{
	// First try to use the dataset if it's ready
	if (!force_light_mode && (uv_rwlock_tryrdlock(&m_datasetLock) == 0)) {
		ON_SCOPE_LEAVE([this]() { uv_rwlock_rdunlock(&m_datasetLock); });

		if (m_stopped.load()) {
			return false;
		}

		MutexLock lock(m_vm[FULL_DATASET_VM].mutex);

		if (m_vm[FULL_DATASET_VM].vm && (seed == m_seed[m_index])) {
			return randomx_calculate_hash_safe(m_vm[FULL_DATASET_VM].vm, data, size, &result);
		}
	}

	// If dataset is not ready, or force_light_mode = true, use the cache and wait if necessary
	ReadLock lock(m_cacheLock);

	if (m_stopped.load()) {
		return false;
	}

	{
		MutexLock lock2(m_vm[m_index].mutex);
		if (m_vm[m_index].vm && (seed == m_seed[m_index])) {
			return randomx_calculate_hash_safe(m_vm[m_index].vm, data, size, &result);
		}
	}

	const uint32_t prev_index = m_index ^ 1;

	MutexLock lock2(m_vm[prev_index].mutex);

	if (m_vm[prev_index].vm && (seed == m_seed[prev_index])) {
		return randomx_calculate_hash_safe(m_vm[prev_index].vm, data, size, &result);
	}

	return false;
}
#endif

RandomX_Hasher_RPC::RandomX_Hasher_RPC(p2pool* pool)
	: m_pool(pool)
	, m_loop{}
	, m_loopThread{}
{
	int err = uv_loop_init(&m_loop);
	if (err) {
		LOGERR(1, "failed to create event loop, error " << uv_err_name(err));
		PANIC_STOP();
	}

	// Init loop user data before running it
	GetLoopUserData(&m_loop);

	uv_async_init_checked(&m_loop, &m_shutdownAsync, on_shutdown);
	m_shutdownAsync.data = this;

	uv_mutex_init_checked(&m_requestMutex);
	uv_mutex_init_checked(&m_condMutex);

	uv_cond_init_checked(&m_cond);

	err = uv_thread_create(&m_loopThread, loop, this);
	if (err) {
		LOGERR(1, "failed to start event loop thread, error " << uv_err_name(err));
		PANIC_STOP();
	}
}

RandomX_Hasher_RPC::~RandomX_Hasher_RPC()
{
	uv_async_send(&m_shutdownAsync);
	uv_thread_join(&m_loopThread);

	uv_mutex_destroy(&m_requestMutex);
	uv_mutex_destroy(&m_condMutex);
	uv_cond_destroy(&m_cond);

	LOGINFO(1, "stopped");
}

void RandomX_Hasher_RPC::loop(void* data)
{
	LOGINFO(1, "event loop started");

	RandomX_Hasher_RPC* hasher = static_cast<RandomX_Hasher_RPC*>(data);

	int err = uv_run(&hasher->m_loop, UV_RUN_DEFAULT);
	if (err) {
		LOGWARN(1, "uv_run returned " << err);
	}

	err = uv_loop_close(&hasher->m_loop);
	if (err) {
		LOGWARN(1, "uv_loop_close returned error " << uv_err_name(err));
	}

	LOGINFO(1, "event loop stopped");
}

bool RandomX_Hasher_RPC::calculate(const void* data_ptr, size_t size, uint64_t height, const hash& /*seed*/, hash& h, bool /*force_light_mode*/)
{
	MutexLock lock(m_requestMutex);

	const uint8_t* data = reinterpret_cast<const uint8_t*>(data_ptr);
	const uint8_t major_version = data[0];

	char buf[log::Stream::BUF_SIZE + 1] = {};
	log::Stream s(buf);
	s << "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"calc_pow\",\"params\":{\"major_version\":" << major_version <<
		",\"height\":" << height <<
		",\"block_blob\":\"" << log::hex_buf(data, size) << '"' <<
		",\"seed_hash\":\"\"}}\0";

	std::atomic<int> result{ 0 };
	std::atomic<bool> done{ false };

	const Params& params = m_pool->params();
	const Params::Host& host = m_pool->current_host();

	JSONRPCRequest::call(host.m_address, host.m_rpcPort, buf, host.m_rpcLogin, params.m_socks5Proxy,
		[&result, &h](const char* data, size_t size, double)
		{
			rapidjson::Document doc;
			if (doc.Parse(data, size).HasParseError() || !parseValue(doc, "result", h)) {
				LOGWARN(3, "RPC calc_pow: invalid JSON response (parse error)");
				result = -1;
				return;
			}
			result = 1;
		},
		[this, &result, &done](const char* data, size_t size, double)
		{
			if (size > 0) {
				LOGWARN(3, "RPC calc_pow: server returned error " << log::const_buf(data, size));
				result = -1;
			}

			MutexLock lock2(m_condMutex);
			done = true;
			uv_cond_signal(&m_cond);
		}, &m_loop);

	{
		MutexLock lock2(m_condMutex);
		while (!done) {
			uv_cond_wait(&m_cond, &m_condMutex);
		}
	}

	return result > 0;
}

} // namespace p2pool
