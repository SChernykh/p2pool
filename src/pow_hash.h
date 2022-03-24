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

struct randomx_cache;
struct randomx_dataset;
class randomx_vm;

namespace p2pool {

class p2pool;

class RandomX_Hasher_Base
{
public:
	virtual ~RandomX_Hasher_Base() {}

	virtual void set_seed_async(const hash&) {}
	virtual void set_old_seed(const hash&) {}

	virtual randomx_cache* cache() const { return nullptr; }
	virtual randomx_dataset* dataset() const { return nullptr; }
	virtual uint32_t seed_counter() const { return 0; }
	virtual void sync_wait() {}

	virtual bool calculate(const void* data, size_t size, uint64_t height, const hash& seed, hash& result) = 0;
};

#ifdef WITH_RANDOMX
class RandomX_Hasher : public RandomX_Hasher_Base
{
public:
	explicit RandomX_Hasher(p2pool* pool);
	~RandomX_Hasher();

	void set_seed_async(const hash& seed) override;
	void set_seed(const hash& seed);

	void set_old_seed(const hash& seed) override;

	randomx_cache* cache() const override { return m_cache[m_index]; }
	randomx_dataset* dataset() const override { return m_dataset; }
	uint32_t seed_counter() const override { return m_seedCounter.load(); }
	void sync_wait() override;

	bool calculate(const void* data, size_t size, uint64_t height, const hash& seed, hash& result) override;

private:

	struct ThreadSafeVM
	{
		uv_mutex_t mutex{};
		randomx_vm* vm = nullptr;
	};

	p2pool* m_pool;

	std::atomic<int> m_stopped{ 0 };

	uv_rwlock_t m_cacheLock;
	randomx_cache* m_cache[2];

	uv_rwlock_t m_datasetLock;
	randomx_dataset* m_dataset;

	// 0: light VM for the current seed
	// 1: light VM for the previous seed
	// 2: full dataset VM for the current seed
	enum { FULL_DATASET_VM = 2 };
	ThreadSafeVM m_vm[3]{};

	hash m_seed[2];
	uint32_t m_index;

	std::atomic<uint32_t> m_seedCounter;
	std::atomic<uint32_t> m_oldSeedCounter;
};
#endif

class RandomX_Hasher_RPC : public RandomX_Hasher_Base
{
public:
	explicit RandomX_Hasher_RPC(p2pool* pool);
	~RandomX_Hasher_RPC();

	bool calculate(const void* data, size_t size, uint64_t height, const hash& seed, hash& result) override;

private:
	static void loop(void* data);

	p2pool* m_pool;

	uv_mutex_t m_requestMutex;
	uv_loop_t m_loop;

	uv_thread_t m_loopThread;
	uv_mutex_t m_condMutex;
	uv_cond_t m_cond;

	uv_async_t m_shutdownAsync;
	uv_async_t m_kickTheLoopAsync;

	static void on_shutdown(uv_async_t* async)
	{
		RandomX_Hasher_RPC* server = reinterpret_cast<RandomX_Hasher_RPC*>(async->data);
		uv_close(reinterpret_cast<uv_handle_t*>(&server->m_shutdownAsync), nullptr);
		uv_close(reinterpret_cast<uv_handle_t*>(&server->m_kickTheLoopAsync), nullptr);
	}
};

} // namespace p2pool
