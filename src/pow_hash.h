/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2026 SChernykh <https://github.com/SChernykh>
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

	virtual bool calculate(const void* data, size_t size, uint64_t height, const hash& seed, hash& result, bool force_light_mode, size_t lane) = 0;

	enum {
		VM_LANE_STRATUM = 0,
		VM_LANE_P2P = 1,
		VM_LANE_MONERO = 2,
		VM_LANE_COUNT,
	};
};

#ifdef WITH_RANDOMX
class RandomX_Hasher : public RandomX_Hasher_Base
{
public:
	explicit RandomX_Hasher(p2pool* pool);
	~RandomX_Hasher() override;

	void set_seed_async(const hash& seed) override;
	void set_seed(const hash& seed);

	void set_old_seed(const hash& seed) override;

	randomx_cache* cache() const override { return m_cache[m_index]; }
	randomx_dataset* dataset() const override { return m_dataset; }
	uint32_t seed_counter() const override { return m_seedCounter.load(); }
	void sync_wait() override;

	bool calculate(const void* data, size_t size, uint64_t height, const hash& seed, hash& result, bool force_light_mode, size_t lane) override;

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

	enum {
		LIGHT_VM_CURRENT_SEED = 0,
		LIGHT_VM_PREV_SEED = 1,
		FULL_DATASET_VM = 2,
		VM_INDEX_COUNT,
	};

	ThreadSafeVM m_vm[VM_LANE_COUNT][VM_INDEX_COUNT]{};

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
	~RandomX_Hasher_RPC() override;

	bool calculate(const void* data_ptr, size_t size, uint64_t height, const hash& seed, hash& h, bool force_light_mode, size_t lane) override;

private:
	static void loop(void* data);

	p2pool* m_pool;

	uv_mutex_t m_requestMutex;
	uv_loop_t m_loop;

	uv_thread_t m_loopThread;
	uv_mutex_t m_condMutex;
	uv_cond_t m_cond;

	uv_async_t m_shutdownAsync;

	static void on_shutdown(uv_async_t* async)
	{
		RandomX_Hasher_RPC* server = reinterpret_cast<RandomX_Hasher_RPC*>(async->data);
		uv_close(reinterpret_cast<uv_handle_t*>(&server->m_shutdownAsync), nullptr);

		DeleteLoopUserData(&server->m_loop);
	}
};

} // namespace p2pool
