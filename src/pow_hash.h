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

class RandomX_Hasher
{
public:
	explicit RandomX_Hasher(p2pool* pool);
	~RandomX_Hasher();

	void set_seed_async(const hash& seed);
	void set_old_seed_async(const hash& seed);

	bool calculate(const void* data, size_t size, const hash& seed, hash& result);

private:
	void set_seed(const hash& seed);
	void set_old_seed(const hash& seed);

	struct ThreadSafeVM
	{
		uv_mutex_t mutex;
		randomx_vm* vm;
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
	ThreadSafeVM m_vm[3];

	hash m_seed[2];
	uint32_t m_index;

	std::atomic<uint32_t> m_setSeedCounter;
};

} // namespace p2pool
