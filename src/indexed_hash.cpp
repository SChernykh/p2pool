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
#include "util.h"
#include "uv_util.h"

LOG_CATEGORY(indexed_hash)

namespace p2pool {

static constexpr uint32_t BUCKET_COUNT = 1U << indexed_hash::BUCKET_BITS;
static constexpr uint32_t INDEX_MASK = (1U << indexed_hash::BUCKET_SHIFT) - 1U;

// Stores hashes only
static std::vector<hash> storage1[BUCKET_COUNT];

// Stores first 4 bytes of each hash (for better cache locality during search) and reference counters
static std::vector<std::pair<uint32_t, uint32_t>> storage2[BUCKET_COUNT];

static constexpr uint32_t LOCK_COUNT = 64;

static ReadWriteLock locks[LOCK_COUNT];

static FORCEINLINE void decref(uint32_t index)
{
	if (index == std::numeric_limits<uint32_t>::max()) {
		return;
	}

	const uint32_t bucket = index >> indexed_hash::BUCKET_SHIFT;
	index &= INDEX_MASK;

	auto& d2 = storage2[bucket];

	WriteLock lock(locks[bucket % LOCK_COUNT]);

	auto& p2 = d2[index];

#ifdef P2POOL_DEBUGGING
	if (p2.second == 0) {
		LOGERR(0, "fatal error: reference counter is 0 when it shouldn't be 0");
		PANIC_STOP();
	}
#endif

	--p2.second;
}

static FORCEINLINE void incref(uint32_t index)
{
	if (index == std::numeric_limits<uint32_t>::max()) {
		return;
	}

	const uint32_t bucket = index >> indexed_hash::BUCKET_SHIFT;
	index &= INDEX_MASK;

	auto& d2 = storage2[bucket];

	WriteLock lock(locks[bucket % LOCK_COUNT]);
	++d2[index].second;
}

indexed_hash::indexed_hash(const hash& h)
{
	if (h.empty()) {
		m_index = std::numeric_limits<uint32_t>::max();
		return;
	}

	const uint32_t bucket = get_bucket(h);

	auto& d1 = storage1[bucket];
	auto& d2 = storage2[bucket];

	const uint32_t h32 = static_cast<uint32_t>(h.u64()[0]);
	uint32_t first_free_slot = std::numeric_limits<uint32_t>::max();

	WriteLock lock(locks[bucket % LOCK_COUNT]);

	const uint32_t n = static_cast<uint32_t>(d1.size());

	for (uint32_t i = 0; i < n; ++i) {
		auto& p2 = d2[i];

		if ((p2.first == h32) && (d1[i] == h)) {
			m_index = (bucket << BUCKET_SHIFT) | i;
			++p2.second;
			return;
		}

		if ((p2.second == 0) && (first_free_slot == std::numeric_limits<uint32_t>::max())) {
			first_free_slot = i;
		}
	}

	if (first_free_slot != std::numeric_limits<uint32_t>::max()) {
		m_index = (bucket << BUCKET_SHIFT) | first_free_slot;

		d1[first_free_slot] = h;

		auto& p2 = d2[first_free_slot];
		p2.first = h32;
		p2.second = 1;
	}
	else {
		if (n > INDEX_MASK) {
			LOGERR(0, "fatal error: storage overflow");
			PANIC_STOP();
		}

		m_index = (bucket << BUCKET_SHIFT) | n;

		if (n == d1.capacity()) {
			const uint32_t new_capacity = static_cast<uint32_t>(std::min<size_t>(n + ((n + 3) / 4), INDEX_MASK + 1));
			d1.reserve(new_capacity);
			d2.reserve(new_capacity);
		}

		d1.emplace_back(h);
		d2.emplace_back(h32, 1);
	}
}

indexed_hash::~indexed_hash()
{
	decref(m_index);
}

indexed_hash::indexed_hash(const indexed_hash& h)
{
	const uint32_t i = h.m_index;

	m_index = i;
	incref(i);
}

indexed_hash& indexed_hash::operator=(const indexed_hash& h)
{
	if (this == &h) {
		return *this;
	}

	const uint32_t i = m_index;
	const uint32_t j = h.m_index;

	if (i == j) {
		return *this;
	}

	decref(i);

	m_index = j;
	incref(j);

	return *this;
}

indexed_hash& indexed_hash::operator=(indexed_hash&& h)
{
	if (this == &h) {
		return *this;
	}

	const uint32_t i = m_index;
	const uint32_t j = h.m_index;

	// Empty h because we're moving it
	h.m_index = std::numeric_limits<uint32_t>::max();

	if (i == j) {
		// If h had the same index, decrease h's reference counter because now we have 1 instead of 2 objects using this index
		decref(j);
		return *this;
	}

	// If h had a different index, decrease our reference counter because our index will be overwritten by the index from h
	decref(i);

	// No need to change the reference counter anymore because now we are referencing the hash that was referenced by h
	m_index = j;

	return *this;
}

hash indexed_hash::get(uint32_t index)
{
	const uint32_t bucket = index >> BUCKET_SHIFT;

	const auto& d1 = storage1[bucket];
	index &= INDEX_MASK;

	ReadLock lock(locks[bucket % LOCK_COUNT]);

#ifdef P2POOL_DEBUGGING
	if (storage2[bucket][index].second == 0) {
		LOGERR(0, "fatal error: reference counter is 0 when it shouldn't be 0");
		PANIC_STOP();
	}
#endif

	return d1[index];
}

bool indexed_hash::is_same(uint32_t index, uint32_t bucket, const hash& h)
{
	const auto& d1 = storage1[bucket];
	index &= INDEX_MASK;

	ReadLock lock(locks[bucket % LOCK_COUNT]);

#ifdef P2POOL_DEBUGGING
	if (storage2[bucket][index].second == 0) {
		LOGERR(0, "fatal error: reference counter is 0 when it shouldn't be 0");
		PANIC_STOP();
	}
#endif

	return d1[index] == h;
}

void indexed_hash::cleanup_storage()
{
	for (auto& d1 : storage1) {
		d1.clear();
		d1.shrink_to_fit();
	}

	for (auto& d2 : storage2) {
#ifdef P2POOL_DEBUGGING
		for (const auto& p2 : d2) {
			if (p2.second) {
				LOGERR(0, "storage is not empty at exit. Fix the code!");
				PANIC_STOP();
			}
		}
#endif
		d2.clear();
		d2.shrink_to_fit();
	}
}

void indexed_hash::print_status()
{
	size_t total_hashes_stored = 0;
	size_t total_refcount = 0;
	size_t memory_used = 0;

	const auto& s1 = storage1;
	const auto& s2 = storage2;

	for (uint32_t i = 0; i < LOCK_COUNT; ++i) {
		ReadLock lock(locks[i]);

		for (uint32_t j = i; j < BUCKET_COUNT; j += LOCK_COUNT) {
			memory_used += s1[j].capacity() * HASH_SIZE + s2[j].capacity() * sizeof(uint32_t) * 2;

			for (const auto& p2 : storage2[j]) {
				if (p2.second) {
					++total_hashes_stored;
					total_refcount += p2.second;
				}
			}
		}
	}

	memory_used += total_refcount * sizeof(indexed_hash);

	LOGINFO(4, "status" <<
		"\nTotal hashes stored = " << total_hashes_stored <<
		"\nTotal refcount = " << total_refcount <<
		"\nMemory used = " << static_cast<double>(memory_used) / 1048576.0 << " MB (reduced from " << static_cast<double>(total_refcount * HASH_SIZE) / 1048576.0 << " MB)"
	);
}

} // namespace p2pool
