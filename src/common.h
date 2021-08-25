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

#ifdef _MSC_VER

#pragma warning(disable : 4005 4061 4365 4464 4625 4626 4668 4710 4711 4804 4820 5039 5045 5220)
#define FORCEINLINE __forceinline
#define NOINLINE __declspec(noinline)
#define LIKELY(expression) expression

#elif __GNUC__

#define FORCEINLINE __attribute__((always_inline)) inline
#define NOINLINE __attribute__((noinline))
#define LIKELY(expression) __builtin_expect(expression, 1)

#else

#define FORCEINLINE inline
#define NOINLINE
#define LIKELY(expression) expression

#endif

#include <functional>
#include <type_traits>
#include <limits>

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>

#include <vector>
#include <string>
#include <algorithm>
#include <atomic>

#include <signal.h>

#ifdef _MSC_VER
#include <intrin.h>
#include <immintrin.h>
#endif

#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#elif defined(__linux__) || defined(__unix__) || defined(_POSIX_VERSION) || defined(__MACH__)

#include <unistd.h>
#include <sys/mman.h>

#endif

namespace p2pool {

constexpr size_t HASH_SIZE = 32;
constexpr uint8_t HARDFORK_SUPPORTED_VERSION = 14;
constexpr uint8_t MINER_REWARD_UNLOCK_TIME = 60;
constexpr uint8_t NONCE_SIZE = 4;
constexpr uint8_t EXTRA_NONCE_SIZE = 4;
constexpr uint8_t TX_VERSION = 2;
constexpr uint8_t TXIN_GEN = 0xFF;
constexpr uint8_t TXOUT_TO_KEY = 2;
constexpr uint8_t TX_EXTRA_TAG_PUBKEY = 1;
constexpr uint8_t TX_EXTRA_NONCE = 2;
constexpr uint8_t TX_EXTRA_MERGE_MINING_TAG = 3;

#ifdef _MSC_VER
#define umul128 _umul128
#define udiv128 _udiv128
#else
FORCEINLINE uint64_t umul128(uint64_t a, uint64_t b, uint64_t* hi)
{
	const unsigned __int128 r = static_cast<unsigned __int128>(a) * static_cast<unsigned __int128>(b);
	*hi = r >> 64;
	return static_cast<uint64_t>(r);
}

FORCEINLINE uint64_t udiv128(uint64_t hi, uint64_t lo, uint64_t divisor, uint64_t* remainder)
{
	const unsigned __int128 n = (static_cast<unsigned __int128>(hi) << 64) + lo;

	const uint64_t result = n / divisor;
	*remainder = n % divisor;

	return result;
}
#endif

struct hash
{
	alignas(8) uint8_t h[HASH_SIZE];

	FORCEINLINE hash() : h{} {}

	FORCEINLINE bool operator<(const hash& other) const
	{
		const uint64_t* a = reinterpret_cast<const uint64_t*>(h);
		const uint64_t* b = reinterpret_cast<const uint64_t*>(other.h);

		if (a[3] < b[3]) return true;
		if (a[3] > b[3]) return false;

		if (a[2] < b[2]) return true;
		if (a[2] > b[2]) return false;

		if (a[1] < b[1]) return true;
		if (a[1] > b[1]) return false;

		return (a[0] < b[0]);
	}

	FORCEINLINE bool operator==(const hash& other) const
	{
		const uint64_t* a = reinterpret_cast<const uint64_t*>(h);
		const uint64_t* b = reinterpret_cast<const uint64_t*>(other.h);
		return (a[0] == b[0]) && (a[1] == b[1]) && (a[2] == b[2]) && (a[3] == b[3]);
	}

	FORCEINLINE bool operator!=(const hash& other) const { return !operator==(other); }

	FORCEINLINE bool empty() const {
		const uint64_t* a = reinterpret_cast<const uint64_t*>(h);
		return (a[0] == 0) && (a[1] == 0) && (a[2] == 0) && (a[3] == 0);
	}
};

static_assert(sizeof(hash) == HASH_SIZE, "struct hash has invalid size, check your compiler options");
static_assert(std::is_standard_layout<hash>::value, "struct hash is not a POD, check your compiler options");

struct difficulty_type
{
	FORCEINLINE difficulty_type() : lo(0), hi(0) {}
	FORCEINLINE difficulty_type(uint64_t a, uint64_t b) : lo(a), hi(b) {}

	uint64_t lo;
	uint64_t hi;

	FORCEINLINE difficulty_type& operator+=(const difficulty_type& b)
	{
#ifdef _MSC_VER
		_addcarry_u64(_addcarry_u64(0, lo, b.lo, &lo), hi, b.hi, &hi);
#elif __GNUC__
		*reinterpret_cast<unsigned __int128*>(this) += *reinterpret_cast<const unsigned __int128*>(&b);
#else
		const uint64_t t = lo;
		lo += b.lo;
		const uint64_t carry = (lo < t) ? 1 : 0;
		hi += b.hi + carry;
#endif
		return *this;
	}

	FORCEINLINE bool operator<(const difficulty_type& other) const
	{
		if (hi < other.hi) return true;
		if (hi > other.hi) return false;
		return (lo < other.lo);
	}

	FORCEINLINE bool operator>=(const difficulty_type& other) const { return !operator<(other); }

	FORCEINLINE bool operator==(const difficulty_type& other) const { return (lo == other.lo) && (hi == other.hi); }
	FORCEINLINE bool operator!=(const difficulty_type& other) const { return (lo != other.lo) || (hi != other.hi); }

	// Finds a 64-bit target for mining (target = 2^64 / difficulty) and rounds up the result of division
	// Because of that, there's a very small chance that miners will find a hash that meets the target but is still wrong (hash * difficulty >= 2^256)
	// A proper difficulty check is in check_pow()
	FORCEINLINE uint64_t target() const
	{
		if (hi) {
			return 1;
		}

		uint64_t rem;
		uint64_t result = udiv128(1, 0, lo, &rem);
		return rem ? (result + 1) : result;
	}

	bool check_pow(const hash& pow_hash) const;
};

static_assert(sizeof(difficulty_type) == sizeof(uint64_t) * 2, "struct difficulty_type has invalid size, check your compiler options");
static_assert(std::is_standard_layout<difficulty_type>::value, "struct difficulty_type is not a POD, check your compiler options");

difficulty_type operator+(const difficulty_type& a, const difficulty_type& b);

struct TxMempoolData
{
	FORCEINLINE TxMempoolData() : id(), blob_size(0), weight(0), fee(0) {}

	hash id;
	uint64_t blob_size;
	uint64_t weight;
	uint64_t fee;
};

struct MinerData
{
	FORCEINLINE MinerData()
		: major_version(0)
		, height(0)
		, prev_id()
		, seed_hash()
		, difficulty()
		, median_weight(0)
		, already_generated_coins(0)
		, median_timestamp(0)
	{}

	uint8_t major_version;
	uint64_t height;
	hash prev_id;
	hash seed_hash;
	difficulty_type difficulty;
	uint64_t median_weight;
	uint64_t already_generated_coins;
	uint64_t median_timestamp;
	std::vector<TxMempoolData> tx_backlog;
};

struct ChainMain
{
	FORCEINLINE ChainMain() : height(0), timestamp(0), id() {}

	uint64_t height;
	uint64_t timestamp;
	hash id;
};

} // namespace p2pool

#include "util.h"
#include "log.h"
