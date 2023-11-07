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

#ifdef _MSC_VER

#pragma warning(disable : 4005 4061 4324 4365 4464 4619 4625 4626 4668 4710 4711 4714 4804 4820 5039 5045 5220 5246 5264)
#define FORCEINLINE __forceinline
#define NOINLINE __declspec(noinline)
#define LIKELY(expression) expression
#define MSVC_PRAGMA(...) __pragma(__VA_ARGS__)

#elif __GNUC__

#define FORCEINLINE __attribute__((always_inline)) inline
#define NOINLINE __attribute__((noinline))
#define LIKELY(expression) __builtin_expect(expression, 1)
#define MSVC_PRAGMA(...)

#else

#define FORCEINLINE inline
#define NOINLINE
#define LIKELY(expression) expression
#define MSVC_PRAGMA(...)

#endif

#include <functional>
#include <type_traits>
#include <limits>

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>

#include <array>
#include <vector>
#include <string>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <random>

#include <signal.h>

#ifdef _MSC_VER
#include <intrin.h>
#include <immintrin.h>
#endif

#ifdef _WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#ifndef NOMINMAX
#define NOMINMAX
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#include <Windows.h>

#elif defined(__linux__) || defined(__unix__) || defined(_POSIX_VERSION) || defined(__MACH__)

#include <unistd.h>
#include <sys/mman.h>

#endif

#ifndef __has_feature
  #define __has_feature(x) 0
#endif

#if defined(_DEBUG) || defined(__SANITIZE_ADDRESS__) || __has_feature(address_sanitizer) || defined(__SANITIZE_THREAD__) || __has_feature(thread_sanitizer)
#define P2POOL_DEBUGGING 1
#endif

#if __has_feature(address_sanitizer) || defined(__SANITIZE_ADDRESS__)
#define P2POOL_ASAN
#define ASAN_POISON_MEMORY_REGION(addr, size) __asan_poison_memory_region((addr), (size))
#define ASAN_UNPOISON_MEMORY_REGION(addr, size) __asan_unpoison_memory_region((addr), (size))
extern "C" void __asan_poison_memory_region(void const volatile* addr, size_t size);
extern "C" void __asan_unpoison_memory_region(void const volatile* addr, size_t size);
#else
#define ASAN_POISON_MEMORY_REGION(addr, size)
#define ASAN_UNPOISON_MEMORY_REGION(addr, size)
#endif 

namespace p2pool {

constexpr size_t HASH_SIZE = 32;
constexpr uint8_t HARDFORK_VIEW_TAGS_VERSION = 15;
constexpr uint8_t HARDFORK_SUPPORTED_VERSION = 16;
constexpr uint8_t MINER_REWARD_UNLOCK_TIME = 60;
constexpr uint8_t NONCE_SIZE = 4;
constexpr uint8_t EXTRA_NONCE_SIZE = 4;
constexpr uint8_t EXTRA_NONCE_MAX_SIZE = EXTRA_NONCE_SIZE + 10;
constexpr uint8_t TX_VERSION = 2;
constexpr uint8_t TXIN_GEN = 0xFF;
constexpr uint8_t TXOUT_TO_KEY = 2;
constexpr uint8_t TXOUT_TO_TAGGED_KEY = 3;
constexpr uint8_t TX_EXTRA_TAG_PUBKEY = 1;
constexpr uint8_t TX_EXTRA_NONCE = 2;
constexpr uint8_t TX_EXTRA_MERGE_MINING_TAG = 3;

#ifdef _MSC_VER
#define umul128 _umul128
#define udiv128 _udiv128
FORCEINLINE uint64_t shiftleft128(uint64_t lo, uint64_t hi, uint64_t shift) { return __shiftleft128(lo, hi, static_cast<unsigned char>(shift)); }
FORCEINLINE uint64_t shiftright128(uint64_t lo, uint64_t hi, uint64_t shift) { return __shiftright128(lo, hi, static_cast<unsigned char>(shift)); }
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

FORCEINLINE uint64_t shiftleft128(uint64_t lo, uint64_t hi, uint64_t shift) { return (hi << shift) | (lo >> (64 - shift)); }
FORCEINLINE uint64_t shiftright128(uint64_t lo, uint64_t hi, uint64_t shift) { return (hi << (64 - shift)) | (lo >> shift); }
#endif

template<typename T> constexpr FORCEINLINE T round_up(T a, size_t granularity) { return static_cast<T>(((a + (granularity - static_cast<size_t>(1))) / granularity) * granularity); }

struct alignas(uint64_t) hash
{
	uint8_t h[HASH_SIZE];

	FORCEINLINE hash() : h{} {}

	FORCEINLINE bool operator<(const hash& other) const
	{
		const uint64_t* a = u64();
		const uint64_t* b = other.u64();

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
		const uint64_t* a = u64();
		const uint64_t* b = other.u64();
		return (a[0] == b[0]) && (a[1] == b[1]) && (a[2] == b[2]) && (a[3] == b[3]);
	}

	FORCEINLINE bool operator!=(const hash& other) const { return !operator==(other); }

	FORCEINLINE bool empty() const {
		const uint64_t* a = u64();
		return (a[0] == 0) && (a[1] == 0) && (a[2] == 0) && (a[3] == 0);
	}

	FORCEINLINE void clear() {
		memset(h, 0, HASH_SIZE);
	}

	FORCEINLINE uint64_t* u64() { return reinterpret_cast<uint64_t*>(h); }
	FORCEINLINE const uint64_t* u64() const { return reinterpret_cast<const uint64_t*>(h); }

	friend std::ostream& operator<<(std::ostream& s, const hash& d);
	friend std::istream& operator>>(std::istream& s, hash& d);
};

static_assert(sizeof(hash) == HASH_SIZE, "struct hash has invalid size, check your compiler options");
static_assert(std::is_standard_layout<hash>::value, "struct hash is not a POD, check your compiler options");

struct
#ifdef __GNUC__
	alignas(unsigned __int128)
#endif
	difficulty_type
{
	FORCEINLINE constexpr difficulty_type() : lo(0), hi(0) {}
	FORCEINLINE constexpr difficulty_type(uint64_t a, uint64_t b) : lo(a), hi(b) {}

	uint64_t lo;
	uint64_t hi;

	FORCEINLINE difficulty_type& operator+=(const difficulty_type& b)
	{
#ifdef _MSC_VER
		_addcarry_u64(_addcarry_u64(0, lo, b.lo, &lo), hi, b.hi, &hi);
#elif defined(__GNUC__) && !defined(DEV_CLANG_TIDY)
		*reinterpret_cast<unsigned __int128*>(this) += *reinterpret_cast<const unsigned __int128*>(&b);
#else
		const uint64_t t = lo;
		lo += b.lo;
		const uint64_t carry = (lo < t) ? 1 : 0;
		hi += b.hi + carry;
#endif
		return *this;
	}

	FORCEINLINE difficulty_type& operator+=(uint64_t b) { return operator+=(difficulty_type{ b, 0 }); }

	FORCEINLINE difficulty_type& operator-=(const difficulty_type& b)
	{
#ifdef _MSC_VER
		_subborrow_u64(_subborrow_u64(0, lo, b.lo, &lo), hi, b.hi, &hi);
#elif defined(__GNUC__) && !defined(DEV_CLANG_TIDY)
		*reinterpret_cast<unsigned __int128*>(this) -= *reinterpret_cast<const unsigned __int128*>(&b);
#else
		const uint64_t t = b.lo;
		const uint64_t carry = (lo < t) ? 1 : 0;
		lo -= t;
		hi -= b.hi + carry;
#endif
		return *this;
	}

	FORCEINLINE difficulty_type& operator-=(uint64_t b) { return operator-=(difficulty_type{ b, 0 }); }

	FORCEINLINE difficulty_type& operator*=(const uint64_t b)
	{
		uint64_t t;
		lo = umul128(lo, b, &t);
		hi = t + hi * b;

		return *this;
	}

	FORCEINLINE difficulty_type& operator/=(const uint64_t b)
	{
		const uint64_t t = hi;
		hi = t / b;

		uint64_t r;
		lo = udiv128(t % b, lo, b, &r);

		return *this;
	}

	difficulty_type& operator/=(difficulty_type b);

	FORCEINLINE bool operator<(const difficulty_type& other) const
	{
		if (hi < other.hi) return true;
		if (hi > other.hi) return false;
		return (lo < other.lo);
	}

	FORCEINLINE bool operator>(const difficulty_type& other) const { return other.operator<(*this); }

	FORCEINLINE bool operator>=(const difficulty_type& other) const { return !operator<(other); }
	FORCEINLINE bool operator<=(const difficulty_type& other) const { return !operator>(other); }

	FORCEINLINE bool operator==(const difficulty_type& other) const { return (lo == other.lo) && (hi == other.hi); }
	FORCEINLINE bool operator!=(const difficulty_type& other) const { return (lo != other.lo) || (hi != other.hi); }

	FORCEINLINE bool operator==(uint64_t other) const { return (lo == other) && (hi == 0); }
	FORCEINLINE bool operator!=(uint64_t other) const { return (lo != other) || (hi != 0); }

	friend std::ostream& operator<<(std::ostream& s, const difficulty_type& d);
	friend std::istream& operator>>(std::istream& s, difficulty_type& d);

	FORCEINLINE double to_double() const { return static_cast<double>(hi) * 18446744073709551616.0 + static_cast<double>(lo); }

	FORCEINLINE bool empty() const { return (lo == 0) && (hi == 0); }

	// Finds a 64-bit target for mining (target = 2^64 / difficulty) and rounds up the result of division
	// Because of that, there's a very small chance that miners will find a hash that meets the target but is still wrong (hash * difficulty >= 2^256)
	// A proper difficulty check is in check_pow()
	FORCEINLINE uint64_t target() const
	{
		if (hi) {
			return 1;
		}

		// Safeguard against division by zero (CPU will trigger it even if lo = 1 because result doesn't fit in 64 bits)
		if (lo <= 1) {
			return std::numeric_limits<uint64_t>::max();
		}

		uint64_t rem;
		uint64_t result = udiv128(1, 0, lo, &rem);
		return rem ? (result + 1) : result;
	}

	bool check_pow(const hash& pow_hash) const;
};

static_assert(sizeof(difficulty_type) == sizeof(uint64_t) * 2, "struct difficulty_type has invalid size, check your compiler options");
static_assert(std::is_standard_layout<difficulty_type>::value, "struct difficulty_type is not a POD, check your compiler options");

static constexpr difficulty_type diff_max = { std::numeric_limits<uint64_t>::max(), std::numeric_limits<uint64_t>::max() };

template<typename T>
FORCEINLINE difficulty_type operator+(const difficulty_type& a, const T& b)
{
	difficulty_type result = a;
	result += b;
	return result;
}

template<typename T>
FORCEINLINE difficulty_type operator-(const difficulty_type& a, const T& b)
{
	difficulty_type result = a;
	result -= b;
	return result;
}

FORCEINLINE difficulty_type operator*(const difficulty_type& a, uint64_t b)
{
	difficulty_type result = a;
	result *= b;
	return result;
}

template<typename T>
FORCEINLINE difficulty_type operator/(const difficulty_type& a, const T& b)
{
	difficulty_type result = a;
	result /= b;
	return result;
}

struct TxMempoolData
{
	FORCEINLINE TxMempoolData() : id(), blob_size(0), weight(0), fee(0), time_received(0) {}

	FORCEINLINE bool operator<(const TxMempoolData& tx) const
	{
		const uint64_t a = fee * tx.weight;
		const uint64_t b = tx.fee * weight;

		// Prefer transactions with higher fee/byte
		if (a > b) return true;
		if (a < b) return false;

		// If fee/byte is the same, prefer smaller transactions (they give smaller penalty when going above the median block size limit)
		if (weight < tx.weight) return true;
		if (weight > tx.weight) return false;

		// If two transactions have exactly the same fee and weight, just order them by id
		return id < tx.id;
	}

	hash id;
	uint64_t blob_size;
	uint64_t weight;
	uint64_t fee;
	uint64_t time_received;
};

struct AuxChainData
{
	hash unique_id;
	hash data;
	difficulty_type difficulty;
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
		, aux_nonce(0)
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

	std::vector<AuxChainData> aux_chains;
	uint32_t aux_nonce;

	std::chrono::high_resolution_clock::time_point time_received;
};

struct ChainMain
{
	FORCEINLINE ChainMain() : difficulty(), height(0), timestamp(0), reward(0), id() {}

	difficulty_type difficulty;
	uint64_t height;
	uint64_t timestamp;
	uint64_t reward;
	hash id;
};

enum class NetworkType {
	Invalid,
	Mainnet,
	Testnet,
	Stagenet,
};

struct raw_ip
{
	alignas(8) uint8_t data[16];

	FORCEINLINE bool operator<(const raw_ip& other) const
	{
		const uint64_t* a = reinterpret_cast<const uint64_t*>(data);
		const uint64_t* b = reinterpret_cast<const uint64_t*>(other.data);

		if (a[1] < b[1]) return true;
		if (a[1] > b[1]) return false;

		return a[0] < b[0];
	}

	FORCEINLINE bool operator==(const raw_ip& other) const
	{
		const uint64_t* a = reinterpret_cast<const uint64_t*>(data);
		const uint64_t* b = reinterpret_cast<const uint64_t*>(other.data);

		return (a[0] == b[0]) && (a[1] == b[1]);
	}

	FORCEINLINE bool operator!=(const raw_ip& other) const { return !operator==(other); }

	FORCEINLINE bool is_localhost() const { return (*this == localhost_ipv4) || (*this == localhost_ipv6); }
	FORCEINLINE bool is_ipv4_prefix() const { return memcmp(data, ipv4_prefix, sizeof(ipv4_prefix)) == 0; }

	static const raw_ip localhost_ipv4;
	static const raw_ip localhost_ipv6;

	alignas(8) static const uint8_t ipv4_prefix[12];
};

static_assert(sizeof(raw_ip) == 16, "struct raw_ip has invalid size");

void* malloc_hook(size_t n) noexcept;
void* realloc_hook(void* ptr, size_t size) noexcept;
void* calloc_hook(size_t count, size_t size) noexcept;
void free_hook(void* p) noexcept;
char* strdup_hook(const char* s) noexcept;

extern const char* BLOCK_FOUND;

} // namespace p2pool

#include "util.h"
#include "log.h"
