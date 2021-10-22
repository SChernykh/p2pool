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

#include "common.h"
#include "crypto.h"
#include "keccak.h"
#include "uv_util.h"
#include <random>

extern "C" {
#include "crypto-ops.h"
}

namespace p2pool {

namespace {

class RandomBytes
{
public:
	RandomBytes() : rd(), rng(rd()), dist(0, 255)
	{
		uv_mutex_init_checked(&m);
	}

	~RandomBytes()
	{
		uv_mutex_destroy(&m);
	}

	void operator()(uint8_t (&bytes)[HASH_SIZE])
	{
		MutexLock lock(m);

		for (size_t i = 0; i < HASH_SIZE; ++i) {
			bytes[i] = static_cast<uint8_t>(dist(rng));
		}
	}

private:
	uv_mutex_t m;

	std::random_device rd;
	std::mt19937_64 rng;
	std::uniform_int_distribution<> dist;
};

static RandomBytes randomBytes;

}

static FORCEINLINE bool less32(const uint8_t* k0, const uint8_t* k1)
{
	for (int n = 31; n >= 0; --n)
	{
		if (k0[n] < k1[n])
			return true;
		if (k0[n] > k1[n])
			return false;
	}
	return false;
}

// cppcheck-suppress constParameter
void generate_keys(hash& pub, hash& sec)
{
	// l = 2^252 + 27742317777372353535851937790883648493.
	// l fits 15 times in 32 bytes (iow, 15 l is the highest multiple of l that fits in 32 bytes)
	static constexpr uint8_t limit[32] = { 0xe3, 0x6a, 0x67, 0x72, 0x8b, 0xce, 0x13, 0x29, 0x8f, 0x30, 0x82, 0x8c, 0x0b, 0xa4, 0x10, 0x39, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0 };

	do {
		do { randomBytes(sec.h); } while (!less32(sec.h, limit));
		sc_reduce32(sec.h);
	} while (!sc_isnonzero(sec.h));

	ge_p3 point;
	ge_scalarmult_base(&point, sec.h);
	ge_p3_tobytes(pub.h, &point);
}

bool check_keys(const hash& pub, const hash& sec)
{
	// From ge_scalarmult_base's comment: "preconditions a[31] <= 127"
	if (sec.h[HASH_SIZE - 1] > 127) {
		return false;
	}

	ge_p3 point;
	ge_scalarmult_base(&point, sec.h);

	hash pub_check;
	ge_p3_tobytes(pub_check.h, &point);

	return pub == pub_check;
}

static FORCEINLINE void hash_to_scalar(const uint8_t* data, size_t length, uint8_t(&res)[HASH_SIZE])
{
	keccak(data, static_cast<int>(length), res, HASH_SIZE);
	sc_reduce32(res);
}

static FORCEINLINE void derivation_to_scalar(const hash& derivation, size_t output_index, uint8_t (&res)[HASH_SIZE])
{
	struct {
		uint8_t derivation[HASH_SIZE];
		uint8_t output_index[(sizeof(size_t) * 8 + 6) / 7];
	} buf;

	uint8_t* begin = buf.derivation;
	uint8_t* end = buf.output_index;
	memcpy(buf.derivation, derivation.h, sizeof(buf.derivation));

	size_t k = output_index;
	while (k >= 0x80) {
		*(end++) = (static_cast<uint8_t>(k) & 0x7F) | 0x80;
		k >>= 7;
	}
	*(end++) = static_cast<uint8_t>(k);

	hash_to_scalar(begin, end - begin, res);
}

class Cache
{
public:
	Cache()
	{
		uv_mutex_init_checked(&m);
	}

	~Cache()
	{
		uv_mutex_destroy(&m);
	}

	bool get_derivation(const hash& key1, const hash& key2, hash& derivation)
	{
		std::array<uint8_t, HASH_SIZE * 2> index;
		memcpy(index.data(), key1.h, HASH_SIZE);
		memcpy(index.data() + HASH_SIZE, key2.h, HASH_SIZE);

		{
			MutexLock lock(m);
			auto it = derivations.find(index);
			if (it != derivations.end()) {
				derivation = it->second;
				return true;
			}
		}

		ge_p3 point;
		ge_p2 point2;
		ge_p1p1 point3;

		if (ge_frombytes_vartime(&point, key1.h) != 0) {
			return false;
		}

		ge_scalarmult(&point2, key2.h, &point);
		ge_mul8(&point3, &point2);
		ge_p1p1_to_p2(&point2, &point3);
		ge_tobytes(reinterpret_cast<uint8_t*>(&derivation), &point2);

		{
			MutexLock lock(m);
			derivations.emplace(index, derivation);
		}

		return true;
	}

	bool get_public_key(const hash& derivation, size_t output_index, const hash& base, hash& derived_key)
	{
		std::array<uint8_t, HASH_SIZE * 2 + sizeof(size_t)> index;
		memcpy(index.data(), derivation.h, HASH_SIZE);
		memcpy(index.data() + HASH_SIZE, base.h, HASH_SIZE);
		memcpy(index.data() + HASH_SIZE * 2, &output_index, sizeof(size_t));

		{
			MutexLock lock(m);
			auto it = public_keys.find(index);
			if (it != public_keys.end()) {
				derived_key = it->second;
				return true;
			}
		}

		uint8_t scalar[HASH_SIZE];
		ge_p3 point1;
		ge_p3 point2;
		ge_cached point3;
		ge_p1p1 point4;
		ge_p2 point5;

		if (ge_frombytes_vartime(&point1, base.h) != 0) {
			return false;
		}

		derivation_to_scalar(derivation, output_index, scalar);
		ge_scalarmult_base(&point2, reinterpret_cast<uint8_t*>(&scalar));
		ge_p3_to_cached(&point3, &point2);
		ge_add(&point4, &point1, &point3);
		ge_p1p1_to_p2(&point5, &point4);
		ge_tobytes(derived_key.h, &point5);

		{
			MutexLock lock(m);
			public_keys.emplace(index, derived_key);
		}

		return true;
	}

	void clear()
	{
		MutexLock lock(m);

		derivations.clear();
		public_keys.clear();
	}

private:
	uv_mutex_t m;
	unordered_map<std::array<uint8_t, HASH_SIZE * 2>, hash> derivations;
	unordered_map<std::array<uint8_t, HASH_SIZE * 2 + sizeof(size_t)>, hash> public_keys;
};

static Cache* cache = nullptr;

bool generate_key_derivation(const hash& key1, const hash& key2, hash& derivation)
{
	return cache->get_derivation(key1, key2, derivation);
}

bool derive_public_key(const hash& derivation, size_t output_index, const hash& base, hash& derived_key)
{
	return cache->get_public_key(derivation, output_index, base, derived_key);
}

void init_crypto_cache()
{
	if (!cache) {
		cache = new Cache();
	}
}

void destroy_crypto_cache()
{
	if (cache) {
		delete cache;
		cache = nullptr;
	}
}

void clear_crypto_cache()
{
	cache->clear();
}

} // namespace p2pool
