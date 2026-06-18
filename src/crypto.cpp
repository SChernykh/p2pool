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

#include "common.h"
#include "crypto.h"
#include "keccak.h"
#include "uv_util.h"
#include <map>

extern "C" {
#include "crypto-ops.h"
}

// l = 2^252 + 27742317777372353535851937790883648493.
// l fits 15 times in 32 bytes (iow, 15 l is the highest multiple of l that fits in 32 bytes)
static constexpr uint8_t limit[32] = { 0xe3, 0x6a, 0x67, 0x72, 0x8b, 0xce, 0x13, 0x29, 0x8f, 0x30, 0x82, 0x8c, 0x0b, 0xa4, 0x10, 0x39, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0 };

namespace p2pool {

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

// cppcheck-suppress constParameterReference
void generate_keys_deterministic(hash& pub, hash& sec, const uint8_t* entropy, size_t len)
{
	uint32_t counter = 0;

	do {
		do {
			++counter;
			keccak_custom([entropy, len, counter](int offset)
			{
				if (offset < static_cast<int>(len)) {
					return entropy[offset];
				}
				return static_cast<uint8_t>(counter >> ((offset - len) * 8));
			}, static_cast<int>(len + sizeof(counter)), sec.h, HASH_SIZE);
		} while (!less32(sec.h, limit));
		sc_reduce32(sec.h);
	} while (!sc_isnonzero(sec.h));

	ge_p3 point;
	ge_scalarmult_base_vartime(&point, sec.h);
	ge_p3_tobytes(pub.h, &point);
}

bool check_keys(const hash& pub, const hash& sec)
{
	// From ge_scalarmult_base's comment: "preconditions a[31] <= 127"
	if (sec.h[HASH_SIZE - 1] > 127) {
		return false;
	}

	ge_p3 point;
	ge_scalarmult_base_vartime(&point, sec.h);

	hash pub_check;
	ge_p3_tobytes(pub_check.h, &point);

	return pub == pub_check;
}

static FORCEINLINE void hash_to_scalar(const uint8_t* data, int length, uint8_t (&res)[HASH_SIZE])
{
	keccak(data, length, res);
	sc_reduce32(res);
}

static FORCEINLINE void derivation_to_scalar(const hash& derivation, size_t output_index, uint8_t (&res)[HASH_SIZE])
{
	struct {
		uint8_t derivation[HASH_SIZE];
		uint8_t output_index[(sizeof(size_t) * 8 + 6) / 7];
	} buf;

	memcpy(buf.derivation, derivation.h, sizeof(buf.derivation));

	uint8_t* p = buf.output_index;
	writeVarint(output_index, [&p](uint8_t b) { *(p++) = b; });

	hash_to_scalar(buf.derivation, static_cast<int>(sizeof(buf.derivation) + (p - buf.output_index)), res);
}

class Cache : public nocopy_nomove
{
public:
	Cache()
		: derivations(new DerivationsMap())
		, public_keys(new PublicKeysMap())
		, tx_keys(new TxKeysMap())
	{
		uv_rwlock_init_checked(&derivations_lock);
		uv_rwlock_init_checked(&public_keys_lock);
		uv_rwlock_init_checked(&tx_keys_lock);
	}

	~Cache()
	{
		delete derivations;
		delete public_keys;
		delete tx_keys;

		uv_rwlock_destroy(&derivations_lock);
		uv_rwlock_destroy(&public_keys_lock);
		uv_rwlock_destroy(&tx_keys_lock);
	}

	bool get_derivation(const hash& key1, const hash& key2, size_t output_index, hash& derivation, uint8_t& view_tag)
	{
		std::array<uint8_t, HASH_SIZE * 2> index;
		memcpy(index.data(), key1.h, HASH_SIZE);
		memcpy(index.data() + HASH_SIZE, key2.h, HASH_SIZE);

		derivation = {};
		{
			ReadLock lock(derivations_lock);
			auto it = derivations->find(index);
			if (it != derivations->end()) {
				const DerivationEntry& entry = it->second;
				derivation = entry.m_derivation;
				if (entry.find_view_tag(output_index, view_tag)) {
					return true;
				}
			}
		}

		if (derivation.empty()) {
			ge_p3 point;
			ge_p2 point2;
			ge_p1p1 point3;

			if (ge_frombytes_vartime(&point, key1.h) != 0) {
				return false;
			}

			ge_scalarmult_vartime(&point2, key2.h, &point);
			ge_mul8(&point3, &point2);
			ge_p1p1_to_p2(&point2, &point3);
			ge_tobytes(reinterpret_cast<uint8_t*>(&derivation), &point2);
		}

		derive_view_tag(derivation, output_index, view_tag);

		const uint32_t t = static_cast<uint32_t>(seconds_since_epoch());
		{
			WriteLock lock(derivations_lock);

			auto entry = derivations->emplace(index, DerivationEntry{ derivation, { 0xFFFFFFFFUL, 0xFFFFFFFFUL }, {}, t }).first;
			entry->second.add_view_tag(static_cast<uint32_t>(output_index << 8) | view_tag);
			limit_size(derivations, 1'000'000, 500'000);
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
			ReadLock lock(public_keys_lock);
			auto it = public_keys->find(index);
			if (it != public_keys->end()) {
				derived_key = it->second.m_key;
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
		ge_scalarmult_base_vartime(&point2, reinterpret_cast<uint8_t*>(&scalar));
		ge_p3_to_cached(&point3, &point2);
		ge_add(&point4, &point1, &point3);
		ge_p1p1_to_p2(&point5, &point4);
		ge_tobytes(derived_key.h, &point5);

		const uint32_t t = static_cast<uint32_t>(seconds_since_epoch());
		{
			WriteLock lock(public_keys_lock);
			public_keys->emplace(index, PublicKeyEntry{ static_cast<indexed_hash>(derived_key), t });
			limit_size(public_keys, 1'000'000, 500'000);
		}

		return true;
	}

	void get_tx_keys(hash& pub, hash& sec, const hash& seed, const hash& monero_block_id)
	{
		std::array<uint8_t, HASH_SIZE * 2> index;
		memcpy(index.data(), seed.h, HASH_SIZE);
		memcpy(index.data() + HASH_SIZE, monero_block_id.h, HASH_SIZE);

		{
			ReadLock lock(tx_keys_lock);
			auto it = tx_keys->find(index);
			if (it != tx_keys->end()) {
				pub = it->second.m_pub;
				sec = it->second.m_sec;
				return;
			}
		}

		static constexpr char domain[] = "tx_secret_key";
		static constexpr size_t N = sizeof(domain) - 1;
		uint8_t entropy[N + HASH_SIZE * 2];

		memcpy(entropy, domain, N);
		memcpy(entropy + N, seed.h, HASH_SIZE);
		memcpy(entropy + N + HASH_SIZE, monero_block_id.h, HASH_SIZE);

		generate_keys_deterministic(pub, sec, entropy, sizeof(entropy));

		const uint32_t t = static_cast<uint32_t>(seconds_since_epoch());
		{
			WriteLock lock(tx_keys_lock);
			tx_keys->emplace(index, TxKeyEntry{ pub, sec, t });
			limit_size(tx_keys, 10'000, 5'000);
		}
	}

	// Must be called with an appropriate lock held
	template<typename T>
	void clean_old(T* table, uint32_t timestamp, size_t excess_at_timestamp = 0) {
		for (auto it = table->begin(); it != table->end();) {
			const uint32_t t = it->second.m_timestamp;
			bool remove;

			if ((excess_at_timestamp > 0) && (t == timestamp)) {
				remove = true;
				--excess_at_timestamp;
			}
			else {
				// Wraparound-safe way of checking "it->second.m_timestamp < timestamp"
				remove = (((t - timestamp) & 0x80000000UL) != 0);
			}

			if (remove) {
				it = table->erase(it);
			}
			else {
				++it;
			}
		}
	};

	// Must be called with an appropriate lock held
	// If the table exceeded max_size, deletes oldest entries to shrink the table to <= max_new_size entries
	template<typename T>
	void limit_size(T* table, size_t max_size, size_t max_new_size)
	{
		if (table->size() <= max_size) {
			return;
		}

		const uint32_t now = static_cast<uint32_t>(seconds_since_epoch());
		std::map<uint32_t, size_t> ages;

		for (const auto& data : *table) {
			++ages[now - data.second.m_timestamp];
		}

		size_t k = 0;

		for (auto it = ages.begin(); it != ages.end(); ++it) {
			k += it->second;

			if (k >= max_new_size) {
				clean_old(table, now - it->first, k - max_new_size);
				return;
			}
		}
	}

	void clear(uint64_t timestamp)
	{
		if (timestamp) {
			const uint32_t t = static_cast<uint32_t>(timestamp);
			{
				WriteLock lock(derivations_lock);
				clean_old(derivations, t);
			}
			{
				WriteLock lock(public_keys_lock);
				clean_old(public_keys, t);
			}
			{
				WriteLock lock(tx_keys_lock);
				clean_old(tx_keys, t);
			}
			return;
		}

		{
			WriteLock lock(derivations_lock);
			delete derivations;
			derivations = new DerivationsMap();
			derivations->reserve(5000);
		}
		{
			WriteLock lock(public_keys_lock);
			delete public_keys;
			public_keys = new PublicKeysMap();
			public_keys->reserve(5000);
		}
		{
			WriteLock lock(tx_keys_lock);
			delete tx_keys;
			tx_keys = new TxKeysMap();
			tx_keys->reserve(50);
		}
	}

private:
	struct DerivationEntry
	{
		hash m_derivation;
		uint32_t m_viewTags1[2] = { 0xFFFFFFFFUL, 0xFFFFFFFFUL };
		std::vector<uint32_t> m_viewTags2;
		// cppcheck-suppress unusedStructMember
		uint32_t m_timestamp = 0;

		FORCEINLINE bool find_view_tag(size_t output_index, uint8_t& view_tag) const
		{
#define ITER(i) do { \
				const uint32_t k = m_viewTags1[i]; \
				if ((k >> 8) == output_index) { \
					view_tag = static_cast<uint8_t>(k); \
					return true; \
				} \
			} while(0)

			ITER(0);
			ITER(1);
#undef ITER

			for (const uint32_t k : m_viewTags2) {
				if ((k >> 8) == output_index) {
					view_tag = static_cast<uint8_t>(k);
					return true;
				}
			}
			return false;
		}

		FORCEINLINE void add_view_tag(uint32_t k)
		{
#define ITER(i) do { \
				const uint32_t t = m_viewTags1[i]; \
				if (t == 0xFFFFFFFFUL) { \
					m_viewTags1[i] = k; \
					return; \
				} \
				if (t == k) { \
					return; \
				} \
			} while (0)

			ITER(0);
			ITER(1);
#undef ITER

			if ((m_viewTags2.size() < 16) && (std::find(m_viewTags2.begin(), m_viewTags2.end(), k) == m_viewTags2.end())) {
				m_viewTags2.emplace_back(k);
			}
		}
	};

	struct PublicKeyEntry
	{
		indexed_hash m_key;
		// cppcheck-suppress unusedStructMember
		uint32_t m_timestamp = 0;
	};

	struct TxKeyEntry
	{
		hash m_pub;
		hash m_sec;
		// cppcheck-suppress unusedStructMember
		uint32_t m_timestamp = 0;
	};

	typedef unordered_map<std::array<uint8_t, HASH_SIZE * 2>, DerivationEntry> DerivationsMap;
	typedef unordered_map<std::array<uint8_t, HASH_SIZE * 2 + sizeof(size_t)>, PublicKeyEntry> PublicKeysMap;
	typedef unordered_map<std::array<uint8_t, HASH_SIZE * 2>, TxKeyEntry> TxKeysMap;

	uv_rwlock_t derivations_lock;
	DerivationsMap* derivations;

	uv_rwlock_t public_keys_lock;
	PublicKeysMap* public_keys;

	uv_rwlock_t tx_keys_lock;
	TxKeysMap* tx_keys;
};

static Cache* cache = nullptr;

bool generate_key_derivation(const hash& key1, const hash& key2, size_t output_index, hash& derivation, uint8_t& view_tag)
{
	return cache->get_derivation(key1, key2, output_index, derivation, view_tag);
}

bool derive_public_key(const hash& derivation, size_t output_index, const hash& base, hash& derived_key)
{
	return cache->get_public_key(derivation, output_index, base, derived_key);
}

void get_tx_keys(hash& pub, hash& sec, const hash& seed, const hash& monero_block_id)
{
	cache->get_tx_keys(pub, sec, seed, monero_block_id);
}

void derive_view_tag(const hash& derivation, size_t output_index, uint8_t& view_tag)
{
	constexpr uint8_t salt[] = "view_tag";
	constexpr size_t SALT_SIZE = sizeof(salt) - 1;

	uint8_t buf[64];
	memcpy(buf, salt, SALT_SIZE);
	memcpy(buf + SALT_SIZE, derivation.h, HASH_SIZE);
	uint8_t* p = buf + SALT_SIZE + HASH_SIZE;
	writeVarint(output_index, [&p](uint8_t b) { *(p++) = b; });

	hash view_tag_full;
	keccak(buf, static_cast<int>(p - buf), view_tag_full.h);
	view_tag = view_tag_full.h[0];
}

void init_crypto_cache()
{
	if (!cache) {
		cache = new Cache();
	}
}

void destroy_crypto_cache()
{
	{
		auto* p = cache;
		cache = nullptr;
		delete p;
	}
}

void clear_crypto_cache(uint64_t timestamp)
{
	if (cache) {
		cache->clear(timestamp);
	}
}

} // namespace p2pool
