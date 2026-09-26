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
#include "carrot.h"
#include "keccak.h"
#include "uv_util.h"
#include "wallet.h"
#include "fcmp_pp_crypto.h"
#include <map>

#ifdef P2POOL_DEBUGGING
LOG_CATEGORY(Crypto)
#endif

// The prime order l = 2^252 + 27742317777372353535851937790883648493 of Ed25519's main subgroup,
// encoded as a 32-byte little-endian integer. A point P is in the main subgroup if [l]P is the identity.
static constexpr uint8_t curve_order[32] = { 0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10 };

// l fits 15 times in 32 bytes (iow, 15 l is the highest multiple of l that fits in 32 bytes)
static constexpr uint8_t limit[32] = { 0xe3, 0x6a, 0x67, 0x72, 0x8b, 0xce, 0x13, 0x29, 0x8f, 0x30, 0x82, 0x8c, 0x0b, 0xa4, 0x10, 0x39, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0 };

namespace p2pool {

bool is_in_main_subgroup(const ge_p3& point)
{
	ge_p3 result;
	ge_scalarmult_p3(&result, curve_order, &point);

	return ge_p3_is_point_at_infinity_vartime(&result) != 0;
}

static FORCEINLINE bool is_torsion_free(const ge_p3& point)
{
	// torsion_check_vartime() has a "point*8 is not the identity" pre-condition
	return !fcmp_pp::mul8_is_identity(point) && fcmp_pp::torsion_check_vartime(point);
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

struct CombTable
{
	ge_combp m_data;
};

class Cache : public nocopy_nomove
{
public:
	Cache()
		: derivations(new DerivationsMap())
		, coinbase_secrets(new CoinbaseSecretsMap())
		, public_keys(new PublicKeysMap())
		, tx_keys(new TxKeysMap())
		, from_bytes(new FromBytesMap())
		, comb_tables(new CombTablesMap())
	{
		uv_rwlock_init_checked(&derivations_lock);
		uv_rwlock_init_checked(&coinbase_secrets_lock);
		uv_rwlock_init_checked(&public_keys_lock);
		uv_rwlock_init_checked(&tx_keys_lock);
		uv_rwlock_init_checked(&from_bytes_lock);
		uv_rwlock_init_checked(&comb_tables_lock);

		if (ge_wtable_precomp_base(base_table) || ge_wtable_precomp_T(T_table)) {
			PANIC_STOP();
		}
	}

	~Cache()
	{
		delete derivations;
		delete coinbase_secrets;
		delete public_keys;
		delete tx_keys;
		delete from_bytes;
		delete comb_tables;

		uv_rwlock_destroy(&derivations_lock);
		uv_rwlock_destroy(&coinbase_secrets_lock);
		uv_rwlock_destroy(&public_keys_lock);
		uv_rwlock_destroy(&tx_keys_lock);
		uv_rwlock_destroy(&from_bytes_lock);
		uv_rwlock_destroy(&comb_tables_lock);
	}

	FORCEINLINE void scalarmult_base(ge_p3* h, const uint8_t* a) const { ge_scalarmult_wtable_vartime(h, base_table, a); }
	FORCEINLINE void double_scalarmult_base_T(ge_p3* h, const uint8_t* a, const uint8_t* b) const { ge_double_scalarmult_wtable_vartime(h, base_table, a, T_table, b); }

	bool get_from_bytes(const hash& h, ge_p3& p)
	{
		{
			ReadLock lock(from_bytes_lock);

			auto it = from_bytes->find(h);

			if (it != from_bytes->end()) {
				const FromBytesEntry& entry = it->second;

				if (!entry.m_valid) {
					return false;
				}

				p = entry.m_point;
				return true;
			}
		}

		ge_p3 point = {};
		const bool valid = (ge_frombytes_vartime(&point, h.h) == 0);

		const uint32_t t = static_cast<uint32_t>(seconds_since_epoch());
		{
			WriteLock lock(from_bytes_lock);

			from_bytes->emplace(h, FromBytesEntry(valid, point, t));

			// 2xPPLNS window = 4320 blocks, each block = 1 wallet (2 pubkeys), so ~8640 entries max
			// Double it and round it up to have some leeway
			limit_size(from_bytes, 20'000, 10'000);
		}

		if (valid) {
			memcpy(&p, &point, sizeof(p));
		}

		return valid;
	}

	// The comb table of a view public key, built and cached on first use. Empty if the key isn't a valid point.
	std::shared_ptr<const CombTable> get_comb_table(const hash& h)
	{
		{
			ReadLock lock(comb_tables_lock);

			auto it = comb_tables->find(h);

			if (it != comb_tables->end()) {
				return it->second.m_table;
			}
		}

		ViewKeyData data;

		if (!get_from_bytes(h, data.point)) {
			return {};
		}

		data.valid = true;
		data.has_point = true;

		if (!prepare_view_key(data, h)) {
			return {};
		}

		add_comb_table(h, data.table);

		return data.table;
	}

	// Everything needed to multiply a view public key by a scalar
	struct ViewKeyData
	{
		std::shared_ptr<const CombTable> table;
		ge_p3 point = {};

		bool valid = false;
		bool has_point = false;

		// Not in the cache yet
		bool new_point = false;
		bool new_table = false;
	};

	// Copies the cached tables for all keys, and the cached points for the keys that don't have a table yet, holding each read lock once
	void find_view_keys(const std::vector<hash>& keys, std::vector<ViewKeyData>& data)
	{
		const size_t N = keys.size();

		data.clear();
		data.resize(N);

		bool all_tables = true;
		{
			ReadLock lock(comb_tables_lock);

			for (size_t i = 0; i < N; ++i) {
				auto it = comb_tables->find(keys[i]);

				if (it != comb_tables->end()) {
					// Only valid points get a table
					data[i].table = it->second.m_table;
					data[i].valid = true;
				}
				else {
					all_tables = false;
				}
			}
		}

		if (all_tables) {
			return;
		}

		ReadLock lock(from_bytes_lock);

		for (size_t i = 0; i < N; ++i) {
			ViewKeyData& d = data[i];

			if (d.table) {
				continue;
			}

			auto it = from_bytes->find(keys[i]);

			if (it != from_bytes->end()) {
				const FromBytesEntry& entry = it->second;

				d.point = entry.m_point;
				d.valid = entry.m_valid;
				d.has_point = true;
			}
		}
	}

	// Makes sure a valid point has its table, building it if needed. Returns false for an invalid point. Can run in parallel, it only touches "data".
	static bool prepare_view_key(ViewKeyData& data, const hash& key)
	{
		if (data.table) {
			return true;
		}

		if (!data.has_point) {
			data.valid = (ge_frombytes_vartime(&data.point, key.h) == 0);
			data.has_point = true;
			data.new_point = true;
		}

		if (!data.valid) {
			return false;
		}

		std::shared_ptr<CombTable> table = std::make_shared<CombTable>();

		// Can't fail for a valid point: none of the Z coordinates can be zero
		if (ge_comb_precomp(table->m_data, &data.point) != 0) {
			data.valid = false;
			return false;
		}

		data.table = std::move(table);
		data.new_table = true;

		return true;
	}

	// result = scalar * key, pre-condition: prepare_view_key(data, key) returned true
	static void view_key_scalarmult(ge_p2& result, ViewKeyData& data, const hash& key, const hash& scalar)
	{
		if (scalar.h[HASH_SIZE - 1] <= 127) {
			ge_p3 point;
			ge_scalarmult_comb_vartime(&point, data.table->m_data, scalar.h);
			ge_p3_to_p2(&result, &point);
			return;
		}

		if (!data.has_point) {
			ge_frombytes_vartime(&data.point, key.h);
			data.has_point = true;
		}

		ge_dsmp Ai;
		ge_dsm_precomp(Ai, &data.point);

		signed char slide[256];
		ge_scalarmult_slide(slide, scalar.h);

		ge_scalarmult_vartime_precomp(&result, Ai, slide);
	}

	void add_comb_table(const hash& key, const std::shared_ptr<const CombTable>& table)
	{
		const uint32_t t = static_cast<uint32_t>(seconds_since_epoch());

		WriteLock lock(comb_tables_lock);

		comb_tables->emplace(key, CombTableEntry{ table, t });
		limit_size(comb_tables, 5'000, 2'500);
	}

	// Puts the new points and tables from find_view_keys()/prepare_view_key() into the cache
	void store_view_keys(const std::vector<hash>& keys, const std::vector<ViewKeyData>& data)
	{
		const size_t N = keys.size();

		bool new_points = false;
		bool new_tables = false;

		for (const ViewKeyData& d : data) {
			new_points |= d.new_point;
			new_tables |= d.new_table;
		}

		const uint32_t t = static_cast<uint32_t>(seconds_since_epoch());

		if (new_points) {
			WriteLock lock(from_bytes_lock);

			for (size_t i = 0; i < N; ++i) {
				if (data[i].new_point) {
					from_bytes->emplace(keys[i], FromBytesEntry(data[i].valid, data[i].point, t));
				}
			}

			limit_size(from_bytes, 20'000, 10'000);
		}

		if (new_tables) {
			WriteLock lock(comb_tables_lock);

			for (size_t i = 0; i < N; ++i) {
				if (data[i].new_table) {
					comb_tables->emplace(keys[i], CombTableEntry{ data[i].table, t });
				}
			}

			limit_size(comb_tables, 5'000, 2'500);
		}
	}

	bool check_public_key(const hash& h)
	{
		ge_p3 point = {};

		bool valid = false;
		bool point_cached = false;

		{
			ReadLock lock(from_bytes_lock);

			auto it = from_bytes->find(h);

			if (it != from_bytes->end()) {
				const FromBytesEntry& entry = it->second;

				if (!entry.m_valid) {
					return false;
				}

				if (entry.m_torsionChecked) {
					return entry.m_torsionFree;
				}

				valid = true;
				point_cached = true;
				point = entry.m_point;
			}
		}

		if (!point_cached) {
			valid = (ge_frombytes_vartime(&point, h.h) == 0);
		}

		const bool torsion_free = valid && is_torsion_free(point);

		const uint32_t t = static_cast<uint32_t>(seconds_since_epoch());
		{
			WriteLock lock(from_bytes_lock);

			auto it = from_bytes->emplace(h, FromBytesEntry(valid, point, t, true, torsion_free));
			FromBytesEntry& entry = it.first->second;

			if (valid && !entry.m_torsionChecked) {
				entry.m_torsionChecked = true;
				entry.m_torsionFree = torsion_free;
			}

			limit_size(from_bytes, 20'000, 10'000);
		}

		return torsion_free;
	}

	bool batch_eph_pubkeys(const std::vector<hash>& eph_priv_keys, std::vector<std::pair<hash, bool>>& eph_pub_keys)
	{
		eph_pub_keys.clear();

		const size_t N = eph_priv_keys.size();

		if (N == 0) {
			return true;
		}

		eph_pub_keys.assign(N, { hash(), true });

		struct M {
			fe Y;
			fe Z;
			fe D; // Z - Y
			fe P; // partial products of D (segmented, P_i = D_a*D_{a+1}*...*D_i for a <= i < b)
			fe Q; // inverses of D (Q_i = D_i^-1 for 0 <= i < N). Calculated in segments.
		};

		// N*200 bytes for the inversion scratchpad
		std::vector<M> scratchpad(N);

		std::atomic<uint32_t> counter = 0;
		std::atomic<bool> result = true;

		// Montgomery's trick to batch invert all Z - Y values with a single fe_invert call (parallel version)
		parallel_run([&](uint32_t thread_index, uint32_t total_thread_count) {
			// Always have at least 1 element per active thread
			const uint32_t thread_count = static_cast<uint32_t>(std::min<size_t>(total_thread_count, N));

			if (thread_index >= thread_count) {
				return;
			}

			// 0 <= thread_index < thread_count <= N at this point, so
			// 0 <= a < b <= N (non-empty segments with valid bounds) is guaranteed
			const size_t a = (N * thread_index) / thread_count;
			const size_t b = (N * (thread_index + 1)) / thread_count;

			uint32_t next_counter = thread_count;

			for (size_t i = a; i < b; ++i) {
				ge_p3 point;
				ge_scalarmult_wtable_vartime(&point, base_table, eph_priv_keys[i].h);

				memcpy(scratchpad[i].Y, point.Y, sizeof(fe));
				memcpy(scratchpad[i].Z, point.Z, sizeof(fe));
				fe_sub(scratchpad[i].D, point.Z, point.Y);

				hash denominator;
				fe_tobytes(denominator.h, scratchpad[i].D);

				// d_e * G is the point at infinity, so ConvertPointE is not defined for it.
				if (denominator.empty()) {
					eph_pub_keys[i].second = false;
					result = false;

					fe_0(scratchpad[i].Y);
					fe_1(scratchpad[i].Z);
					fe_1(scratchpad[i].D);
				}

				if (i == a) {
					memcpy(scratchpad[i].P, scratchpad[i].D, sizeof(fe));
				}
				else {
					fe_mul(scratchpad[i].P, scratchpad[i - 1].P, scratchpad[i].D);
				}
			}

			const bool last = sync_point(counter, next_counter);
			next_counter += thread_count;

			// Last thread at the sync point is likely the first one to continue execution,
			// so make it calculate each segment end's inverse using Montgomery's trick
			if (last) {
				// Work over the whole batch, but inverse only each segment's end
				// One fe_invert, thread_count*3 - 3 fe_mul calls

				// Calculate partial products of segment ends
				size_t k = N * (0 + 1) / thread_count - 1;
				memcpy(scratchpad[k].Q, scratchpad[k].P, sizeof(fe));

				for (uint32_t i = 1; i < thread_count; ++i) {
					const size_t next_k = N * (i + 1) / thread_count - 1;
					fe_mul(scratchpad[next_k].Q, scratchpad[k].Q, scratchpad[next_k].P);
					k = next_k;
				}

				// Invert the product of all segment ends. k == N - 1 here (because see how the loop above exits).
				fe t;
				fe_invert(t, scratchpad[k].Q);

				// Walk back to calculate inverses of segment ends
				for (uint32_t i = thread_count - 1; i > 0; --i) {
					const size_t prev_k = N * i / thread_count - 1;

					fe_mul(scratchpad[k].Q, t, scratchpad[prev_k].Q);
					fe_mul(t, t, scratchpad[k].P);

					k = prev_k;
				}

				// k is now the end index of the first segment (because see how the loop above exits).
				memcpy(scratchpad[k].Q, t, sizeof(fe));
			}

			sync_point(counter, next_counter);

			// Each segment has scratchpad[b - 1].Q = (D_a*D_{a+1}*...*D_{b-1})^-1 now
			fe t;
			memcpy(t, scratchpad[b - 1].Q, sizeof(fe));

			for (size_t i = b - 1; i > a; --i) {
				fe_mul(scratchpad[i].Q, t, scratchpad[i - 1].P);
				fe_mul(t, t, scratchpad[i].D);
			}

			memcpy(scratchpad[a].Q, t, sizeof(fe));

			// D_e = ConvertPointE(d_e * G) = (Z + Y) / (Z - Y)
			for (size_t i = a; i < b; ++i) {
				if (!eph_pub_keys[i].second) {
					continue;
				}

				fe numerator;

				fe_add(numerator, scratchpad[i].Z, scratchpad[i].Y);
				fe_mul(numerator, numerator, scratchpad[i].Q);
				fe_tobytes(eph_pub_keys[i].first.h, numerator);
			}
		}, true, parallel_run_threads(N, 2));

#ifdef P2POOL_DEBUGGING
		for (size_t i = 0; i < N; ++i) {
			hash eph_pub_key;
			const bool b = carrot::gen_eph_pubkey(eph_priv_keys[i], eph_pub_key);

			if (b != eph_pub_keys[i].second) {
				LOGERR(1, "batch_eph_pubkeys error: result mismatch at position " << i << '/' << N << ": expected " << b << ", got " << eph_pub_keys[i].second);
				PANIC_STOP();
			}

			if (b && (eph_pub_key != eph_pub_keys[i].first)) {
				LOGERR(1, "batch_eph_pubkeys error: wrong ephemeral public key at position " << i << '/' << N);
				PANIC_STOP();
			}
		}
#endif

		return result;
	}

	bool batch_sender_receiver_secrets(const std::vector<hash>& eph_priv_keys, const std::vector<hash>& view_public_keys, std::vector<std::pair<hash, bool>>& secrets)
	{
		secrets.clear();

		const size_t N = eph_priv_keys.size();

		if (view_public_keys.size() != N) {
			return false;
		}

		if (N == 0) {
			return true;
		}

		secrets.assign(N, { hash(), true });

		// Points and comb tables of the view public keys. The missing ones are built in the parallel loop below.
		std::vector<ViewKeyData> view_key_data;
		find_view_keys(view_public_keys, view_key_data);

		struct M {
			fe Y;
			fe Z;
			fe D; // Z - Y
			fe P; // partial products of D (segmented, P_i = D_a*D_{a+1}*...*D_i for a <= i < b)
			fe Q; // inverses of D (Q_i = D_i^-1 for 0 <= i < N). Calculated in segments.
		};

		// N*200 bytes for the inversion scratchpad
		std::vector<M> scratchpad(N);

		std::atomic<uint32_t> counter = 0;
		std::atomic<bool> result = true;

		// Montgomery's trick to batch invert all Z - Y values with a single fe_invert call (parallel version)
		parallel_run([&](uint32_t thread_index, uint32_t total_thread_count) {
			// Always have at least 1 element per active thread
			const uint32_t thread_count = static_cast<uint32_t>(std::min<size_t>(total_thread_count, N));

			if (thread_index >= thread_count) {
				return;
			}

			// 0 <= thread_index < thread_count <= N at this point, so
			// 0 <= a < b <= N (non-empty segments with valid bounds) is guaranteed
			const size_t a = (N * thread_index) / thread_count;
			const size_t b = (N * (thread_index + 1)) / thread_count;

			uint32_t next_counter = thread_count;

			for (size_t i = a; i < b; ++i) {
				ViewKeyData& data = view_key_data[i];

				bool ok = false;

				if (prepare_view_key(data, view_public_keys[i])) {
					ge_p2 point;
					view_key_scalarmult(point, data, view_public_keys[i], eph_priv_keys[i]);

					memcpy(scratchpad[i].Y, point.Y, sizeof(fe));
					memcpy(scratchpad[i].Z, point.Z, sizeof(fe));
					fe_sub(scratchpad[i].D, point.Z, point.Y);

					hash denominator;
					fe_tobytes(denominator.h, scratchpad[i].D);

					// d_e * K_v is the point at infinity, so ConvertPointE is not defined for it
					ok = !denominator.empty();
				}

				if (!ok) {
					secrets[i].second = false;
					result = false;

					fe_0(scratchpad[i].Y);
					fe_1(scratchpad[i].Z);
					fe_1(scratchpad[i].D);
				}

				if (i == a) {
					memcpy(scratchpad[i].P, scratchpad[i].D, sizeof(fe));
				}
				else {
					fe_mul(scratchpad[i].P, scratchpad[i - 1].P, scratchpad[i].D);
				}
			}

			const bool last = sync_point(counter, next_counter);
			next_counter += thread_count;

			// Last thread at the sync point is likely the first one to continue execution,
			// so make it calculate each segment end's inverse using Montgomery's trick
			if (last) {
				// Work over the whole batch, but inverse only each segment's end
				// One fe_invert, thread_count*3 - 3 fe_mul calls

				// Calculate partial products of segment ends
				size_t k = N * (0 + 1) / thread_count - 1;
				memcpy(scratchpad[k].Q, scratchpad[k].P, sizeof(fe));

				for (uint32_t i = 1; i < thread_count; ++i) {
					const size_t next_k = N * (i + 1) / thread_count - 1;
					fe_mul(scratchpad[next_k].Q, scratchpad[k].Q, scratchpad[next_k].P);
					k = next_k;
				}

				// Invert the product of all segment ends. k == N - 1 here (because see how the loop above exits).
				fe t;
				fe_invert(t, scratchpad[k].Q);

				// Walk back to calculate inverses of segment ends
				for (uint32_t i = thread_count - 1; i > 0; --i) {
					const size_t prev_k = N * i / thread_count - 1;

					fe_mul(scratchpad[k].Q, t, scratchpad[prev_k].Q);
					fe_mul(t, t, scratchpad[k].P);

					k = prev_k;
				}

				// k is now the end index of the first segment (because see how the loop above exits).
				memcpy(scratchpad[k].Q, t, sizeof(fe));
			}

			sync_point(counter, next_counter);

			// Each segment has scratchpad[b - 1].Q = (D_a*D_{a+1}*...*D_{b-1})^-1 now
			fe t;
			memcpy(t, scratchpad[b - 1].Q, sizeof(fe));

			for (size_t i = b - 1; i > a; --i) {
				fe_mul(scratchpad[i].Q, t, scratchpad[i - 1].P);
				fe_mul(t, t, scratchpad[i].D);
			}

			memcpy(scratchpad[a].Q, t, sizeof(fe));

			// s_sr = ConvertPointE(d_e * K_v) = (Z + Y) / (Z - Y)
			for (size_t i = a; i < b; ++i) {
				if (!secrets[i].second) {
					continue;
				}

				fe numerator;
				fe_add(numerator, scratchpad[i].Z, scratchpad[i].Y);
				fe_mul(numerator, numerator, scratchpad[i].Q);
				fe_tobytes(secrets[i].first.h, numerator);
			}
		}, true, parallel_run_threads(N, 1));

		store_view_keys(view_public_keys, view_key_data);

#ifdef P2POOL_DEBUGGING
		for (size_t i = 0; i < N; ++i) {
			// gen_sender_receiver_secret() has an a[31] <= 127 pre-condition, so it can't check the other scalars
			if (eph_priv_keys[i].h[HASH_SIZE - 1] > 127) {
				continue;
			}

			hash secret;
			const bool b = carrot::gen_sender_receiver_secret(eph_priv_keys[i], view_public_keys[i], secret);

			if (b != secrets[i].second) {
				LOGERR(1, "batch_sender_receiver_secrets error: result mismatch at position " << i << '/' << N << ": expected " << b << ", got " << secrets[i].second);
				PANIC_STOP();
			}

			if (b && (secret != secrets[i].first)) {
				LOGERR(1, "batch_sender_receiver_secrets error: wrong secret at position " << i << '/' << N);
				PANIC_STOP();
			}
		}
#endif

		return result;
	}

	// Calculates the entire amount-dependent part of a Carrot coinbase transaction in one go: K_o, the view tag
	// and the encrypted Janus anchor for every output.
	bool batch_coinbase_outputs(uint64_t height, const std::vector<carrot::coinbase_output_input>& in, std::vector<carrot::coinbase_tx_output>& out)
	{
		out.clear();

		const size_t N = in.size();

		if (N == 0) {
			return true;
		}

		out.assign(N, carrot::coinbase_tx_output{});

		std::atomic<bool> result = true;

		struct SpendKeyData {
			ge_p3 point = {};

			bool valid = false;
			bool has_point = false;
			bool cache_update = false;
		};

		std::vector<SpendKeyData> spend_key_data(N);

		// Copy all available cache data while holding the read lock only once, and write back below.
		{
			ReadLock lock(from_bytes_lock);

			for (size_t i = 0; i < N; ++i) {
				auto it = from_bytes->find(in[i].spend_public_key);

				if (it == from_bytes->end()) {
					continue;
				}

				const FromBytesEntry& entry = it->second;

				SpendKeyData& data = spend_key_data[i];

				data.point = entry.m_point;
				data.valid = entry.m_valid;
				data.has_point = true;
			}
		}

		struct M {
			ge_p2 p; // the original point p
			fe P;    // partial products of p.Z (segmented, P_i = Z_a*Z_{a+1}*...*Z_i for a <= i < b)
			fe Q;    // inverses of p.Z (Q_i = Z_i^-1 for 0 <= i < N). Calculated in segments.
		};

		// N*200 bytes for the scratchpad
		std::vector<M> scratchpad(N);

		std::atomic<uint32_t> counter = 0;
		std::atomic<bool> cache_update = false;

		// Montgomery's trick to batch invert all Z values with a single fe_invert call (parallel version)
		parallel_run([&](uint32_t thread_index, uint32_t total_thread_count) {
			// Always have at least 1 element per thread
			const uint32_t thread_count = static_cast<uint32_t>(std::min<size_t>(total_thread_count, N));

			if (thread_index >= thread_count) {
				return;
			}

			// 0 <= thread_index < thread_count <= N at this point, so
			// 0 <= a < b <= N (non-empty segments with valid bounds) is guaranteed
			const size_t a = (N * thread_index) / thread_count;
			const size_t b = (N * (thread_index + 1)) / thread_count;

			uint32_t next_counter = thread_count;

			for (size_t i = a; i < b; ++i) {
				const carrot::coinbase_output_input& t = in[i];

				SpendKeyData& data = spend_key_data[i];

				if (!data.has_point) {
					data.valid = (ge_frombytes_vartime(&data.point, t.spend_public_key.h) == 0);
					data.cache_update = true;
					cache_update.store(true, std::memory_order_release);
				}

				ge_p2 point5;

				if (!data.valid) {
					result = false;
					out[i].valid = false;

					// A zero Z would zero the product chain and take every other output in the batch down with it,
					// so invalid elements get a dummy point with Z = 1 and are skipped at the end.
					fe_1(point5.X);
					fe_1(point5.Y);
					fe_1(point5.Z);
				}
				else {
					out[i].valid = true;

					// k^o_g and k^o_t
					const hash sender_extension_g = carrot::gen_sender_extension_g(t.contextualized_sender_receiver_secret, t.amount, t.spend_public_key);
					const hash sender_extension_t = carrot::gen_sender_extension_t(t.contextualized_sender_receiver_secret, t.amount, t.spend_public_key);

					// K_o = K_s + k^o_g G + k^o_t T, kept projective until the final loop below
					ge_p3 point2;
					ge_cached point3;
					ge_p1p1 point4;

					ge_double_scalarmult_wtable_vartime(&point2, base_table, sender_extension_g.h, T_table, sender_extension_t.h);
					ge_p3_to_cached(&point3, &point2);
					ge_add(&point4, &data.point, &point3);
					ge_p1p1_to_p2(&point5, &point4);
				}

				memcpy(&scratchpad[i].p, &point5, sizeof(ge_p2));

				if (i == a) {
					memcpy(&scratchpad[i].P, point5.Z, sizeof(fe));
				}
				else {
					fe_mul(scratchpad[i].P, scratchpad[i - 1].P, point5.Z);
				}
			}

			const bool last = sync_point(counter, next_counter);
			next_counter += thread_count;

			// Last thread at the sync point is likely the first one to continue execution,
			// so make it calculate each segment end's inverse using Montgomery's trick
			if (last) {
				// Work over the whole range 0...N-1, but inverse only each segment's end
				// One fe_invert, thread_count*3 - 3 fe_mul calls

				// Calculate partial products of segment ends
				size_t k = N * (0 + 1) / thread_count - 1;
				memcpy(scratchpad[k].Q, scratchpad[k].P, sizeof(fe));

				for (uint32_t i = 1; i < thread_count; ++i) {
					const size_t next_k = N * (i + 1) / thread_count - 1;
					fe_mul(scratchpad[next_k].Q, scratchpad[k].Q, scratchpad[next_k].P);
					k = next_k;
				}

				// Invert the product of all segment ends. k == N - 1 here (because see how the loop above exits).
				fe t;
				fe_invert(t, scratchpad[k].Q);

				// Walk back to calculate inverses of segment ends
				for (uint32_t i = thread_count - 1; i > 0; --i) {
					const size_t prev_k = N * i / thread_count - 1;

					fe_mul(scratchpad[k].Q, t, scratchpad[prev_k].Q);
					fe_mul(t, t, scratchpad[k].P);

					k = prev_k;
				}

				// k is now the end index of the first segment (because see how the loop above exits).
				memcpy(scratchpad[k].Q, t, sizeof(fe));
			}

			sync_point(counter, next_counter);

			// Each segment has scratchpad[b - 1].Q = (Z_a*Z_{a+1}*...*Z_{b-1})^-1 now
			fe t;
			memcpy(t, scratchpad[b - 1].Q, sizeof(fe));

			for (size_t i = b - 1; i > a; --i) {
				fe_mul(scratchpad[i].Q, t, scratchpad[i - 1].P);
				fe_mul(t, t, scratchpad[i].p.Z);
			}

			memcpy(scratchpad[a].Q, t, sizeof(fe));

			// Last step - replicate ge_tobytes() code for each segment, then hash the encoded K_o twice
			for (size_t i = a; i < b; ++i) {
				if (!out[i].valid) {
					continue;
				}

				const fe& r = scratchpad[i].Q;

				fe x, y;
				fe_mul(x, scratchpad[i].p.X, r);
				fe_mul(y, scratchpad[i].p.Y, r);

				unsigned char* s = out[i].onetime_address.h;
				fe_tobytes(s, y);
				s[31] ^= fe_isnegative(x) << 7;

				out[i].vt = carrot::gen_view_tag(in[i].sender_receiver_secret, height, out[i].onetime_address);
				out[i].anchor_enc = carrot::gen_encrypted_janus_anchor(in[i].contextualized_sender_receiver_secret, in[i].anchor, out[i].onetime_address);
			}
		}, true, parallel_run_threads(N, 2));

		if (cache_update.load(std::memory_order_acquire)) {
			const uint32_t t = static_cast<uint32_t>(seconds_since_epoch());

			WriteLock lock(from_bytes_lock);

			for (size_t i = 0; i < N; ++i) {
				const SpendKeyData& data = spend_key_data[i];

				if (data.cache_update) {
					from_bytes->emplace(in[i].spend_public_key, FromBytesEntry(data.valid, data.point, t));
				}
			}

			limit_size(from_bytes, 20'000, 10'000);
		}

#ifdef P2POOL_DEBUGGING
		for (size_t i = 0; i < N; ++i) {
			const carrot::coinbase_output_input& t = in[i];

			const hash sender_extension_g = carrot::gen_sender_extension_g(t.contextualized_sender_receiver_secret, t.amount, t.spend_public_key);
			const hash sender_extension_t = carrot::gen_sender_extension_t(t.contextualized_sender_receiver_secret, t.amount, t.spend_public_key);

			hash onetime_address;
			const bool b = carrot::gen_onetime_address(t.spend_public_key, sender_extension_g, sender_extension_t, onetime_address);

			if (b != out[i].valid) {
				LOGERR(1, "batch_coinbase_outputs error: result mismatch at position " << i << '/' << N << ": expected " << b << ", got " << out[i].valid);
				PANIC_STOP();
			}

			if (!b) {
				continue;
			}

			if (onetime_address != out[i].onetime_address) {
				LOGERR(1, "batch_coinbase_outputs error: wrong one-time address at position " << i << '/' << N);
				PANIC_STOP();
			}

			const carrot::view_tag vt = carrot::gen_view_tag(t.sender_receiver_secret, height, onetime_address);
			const carrot::janus_anchor anchor_enc = carrot::gen_encrypted_janus_anchor(t.contextualized_sender_receiver_secret, t.anchor, onetime_address);

			if (memcmp(&vt, &out[i].vt, sizeof(carrot::view_tag)) != 0) {
				LOGERR(1, "batch_coinbase_outputs error: wrong view tag at position " << i << '/' << N);
				PANIC_STOP();
			}

			if (memcmp(&anchor_enc, &out[i].anchor_enc, sizeof(carrot::janus_anchor)) != 0) {
				LOGERR(1, "batch_coinbase_outputs error: wrong encrypted Janus anchor at position " << i << '/' << N);
				PANIC_STOP();
			}
		}
#endif

		return result;
	}

	// anchor_norm, D_e, s_sr and s^ctx_sr for every wallet, cached per (txkey_sec, wallet, height, retry_counter).
	// With "amounts", also the cached output paying amounts[i] to wallets[i]. Outputs that aren't in the cache
	// are left invalid and complete_coinbase_outputs() will fill them in.
	bool batch_coinbase_secrets(const hash& txkey_sec, uint8_t retry_counter, uint64_t height, const std::vector<const Wallet*>& wallets, const std::vector<uint64_t>* amounts, std::vector<carrot::coinbase_secrets>& secrets, std::vector<carrot::coinbase_tx_output>* outputs)
	{
		secrets.clear();

		if (outputs) {
			outputs->clear();
		}

#ifdef P2POOL_UNIT_TESTS
		m_lastCoinbaseSecretsBatchSize.store(0);
#endif

		const size_t N = wallets.size();

		if ((amounts != nullptr) != (outputs != nullptr)) {
			return false;
		}

		if (amounts && (amounts->size() != N)) {
			return false;
		}

		if (N == 0) {
			return true;
		}

		secrets.resize(N);

		if (outputs) {
			outputs->resize(N);
		}

		bool result = true;

		// First read all cached entries and save the indices we will need to fill in.
		std::vector<size_t> batch;
		{
			ReadLock lock(coinbase_secrets_lock);

			for (size_t i = 0; i < N; ++i) {
				const Wallet* w = wallets[i];

				if (!w) {
					result = false;
					continue;
				}

				auto it = coinbase_secrets->find(coinbase_secrets_index(txkey_sec, retry_counter, height, *w));

				if (it == coinbase_secrets->end()) {
					batch.reserve(N);
					batch.emplace_back(i);
					continue;
				}

				const CoinbaseSecretsEntry& entry = it->second;
				secrets[i] = entry.m_secrets;

				if (!outputs) {
					continue;
				}

				const uint64_t amount = (*amounts)[i];

				for (const CoinbaseOutputEntry& o : entry.m_outputs) {
					if (o.m_amount == amount) {
						carrot::coinbase_tx_output& t = (*outputs)[i];

						t.anchor_enc = o.m_anchorEnc;
						t.onetime_address = o.m_onetimeAddress;
						t.vt = o.m_viewTag;
						t.valid = true;
						break;
					}
				}
			}
		}

#ifdef P2POOL_UNIT_TESTS
		m_lastCoinbaseSecretsBatchSize.store(batch.size());
#endif

		if (batch.empty()) {
			return result;
		}

		const size_t batch_size = batch.size();

		std::vector<const Wallet*> batch_wallets;
		std::vector<hash> view_public_keys;

		batch_wallets.reserve(batch_size);
		view_public_keys.reserve(batch_size);

		for (const size_t i : batch) {
			batch_wallets.emplace_back(wallets[i]);
			view_public_keys.emplace_back(wallets[i]->view_public_key());
		}

		std::vector<carrot::janus_anchor> anchors;
		std::vector<hash> eph_priv_keys;
		std::vector<std::pair<hash, bool>> eph_pub_keys;
		std::vector<std::pair<hash, bool>> sender_receiver_secrets;
		std::vector<std::pair<hash, bool>> contextualized_secrets;

		// A failed element leaves a zero d_e, which batch_eph_pubkeys and batch_sender_receiver_secrets reject on their own.
		// s^ctx_sr is valid only if both D_e and s_sr are, so it's the only result that has to be checked below.
		carrot::batch_eph_privkeys(txkey_sec, retry_counter, height, batch_wallets, anchors, eph_priv_keys);
		batch_eph_pubkeys(eph_priv_keys, eph_pub_keys);
		batch_sender_receiver_secrets(eph_priv_keys, view_public_keys, sender_receiver_secrets);
		carrot::batch_contextualized_sender_receiver_secrets(sender_receiver_secrets, eph_pub_keys, height, contextualized_secrets);

		for (size_t k = 0; k < batch_size; ++k) {
			if (!contextualized_secrets[k].second) {
				result = false;
				continue;
			}

			carrot::coinbase_secrets& s = secrets[batch[k]];

			s.anchor = anchors[k];
			s.eph_pub_key = eph_pub_keys[k].first;
			s.sender_receiver_secret = sender_receiver_secrets[k].first;
			s.contextualized_sender_receiver_secret = contextualized_secrets[k].first;
		}

		// When debugging, don't pollute the cache
#if !defined(P2POOL_DEBUGGING) || defined(P2POOL_UNIT_TESTS)
		{
			const uint32_t t = static_cast<uint32_t>(seconds_since_epoch());

			WriteLock lock(coinbase_secrets_lock);

			for (const size_t i : batch) {
				if (secrets[i].valid()) {
					coinbase_secrets->emplace(coinbase_secrets_index(txkey_sec, retry_counter, height, *wallets[i]), CoinbaseSecretsEntry{ secrets[i], {}, t });
				}
			}

			limit_size(coinbase_secrets, 500'000, 250'000);
		}
#endif

		return result;
	}

	// Calculates outputs[i] for every output batch_coinbase_secrets() didn't find in the cache, and caches them with their wallet's secrets.
	// Also sets eph_pub_key and amount in every output.
	bool complete_coinbase_outputs(const hash& txkey_sec, uint8_t retry_counter, uint64_t height, const std::vector<const Wallet*>& wallets, const std::vector<uint64_t>& amounts, const std::vector<carrot::coinbase_secrets>& secrets, std::vector<carrot::coinbase_tx_output>& outputs)
	{
#ifdef P2POOL_UNIT_TESTS
		m_lastCoinbaseOutputBatchSize.store(0);
#endif

		const size_t N = wallets.size();

		if ((amounts.size() != N) || (secrets.size() != N) || (outputs.size() != N)) {
			return false;
		}

		bool result = true;

		std::vector<size_t> batch;
		std::vector<carrot::coinbase_output_input> in;

		for (size_t i = 0; i < N; ++i) {
			carrot::coinbase_tx_output& t = outputs[i];

			t.eph_pub_key = secrets[i].eph_pub_key;
			t.amount = amounts[i];

			if (t.valid) {
				continue;
			}

			if (!wallets[i] || !secrets[i].valid()) {
				result = false;
				continue;
			}

			batch.reserve(N);
			batch.emplace_back(i);

			in.reserve(N);
			in.emplace_back(carrot::coinbase_output_input{
				wallets[i]->spend_public_key(),
				secrets[i].sender_receiver_secret,
				secrets[i].contextualized_sender_receiver_secret,
				secrets[i].anchor,
				amounts[i]
			});
		}

#ifdef P2POOL_UNIT_TESTS
		m_lastCoinbaseOutputBatchSize.store(batch.size());
#endif

		if (batch.empty()) {
			return result;
		}

		std::vector<carrot::coinbase_tx_output> out;

		if (!batch_coinbase_outputs(height, in, out)) {
			result = false;
		}

		for (size_t k = 0, n = batch.size(); k < n; ++k) {
			carrot::coinbase_tx_output& t = outputs[batch[k]];

			t.anchor_enc = out[k].anchor_enc;
			t.onetime_address = out[k].onetime_address;
			t.vt = out[k].vt;
			t.valid = out[k].valid;
		}

		// Don't pollute the cache when debugging
#if !defined(P2POOL_DEBUGGING) || defined(P2POOL_UNIT_TESTS)
		{
			WriteLock lock(coinbase_secrets_lock);

			for (size_t k = 0, n = batch.size(); k < n; ++k) {
				if (!out[k].valid) {
					continue;
				}

				const size_t i = batch[k];

				auto it = coinbase_secrets->find(coinbase_secrets_index(txkey_sec, retry_counter, height, *wallets[i]));

				// A cache cleanup could have removed the entry after batch_coinbase_secrets() returned
				if (it == coinbase_secrets->end()) {
					continue;
				}

				CoinbaseSecretsEntry& entry = it->second;

				// Only keep outputs that were calculated from this entry's own secrets
				if (!same_secrets(entry.m_secrets, secrets[i])) {
					continue;
				}

				std::vector<CoinbaseOutputEntry>& v = entry.m_outputs;

				const uint64_t amount = amounts[i];

				// Repeated amounts in the same batch are cached once
				if (std::any_of(v.begin(), v.end(), [amount](const CoinbaseOutputEntry& o) { return o.m_amount == amount; })) {
					continue;
				}

				// The oldest amount makes room for the new one. Shifting at most 32 entries costs ~20 ns, nothing compared to calculating the output.
				if (v.size() >= MAX_COINBASE_OUTPUTS_PER_WALLET) {
					v.erase(v.begin());
				}

				v.emplace_back(CoinbaseOutputEntry{ amount, out[k].onetime_address, out[k].anchor_enc, out[k].vt });
			}
		}
#else
		(void)txkey_sec;
		(void)retry_counter;
#endif

		return result;
	}

#ifdef P2POOL_UNIT_TESTS
	size_t get_last_coinbase_secrets_batch_size() const { return m_lastCoinbaseSecretsBatchSize.load(); }
	size_t get_last_coinbase_output_batch_size() const { return m_lastCoinbaseOutputBatchSize.load(); }

	uint32_t get_from_bytes_cache_state(const hash& public_key)
	{
		uint32_t state = 0;
		{
			ReadLock lock(from_bytes_lock);

			auto it = from_bytes->find(public_key);
			if (it != from_bytes->end()) {
				const FromBytesEntry& entry = it->second;

				state = 1U |
					(entry.m_valid ? 2U : 0U) |
					(entry.m_torsionChecked ? 8U : 0U) |
					(entry.m_torsionFree ? 16U : 0U);
			}
		}
		{
			ReadLock lock(comb_tables_lock);

			if (comb_tables->find(public_key) != comb_tables->end()) {
				state |= 4U;
			}
		}
		return state;
	}
#endif

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
			ViewKeyData data;

			data.table = get_comb_table(key1);

			if (!data.table) {
				return false;
			}

			data.valid = true;

			ge_p2 point2;
			ge_p1p1 point3;

			view_key_scalarmult(point2, data, key1, key2);
			ge_mul8(&point3, &point2);
			ge_p1p1_to_p2(&point2, &point3);
			ge_tobytes(reinterpret_cast<uint8_t*>(&derivation), &point2);
		}

		derive_view_tag(derivation, output_index, view_tag);

		const uint32_t t = static_cast<uint32_t>(seconds_since_epoch());
		{
			WriteLock lock(derivations_lock);

			auto entry = derivations->emplace(index, DerivationEntry(derivation, t)).first;
			entry->second.add_view_tag(static_cast<uint32_t>(output_index << 8) | view_tag);
			limit_size(derivations, 1'000'000, 500'000);
		}

		return true;
	}

	// "in" vector  = pairs of (view pub key, output index)
	// "out" vector = pairs of (derivation, view tag).
	//
	// Negative view tag in out[i] means out[i] is invalid (get_derivation would've returned false for in[i])
	//
	// Returns true if all derivations were computed successfully
	bool batch_derivations(const std::vector<std::pair<hash, size_t>>& in, const hash& txkey_sec, std::vector<std::pair<hash, int32_t>>& out)
	{
		std::atomic<bool> result = true;

		out.clear();
		out.reserve(in.size());

		std::array<uint8_t, HASH_SIZE * 2> index;

		// First read all already cached data and save the indices we will need to fill in
		std::vector<size_t> derivation_batch;
		std::vector<size_t> view_tag_batch;
		{
			ReadLock lock(derivations_lock);

			for (const std::pair<hash, size_t>& k : in) {
				memcpy(index.data(), k.first.h, HASH_SIZE);
				memcpy(index.data() + HASH_SIZE, txkey_sec.h, HASH_SIZE);

				auto it = derivations->find(index);

				if (it == derivations->end()) {
					derivation_batch.reserve(in.size());
					derivation_batch.emplace_back(out.size());

					view_tag_batch.reserve(in.size());
					view_tag_batch.emplace_back(out.size());

					out.emplace_back(hash(), 0);
				}
				else {
					const DerivationEntry& entry = it->second;
					uint8_t view_tag;

					if (entry.find_view_tag(k.second, view_tag)) {
						out.emplace_back(entry.m_derivation, view_tag);
					}
					else {
						view_tag_batch.reserve(in.size());
						view_tag_batch.emplace_back(out.size());
						out.emplace_back(entry.m_derivation, 0);
					}
				}
			}
		}

		// Then fill in the gaps in parallel
		if (!derivation_batch.empty()) {
			const size_t N = derivation_batch.size();

			struct M {
				ge_p2 p; // the original point p
				fe P;    // partial products of p.Z (segmented, P_i = Z_a*Z_{a+1}*...*Z_i for a <= i < b)
				fe Q;    // inverses of p.Z (Q_i = Z_i^-1 for 0 <= i < N). Calculated in segments.
			};

			// N*200 bytes for the scratchpad
			std::vector<M> scratchpad(N);

			std::atomic<uint32_t> counter = 0;

			// Points and comb tables of the view public keys. The missing ones are built in the parallel loop below.
			std::vector<hash> view_public_keys;
			view_public_keys.reserve(N);

			for (const size_t j : derivation_batch) {
				view_public_keys.emplace_back(in[j].first);
			}

			std::vector<ViewKeyData> view_key_data;
			find_view_keys(view_public_keys, view_key_data);

			// Montgomery's trick to batch invert all Z values with a single fe_invert call (parallel version)
			parallel_run([&](uint32_t thread_index, uint32_t total_thread_count) {
				// Always have at least 1 element per thread
				const uint32_t thread_count = static_cast<uint32_t>(std::min<size_t>(total_thread_count, N));

				if (thread_index >= thread_count) {
					return;
				}

				// 0 <= thread_index < thread_count <= N at this point, so
				// 0 <= a < b <= N (non-empty segments with valid bounds) is guaranteed
				const size_t a = (N * thread_index) / thread_count;
				const size_t b = (N * (thread_index + 1)) / thread_count;

				uint32_t next_counter = thread_count;

				for (size_t i = a; i < b; ++i) {
					ge_p2 point2;
					ge_p1p1 point3;

					if (!prepare_view_key(view_key_data[i], view_public_keys[i])) {
						out[derivation_batch[i]].second = -1;
						result = false;

						fe_1(point2.X);
						fe_1(point2.Y);
						fe_1(point2.Z);
					}
					else {
						view_key_scalarmult(point2, view_key_data[i], view_public_keys[i], txkey_sec);
						ge_mul8(&point3, &point2);
						ge_p1p1_to_p2(&point2, &point3);
					}

					memcpy(&scratchpad[i].p, &point2, sizeof(ge_p2));

					if (i == a) {
						memcpy(&scratchpad[i].P, point2.Z, sizeof(fe));
					}
					else {
						fe_mul(scratchpad[i].P, scratchpad[i - 1].P, point2.Z);
					}
				}

				const bool last = sync_point(counter, next_counter);
				next_counter += thread_count;

				// Last thread at the sync point is likely the first one to continue execution,
				// so make it calculate each segment end's inverse using Montgomery's trick
				if (last) {
					// Work over the whole range 0...N-1, but inverse only each segment's end
					// One fe_invert, thread_count*3 - 3 fe_mul calls

					// Calculate partial products of segment ends
					size_t k = N * (0 + 1) / thread_count - 1;
					memcpy(scratchpad[k].Q, scratchpad[k].P, sizeof(fe));

					for (uint32_t i = 1; i < thread_count; ++i) {
						const size_t next_k = N * (i + 1) / thread_count - 1;
						fe_mul(scratchpad[next_k].Q, scratchpad[k].Q, scratchpad[next_k].P);
						k = next_k;
					}

					// Invert the product of all segment ends. k == N - 1 here (because see how the loop above exits).
					fe t;
					fe_invert(t, scratchpad[k].Q);

					// Walk back to calculate inverses of segment ends
					for (uint32_t i = thread_count - 1; i > 0; --i) {
						const size_t prev_k = N * i / thread_count - 1;

						fe_mul(scratchpad[k].Q, t, scratchpad[prev_k].Q);
						fe_mul(t, t, scratchpad[k].P);

						k = prev_k;
					}

					// k is now the end index of the first segment (because see how the loop above exits).
					memcpy(scratchpad[k].Q, t, sizeof(fe));
				}

				sync_point(counter, next_counter);

				// Each segment has scratchpad[b - 1].Q = (Z_a*Z_{a+1}*...*Z_{b-1})^-1 now
				fe t;
				memcpy(t, scratchpad[b - 1].Q, sizeof(fe));

				for (size_t i = b - 1; i > a; --i) {
					fe_mul(scratchpad[i].Q, t, scratchpad[i - 1].P);
					fe_mul(t, t, scratchpad[i].p.Z);
				}

				memcpy(scratchpad[a].Q, t, sizeof(fe));

				// Last step - replicate ge_tobytes() code for each segment
				for (size_t i = a; i < b; ++i) {
					const fe& r = scratchpad[i].Q;

					fe x, y;
					fe_mul(x, scratchpad[i].p.X, r);
					fe_mul(y, scratchpad[i].p.Y, r);

					unsigned char* s = out[derivation_batch[i]].first.h;
					fe_tobytes(s, y);
					s[31] ^= fe_isnegative(x) << 7;
				}
			}, true, parallel_run_threads(N, 1));

			store_view_keys(view_public_keys, view_key_data);
		}

		if (!view_tag_batch.empty()) {
			const size_t N = view_tag_batch.size();

			parallel_run([N, &in, &out, &view_tag_batch](uint32_t thread_index, uint32_t total_thread_count) {
				const size_t a = (N * thread_index) / total_thread_count;
				const size_t b = (N * (thread_index + 1)) / total_thread_count;

				for (size_t i = a; i < b; ++i) {
					std::pair<hash, int32_t>& t = out[view_tag_batch[i]];

					// Skip entries with invalid derivations
					if (t.second < 0) {
						continue;
					}

					uint8_t view_tag;
					derive_view_tag(t.first, in[view_tag_batch[i]].second, view_tag);
					t.second = view_tag;
				}
			}, true, parallel_run_threads(N, 16));
		}

		// Finally fill in the cache with all new values

		// When debugging, don't pollute the cache with the values calculated here.
		// Instead, compare them with get_derivation() output.
		// get_derivation will fill the cache the normal way.
#ifndef P2POOL_DEBUGGING
		const uint32_t t = static_cast<uint32_t>(seconds_since_epoch());

		if (!derivation_batch.empty() || !view_tag_batch.empty()) {
			WriteLock lock(derivations_lock);

			for (size_t i = 0, n = derivation_batch.size(); i < n; ++i) {
				const size_t j = derivation_batch[i];

				// Skip entries with invalid derivations
				if (out[j].second < 0) {
					continue;
				}

				memcpy(index.data(), in[j].first.h, HASH_SIZE);
				memcpy(index.data() + HASH_SIZE, txkey_sec.h, HASH_SIZE);

				derivations->emplace(index, DerivationEntry(out[j].first, t));
			}

			if (!derivation_batch.empty()) {
				limit_size(derivations, 1'000'000, 500'000);
			}

			for (size_t i = 0, n = view_tag_batch.size(); i < n; ++i) {
				const size_t j = view_tag_batch[i];

				// Skip entries with invalid derivations
				if (out[j].second < 0) {
					continue;
				}

				memcpy(index.data(), in[j].first.h, HASH_SIZE);
				memcpy(index.data() + HASH_SIZE, txkey_sec.h, HASH_SIZE);

				auto it = derivations->find(index);
				if (it != derivations->end()) {
					it->second.add_view_tag(static_cast<uint32_t>(in[j].second << 8) | static_cast<uint8_t>(out[j].second));
				}
			}
		}
#else // P2POOL_DEBUGGING
		if (out.size() != in.size()) {
			LOGERR(1, "batch_derivations error: size mismatch: expected " << in.size() << ", produced " << out.size() << " elements");
			PANIC_STOP();
		}
		else {
			for (size_t i = 0, n = in.size(); i < n; ++i) {
				hash derivation;
				uint8_t view_tag;

				if (get_derivation(in[i].first, txkey_sec, in[i].second, derivation, view_tag)) {
					if (derivation != out[i].first) {
						LOGERR(1, "batch_derivations error: wrong derivation at position " << i << '/' << n);
						PANIC_STOP();
					}

					if (view_tag != out[i].second) {
						LOGERR(1, "batch_derivations error: wrong view tag at position " << i << '/' << n << " (should be " << static_cast<int32_t>(view_tag) << " instead of " << out[i].second << ')');
						PANIC_STOP();
					}
				}
				else {
					if (out[i].second != -1) {
						LOGERR(1, "batch_derivations error: wrong view tag at position " << i << '/' << n << " (should be -1 instead of " << out[i].second << ')');
						PANIC_STOP();
					}
				}
			}
		}
#endif // P2POOL_DEBUGGING

		return result;
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

		if (!get_from_bytes(base, point1)) {
			return false;
		}

		derivation_to_scalar(derivation, output_index, scalar);
		ge_scalarmult_wtable_vartime(&point2, base_table, scalar);
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

	// "in" vector  = tuples of (derivation, output index, public spend key)
	// "out" vector = pairs of (derived ephemeral public key, valid)
	//
	// out[i].second == false means out[i] is invalid (get_public_key would've returned false for in[i])
	//
	// Returns true if all ephemeral public keys were computed successfully
	bool batch_public_keys(const std::vector<batch_public_key_input>& in, std::vector<std::pair<hash, bool>>& out)
	{
		std::atomic<bool> result = true;

		out.clear();
		out.reserve(in.size());

		std::array<uint8_t, HASH_SIZE * 2 + sizeof(size_t)> index;

		// First read all already cached data and save the indices we will need to fill in
		std::vector<size_t> batch;
		{
			ReadLock lock(public_keys_lock);

			for (const batch_public_key_input& k : in) {
				memcpy(index.data(), k.derivation.h, HASH_SIZE);
				memcpy(index.data() + HASH_SIZE, k.base.h, HASH_SIZE);
				memcpy(index.data() + HASH_SIZE * 2, &k.output_index, sizeof(size_t));

				auto it = public_keys->find(index);

				if (it == public_keys->end()) {
					batch.reserve(in.size());
					batch.emplace_back(out.size());

					out.emplace_back(hash(), false);
				}
				else {
					out.emplace_back(it->second.m_key, true);
				}
			}
		}

		if (!batch.empty())
		{
			const size_t N = batch.size();

			struct BaseKeyData {
				ge_p3 point = {};

				bool valid = false;
				bool has_point = false;
				bool cache_update = false;
			};

			std::vector<BaseKeyData> base_key_data(N);

			// Copy all available cache data while holding the read lock only once, and write back below.
			{
				ReadLock lock(from_bytes_lock);

				for (size_t i = 0; i < N; ++i) {
					auto it = from_bytes->find(in[batch[i]].base);

					if (it == from_bytes->end()) {
						continue;
					}

					const FromBytesEntry& entry = it->second;

					BaseKeyData& data = base_key_data[i];

					data.point = entry.m_point;
					data.valid = entry.m_valid;
					data.has_point = true;
				}
			}

			struct M {
				ge_p2 p; // the original point p
				fe P;    // partial products of p.Z (segmented, P_i = Z_a*Z_{a+1}*...*Z_i for a <= i < b)
				fe Q;    // inverses of p.Z (Q_i = Z_i^-1 for 0 <= i < N). Calculated in segments.
			};

			// N*200 bytes for the scratchpad
			std::vector<M> scratchpad(N);

			std::atomic<uint32_t> counter = 0;
			std::atomic<bool> cache_update = false;

			// Montgomery's trick to batch invert all Z values with a single fe_invert call (parallel version)
			parallel_run([&](uint32_t thread_index, uint32_t total_thread_count) {
				// Always have at least 1 element per thread
				const uint32_t thread_count = static_cast<uint32_t>(std::min<size_t>(total_thread_count, N));

				if (thread_index >= thread_count) {
					return;
				}

				// 0 <= thread_index < thread_count <= N at this point, so
				// 0 <= a < b <= N (non-empty segments with valid bounds) is guaranteed
				const size_t a = (N * thread_index) / thread_count;
				const size_t b = (N * (thread_index + 1)) / thread_count;

				uint32_t next_counter = thread_count;

				for (size_t i = a; i < b; ++i) {
					const batch_public_key_input& t = in[batch[i]];

					BaseKeyData& data = base_key_data[i];

					if (!data.has_point) {
						data.valid = (ge_frombytes_vartime(&data.point, t.base.h) == 0);
						data.cache_update = true;
						cache_update.store(true, std::memory_order_release);
					}

					ge_p2 point5;

					if (!data.valid) {
						result = false;
						out[batch[i]].second = false;

						fe_1(point5.X);
						fe_1(point5.Y);
						fe_1(point5.Z);
					}
					else {
						out[batch[i]].second = true;

						uint8_t scalar[HASH_SIZE];
						ge_p3 point2;
						ge_cached point3;
						ge_p1p1 point4;

						derivation_to_scalar(t.derivation, t.output_index, scalar);
						ge_scalarmult_wtable_vartime(&point2, base_table, scalar);
						ge_p3_to_cached(&point3, &point2);
						ge_add(&point4, &data.point, &point3);
						ge_p1p1_to_p2(&point5, &point4);
					}

					memcpy(&scratchpad[i].p, &point5, sizeof(ge_p2));

					if (i == a) {
						memcpy(&scratchpad[i].P, point5.Z, sizeof(fe));
					}
					else {
						fe_mul(scratchpad[i].P, scratchpad[i - 1].P, point5.Z);
					}
				}

				const bool last = sync_point(counter, next_counter);
				next_counter += thread_count;

				// Last thread at the sync point is likely the first one to continue execution,
				// so make it calculate each segment end's inverse using Montgomery's trick
				if (last) {
					// Work over the whole range 0...N-1, but inverse only each segment's end
					// One fe_invert, thread_count*3 - 3 fe_mul calls

					// Calculate partial products of segment ends
					size_t k = N * (0 + 1) / thread_count - 1;
					memcpy(scratchpad[k].Q, scratchpad[k].P, sizeof(fe));

					for (uint32_t i = 1; i < thread_count; ++i) {
						const size_t next_k = N * (i + 1) / thread_count - 1;
						fe_mul(scratchpad[next_k].Q, scratchpad[k].Q, scratchpad[next_k].P);
						k = next_k;
					}

					// Invert the product of all segment ends. k == N - 1 here (because see how the loop above exits).
					fe t;
					fe_invert(t, scratchpad[k].Q);

					// Walk back to calculate inverses of segment ends
					for (uint32_t i = thread_count - 1; i > 0; --i) {
						const size_t prev_k = N * i / thread_count - 1;

						fe_mul(scratchpad[k].Q, t, scratchpad[prev_k].Q);
						fe_mul(t, t, scratchpad[k].P);

						k = prev_k;
					}

					// k is now the end index of the first segment (because see how the loop above exits).
					memcpy(scratchpad[k].Q, t, sizeof(fe));
				}

				sync_point(counter, next_counter);

				// Each segment has scratchpad[b - 1].Q = (Z_a*Z_{a+1}*...*Z_{b-1})^-1 now
				fe t;
				memcpy(t, scratchpad[b - 1].Q, sizeof(fe));

				for (size_t i = b - 1; i > a; --i) {
					fe_mul(scratchpad[i].Q, t, scratchpad[i - 1].P);
					fe_mul(t, t, scratchpad[i].p.Z);
				}

				memcpy(scratchpad[a].Q, t, sizeof(fe));

				// Last step - replicate ge_tobytes() code for each segment
				for (size_t i = a; i < b; ++i) {
					const fe& r = scratchpad[i].Q;

					fe x, y;
					fe_mul(x, scratchpad[i].p.X, r);
					fe_mul(y, scratchpad[i].p.Y, r);

					unsigned char* s = out[batch[i]].first.h;
					fe_tobytes(s, y);
					s[31] ^= fe_isnegative(x) << 7;
				}
			}, true, parallel_run_threads(N, 2));

			if (cache_update.load(std::memory_order_acquire)) {
				const uint32_t t = static_cast<uint32_t>(seconds_since_epoch());

				WriteLock lock(from_bytes_lock);

				for (size_t i = 0; i < N; ++i) {
					const BaseKeyData& data = base_key_data[i];

					if (data.cache_update) {
						from_bytes->emplace(in[batch[i]].base, FromBytesEntry(data.valid, data.point, t));
					}
				}

				limit_size(from_bytes, 20'000, 10'000);
			}

			// Finally fill in the cache with all new values

			// When debugging, don't pollute the cache with the values calculated here.
			// Instead, compare them with get_derivation() output.
			// get_derivation will fill the cache the normal way.
#ifndef P2POOL_DEBUGGING
			const uint32_t t = static_cast<uint32_t>(seconds_since_epoch());
			{
				WriteLock lock(public_keys_lock);

				for (size_t i = 0; i < N; ++i) {
					if (out[batch[i]].second) {
						const batch_public_key_input& k = in[batch[i]];

						memcpy(index.data(), k.derivation.h, HASH_SIZE);
						memcpy(index.data() + HASH_SIZE, k.base.h, HASH_SIZE);
						memcpy(index.data() + HASH_SIZE * 2, &k.output_index, sizeof(size_t));

						public_keys->emplace(index, PublicKeyEntry{ static_cast<indexed_hash>(out[batch[i]].first), t });
					}
				}

				limit_size(public_keys, 1'000'000, 500'000);
			}
#else // P2POOL_DEBUGGING
			for (size_t i = 0; i < N; ++i) {
				const batch_public_key_input& k = in[batch[i]];

				hash derived_key;
				const bool b = get_public_key(k.derivation, k.output_index, k.base, derived_key);

				if (b != out[batch[i]].second) {
					LOGERR(1, "batch_public_keys error: result mismatch: expected " << b << ", got " << out[batch[i]].second);
					PANIC_STOP();
				}

				if (b && (derived_key != out[batch[i]].first)) {
					LOGERR(1, "batch_public_keys error: wrong derived key at position " << i << '/' << N);
					PANIC_STOP();
				}
			}
#endif // P2POOL_DEBUGGING
		}

		return result;
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
	static void clean_old(T* table, uint32_t timestamp, size_t excess_at_timestamp = 0) {
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
	}

	// Must be called with an appropriate lock held
	// If the table exceeded max_size, deletes oldest entries to shrink the table to <= max_new_size entries
	template<typename T>
	static void limit_size(T* table, size_t max_size, size_t max_new_size)
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
				WriteLock lock(coinbase_secrets_lock);
				clean_old(coinbase_secrets, t);
			}
			{
				WriteLock lock(public_keys_lock);
				clean_old(public_keys, t);
			}
			{
				WriteLock lock(tx_keys_lock);
				clean_old(tx_keys, t);
			}
			// from_bytes and comb_tables are not cleaned of old entries because they have data for miner wallets which change rarely
			// limit_size is what limits them instead
			return;
		}

		{
			WriteLock lock(derivations_lock);
			delete derivations;
			derivations = new DerivationsMap();
			derivations->reserve(5000);
		}
		{
			WriteLock lock(coinbase_secrets_lock);
			delete coinbase_secrets;
			coinbase_secrets = new CoinbaseSecretsMap();
			coinbase_secrets->reserve(5000);
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
		{
			WriteLock lock(from_bytes_lock);
			delete from_bytes;
			from_bytes = new FromBytesMap();
			from_bytes->reserve(50);
		}
		{
			WriteLock lock(comb_tables_lock);
			delete comb_tables;
			comb_tables = new CombTablesMap();
			comb_tables->reserve(50);
		}
	}

private:
	struct DerivationEntry
	{
		FORCEINLINE DerivationEntry(const hash& derivation, uint32_t timestamp)
			: m_derivation(derivation)
			, m_viewTags{ TAG_NONE, TAG_NONE, TAG_NONE, TAG_NONE, TAG_NONE, TAG_NONE, TAG_NONE }
			, m_timestamp(timestamp)
		{}

		static constexpr uint32_t TAG_NONE = 0xFFFFFFFFUL;

		hash m_derivation;
		uint32_t m_viewTags[7];
		// cppcheck-suppress unusedStructMember
		uint32_t m_timestamp;

		FORCEINLINE bool find_view_tag(size_t output_index, uint8_t& view_tag) const
		{
			for (const uint32_t k : m_viewTags) {
				if (k == TAG_NONE) {
					return false;
				}

				if ((k >> 8) == output_index) {
					view_tag = static_cast<uint8_t>(k);
					return true;
				}
			}
			return false;
		}

		FORCEINLINE void add_view_tag(uint32_t k)
		{
			for (size_t i = 0, n = array_size(m_viewTags); i < n; ++i) {
				const uint32_t t = m_viewTags[i];

				if (t == TAG_NONE) {
					m_viewTags[i] = k;
					return;
				}

				if (t == k) {
					return;
				}
			}
		}
	};

	static_assert(sizeof(DerivationEntry) == 64, "Invalid DerivationEntry size");

	// One entry per (tx key, wallet, height, retry counter)
	using CoinbaseSecretsIndex = std::array<uint8_t, HASH_SIZE * 3 + sizeof(uint64_t) + 1>;

	static FORCEINLINE CoinbaseSecretsIndex coinbase_secrets_index(const hash& txkey_sec, uint8_t retry_counter, uint64_t height, const Wallet& w)
	{
		CoinbaseSecretsIndex index;

		memcpy(index.data(), txkey_sec.h, HASH_SIZE);
		memcpy(index.data() + HASH_SIZE, w.keys(), HASH_SIZE * 2);
		memcpy(index.data() + HASH_SIZE * 3, &height, sizeof(height));
		index[HASH_SIZE * 3 + sizeof(height)] = retry_counter;

		return index;
	}

	struct CoinbaseOutputEntry
	{
		uint64_t m_amount = 0;
		hash m_onetimeAddress;
		carrot::janus_anchor m_anchorEnc = {};
		carrot::view_tag m_viewTag = {};
	};

	struct CoinbaseSecretsEntry
	{
		carrot::coinbase_secrets m_secrets;
		std::vector<CoinbaseOutputEntry> m_outputs;

		// cppcheck-suppress unusedStructMember
		uint32_t m_timestamp = 0;
	};

	static FORCEINLINE bool same_secrets(const carrot::coinbase_secrets& a, const carrot::coinbase_secrets& b)
	{
		return (memcmp(a.anchor.data, b.anchor.data, CARROT_JANUS_ANCHOR_BYTES) == 0) &&
			(a.sender_receiver_secret == b.sender_receiver_secret) &&
			(a.contextualized_sender_receiver_secret == b.contextualized_sender_receiver_secret);
	}

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

	struct FromBytesEntry
	{
		FORCEINLINE FromBytesEntry(bool b, const ge_p3& p, uint32_t t, bool torsion_checked = false, bool torsion_free = false)
			: m_valid(b)
			, m_point(p)
			, m_torsionChecked(b && torsion_checked)
			, m_torsionFree(b && torsion_checked && torsion_free)
			, m_timestamp(t)
		{}

		bool m_valid;
		ge_p3 m_point;

		// Whether this key has been through the FCMP++ torsion check, and the result
		bool m_torsionChecked;
		bool m_torsionFree;

		// cppcheck-suppress unusedStructMember
		uint32_t m_timestamp;
	};

	struct CombTableEntry
	{
		// Shared with the code that uses it after releasing the cache lock
		std::shared_ptr<const CombTable> m_table;

		// cppcheck-suppress unusedStructMember
		uint32_t m_timestamp = 0;
	};

	typedef unordered_map<std::array<uint8_t, HASH_SIZE * 2>, DerivationEntry> DerivationsMap;
	typedef unordered_map<CoinbaseSecretsIndex, CoinbaseSecretsEntry> CoinbaseSecretsMap;
	typedef unordered_map<std::array<uint8_t, HASH_SIZE * 2 + sizeof(size_t)>, PublicKeyEntry> PublicKeysMap;
	typedef unordered_map<std::array<uint8_t, HASH_SIZE * 2>, TxKeyEntry> TxKeysMap;
	typedef unordered_map<hash, FromBytesEntry> FromBytesMap;
	typedef unordered_map<hash, CombTableEntry> CombTablesMap;

	uv_rwlock_t derivations_lock;
	DerivationsMap* derivations;

	uv_rwlock_t coinbase_secrets_lock;
	CoinbaseSecretsMap* coinbase_secrets;

	uv_rwlock_t public_keys_lock;
	PublicKeysMap* public_keys;

	uv_rwlock_t tx_keys_lock;
	TxKeysMap* tx_keys;

	uv_rwlock_t from_bytes_lock;
	FromBytesMap* from_bytes;

	uv_rwlock_t comb_tables_lock;
	CombTablesMap* comb_tables;

	// ge_wtable for G and T, read-only after the constructor
	ge_precomp base_table[GE_WTABLE_ROWS * GE_WTABLE_ROW_SIZE] = {};
	ge_precomp T_table[GE_WTABLE_ROWS * GE_WTABLE_ROW_SIZE] = {};

#ifdef P2POOL_UNIT_TESTS
	std::atomic<size_t> m_lastCoinbaseSecretsBatchSize{ 0 };
	std::atomic<size_t> m_lastCoinbaseOutputBatchSize{ 0 };
#endif
};

static Cache* cache = nullptr;

namespace carrot {

bool batch_eph_pubkeys(const std::vector<hash>& eph_priv_keys, std::vector<std::pair<hash, bool>>& eph_pub_keys)
{
	return cache->batch_eph_pubkeys(eph_priv_keys, eph_pub_keys);
}

bool batch_sender_receiver_secrets(const std::vector<hash>& eph_priv_keys, const std::vector<hash>& view_public_keys, std::vector<std::pair<hash, bool>>& secrets)
{
	return cache->batch_sender_receiver_secrets(eph_priv_keys, view_public_keys, secrets);
}

bool batch_coinbase_outputs(uint64_t height, const std::vector<coinbase_output_input>& in, std::vector<coinbase_tx_output>& out)
{
	return cache->batch_coinbase_outputs(height, in, out);
}

bool batch_coinbase_secrets(const hash& txkey_sec, uint8_t retry_counter, uint64_t height, const std::vector<const Wallet*>& wallets, std::vector<coinbase_secrets>& secrets)
{
	return cache->batch_coinbase_secrets(txkey_sec, retry_counter, height, wallets, nullptr, secrets, nullptr);
}

bool batch_coinbase_secrets(const hash& txkey_sec, uint8_t retry_counter, uint64_t height, const std::vector<const Wallet*>& wallets, const std::vector<uint64_t>& amounts, std::vector<coinbase_secrets>& secrets, std::vector<coinbase_tx_output>& outputs)
{
	return cache->batch_coinbase_secrets(txkey_sec, retry_counter, height, wallets, &amounts, secrets, &outputs);
}

bool complete_coinbase_outputs(const hash& txkey_sec, uint8_t retry_counter, uint64_t height, const std::vector<const Wallet*>& wallets, const std::vector<uint64_t>& amounts, const std::vector<coinbase_secrets>& secrets, std::vector<coinbase_tx_output>& outputs)
{
	return cache->complete_coinbase_outputs(txkey_sec, retry_counter, height, wallets, amounts, secrets, outputs);
}

} // namespace carrot

#ifdef P2POOL_UNIT_TESTS
size_t get_last_coinbase_secrets_batch_size() { return cache->get_last_coinbase_secrets_batch_size(); }
size_t get_last_coinbase_output_batch_size() { return cache->get_last_coinbase_output_batch_size(); }
uint32_t get_from_bytes_cache_state(const hash& public_key) { return cache->get_from_bytes_cache_state(public_key); }
#endif

void ge_scalarmult_base_vartime(ge_p3* h, const uint8_t* a)
{
	cache->scalarmult_base(h, a);
}

void ge_double_scalarmult_base_T_vartime(ge_p3* h, const uint8_t* a, const uint8_t* b)
{
	cache->double_scalarmult_base_T(h, a, b);
}

bool generate_key_derivation(const hash& key1, const hash& key2, size_t output_index, hash& derivation, uint8_t& view_tag)
{
	return cache->get_derivation(key1, key2, output_index, derivation, view_tag);
}

bool batch_derivations(const std::vector<std::pair<hash, size_t>>& in, const hash& txkey_sec, std::vector<std::pair<hash, int32_t>>& out)
{
	return cache->batch_derivations(in, txkey_sec, out);
}

bool derive_public_key(const hash& derivation, size_t output_index, const hash& base, hash& derived_key)
{
	return cache->get_public_key(derivation, output_index, base, derived_key);
}

bool batch_public_keys(const std::vector<batch_public_key_input>& in, std::vector<std::pair<hash, bool>>& out)
{
	return cache->batch_public_keys(in, out);
}

bool check_public_key(const hash& key)
{
	if (cache) {
		return cache->check_public_key(key);
	}

	ge_p3 point;

	if (ge_frombytes_vartime(&point, key.h) != 0) {
		return false;
	}

	return is_torsion_free(point);
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
