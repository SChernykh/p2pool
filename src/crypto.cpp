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

class Cache : public nocopy_nomove
{
public:
	Cache()
		: derivations(new DerivationsMap())
		, carrot_public_keys(new CarrotPublicKeysMap())
		, sender_receiver_secrets(new SenderReceiverSecretsMap())
		, public_keys(new PublicKeysMap())
		, tx_keys(new TxKeysMap())
		, from_bytes(new FromBytesMap())
	{
		uv_rwlock_init_checked(&derivations_lock);
		uv_rwlock_init_checked(&carrot_public_keys_lock);
		uv_rwlock_init_checked(&sender_receiver_secrets_lock);
		uv_rwlock_init_checked(&public_keys_lock);
		uv_rwlock_init_checked(&tx_keys_lock);
		uv_rwlock_init_checked(&from_bytes_lock);
	}

	~Cache()
	{
		delete derivations;
		delete carrot_public_keys;
		delete sender_receiver_secrets;
		delete public_keys;
		delete tx_keys;
		delete from_bytes;

		uv_rwlock_destroy(&derivations_lock);
		uv_rwlock_destroy(&carrot_public_keys_lock);
		uv_rwlock_destroy(&sender_receiver_secrets_lock);
		uv_rwlock_destroy(&public_keys_lock);
		uv_rwlock_destroy(&tx_keys_lock);
		uv_rwlock_destroy(&from_bytes_lock);
	}

	bool get_from_bytes(const hash& h, ge_p3& p, ge_cached* Ai)
	{
		ge_p3 point = {};

		bool valid = false;
		bool point_cached = false;
		bool precomp_cached = false;

		{
			ReadLock lock(from_bytes_lock);

			auto it = from_bytes->find(h);

			if (it != from_bytes->end()) {
				const FromBytesEntry& entry = it->second;

				if (!entry.m_valid) {
					return false;
				}

				valid = true;
				point_cached = true;
				point = entry.m_point;

				if (Ai && entry.m_hasAi) {
					memcpy(Ai, entry.m_Ai, sizeof(ge_dsmp));
					precomp_cached = true;
				}

				if (!Ai || precomp_cached) {
					p = point;
					return true;
				}
			}
		}

		if (!point_cached) {
			valid = (ge_frombytes_vartime(&point, h.h) == 0);
		}

		if (valid && Ai && !precomp_cached) {
			ge_dsm_precomp(Ai, &point);
		}

		const uint32_t t = static_cast<uint32_t>(seconds_since_epoch());
		{
			WriteLock lock(from_bytes_lock);

			auto it = from_bytes->emplace(h, FromBytesEntry(valid, point, t, Ai));

			if (valid && Ai && !it.first->second.m_hasAi) {
				it.first->second.m_hasAi = true;
				memcpy(it.first->second.m_Ai, Ai, sizeof(ge_dsmp));
			}

			// 2xPPLNS window = 4320 blocks, each block = 1 wallet (2 pubkeys), so ~8640 entries max
			// Double it and round it up to have some leeway
			limit_size(from_bytes, 20'000, 10'000);
		}

		if (valid) {
			memcpy(&p, &point, sizeof(p));
		}

		return valid;
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

			auto it = from_bytes->emplace(h, FromBytesEntry(valid, point, t, nullptr, true, torsion_free));
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

#ifdef P2POOL_UNIT_TESTS
		m_lastCarrotPublicKeyBatchSize.store(0);
#endif

		const size_t N = eph_priv_keys.size();

		if (N == 0) {
			return true;
		}

		eph_pub_keys.assign(N, { hash(), true });

		// First read all already cached public keys and save the indices we will need to fill in.
		std::vector<size_t> batch;
		batch.reserve(N);
		{
			ReadLock lock(carrot_public_keys_lock);

			for (size_t i = 0; i < N; ++i) {
				auto it = carrot_public_keys->find(eph_priv_keys[i]);

				if (it == carrot_public_keys->end()) {
					batch.emplace_back(i);
				}
				else {
					eph_pub_keys[i].first = it->second.m_key;
				}
			}
		}

#ifdef P2POOL_UNIT_TESTS
		m_lastCarrotPublicKeyBatchSize.store(batch.size());
#endif

		if (batch.empty()) {
			return true;
		}

		const size_t batch_size = batch.size();

		struct M {
			fe Y;
			fe Z;
			fe D; // Z - Y
			fe P; // partial products of D (segmented, P_i = D_a*D_{a+1}*...*D_i for a <= i < b)
			fe Q; // inverses of D (Q_i = D_i^-1 for 0 <= i < batch_size). Calculated in segments.
		};

		// batch_size*200 bytes for the inversion scratchpad
		std::vector<M> scratchpad(batch_size);

		std::atomic<uint32_t> counter = 0;
		std::atomic<bool> result = true;

		// Montgomery's trick to batch invert all Z - Y values with a single fe_invert call (parallel version)
		parallel_run([&](uint32_t thread_index, uint32_t total_thread_count) {
			// Always have at least 1 element per active thread
			const uint32_t thread_count = static_cast<uint32_t>(std::min<size_t>(total_thread_count, batch_size));

			if (thread_index >= thread_count) {
				return;
			}

			// 0 <= thread_index < thread_count <= batch_size at this point, so
			// 0 <= a < b <= batch_size (non-empty segments with valid bounds) is guaranteed
			const size_t a = (batch_size * thread_index) / thread_count;
			const size_t b = (batch_size * (thread_index + 1)) / thread_count;

			uint32_t next_counter = thread_count;

			for (size_t i = a; i < b; ++i) {
				ge_p3 point;
				ge_scalarmult_base_vartime(&point, eph_priv_keys[batch[i]].h);

				memcpy(scratchpad[i].Y, point.Y, sizeof(fe));
				memcpy(scratchpad[i].Z, point.Z, sizeof(fe));
				fe_sub(scratchpad[i].D, point.Z, point.Y);

				hash denominator;
				fe_tobytes(denominator.h, scratchpad[i].D);

				// d_e * G is the point at infinity, so ConvertPointE is not defined for it.
				if (denominator.empty()) {
					eph_pub_keys[batch[i]].second = false;
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
				// Work over the whole miss batch, but inverse only each segment's end
				// One fe_invert, thread_count*3 - 3 fe_mul calls

				// Calculate partial products of segment ends
				size_t k = batch_size * (0 + 1) / thread_count - 1;
				memcpy(scratchpad[k].Q, scratchpad[k].P, sizeof(fe));

				for (uint32_t i = 1; i < thread_count; ++i) {
					const size_t next_k = batch_size * (i + 1) / thread_count - 1;
					fe_mul(scratchpad[next_k].Q, scratchpad[k].Q, scratchpad[next_k].P);
					k = next_k;
				}

				// Invert the product of all segment ends. k == batch_size - 1 here (because see how the loop above exits).
				fe t;
				fe_invert(t, scratchpad[k].Q);

				// Walk back to calculate inverses of segment ends
				for (uint32_t i = thread_count - 1; i > 0; --i) {
					const size_t prev_k = batch_size * i / thread_count - 1;

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
				if (!eph_pub_keys[batch[i]].second) {
					continue;
				}

				fe numerator;

				fe_add(numerator, scratchpad[i].Z, scratchpad[i].Y);
				fe_mul(numerator, numerator, scratchpad[i].Q);
				fe_tobytes(eph_pub_keys[batch[i]].first.h, numerator);
			}
		}, true);

		// When debugging, don't pollute the cache with the values calculated here.
		// Instead, compare them with gen_eph_pubkey() output below.
		// Unit test builds keep the cache because the tests check cache behavior explicitly,
		// and they compare every element (cached or not) against gen_eph_pubkey() themselves.
#if !defined(P2POOL_DEBUGGING) || defined(P2POOL_UNIT_TESTS)
		{
			const uint32_t t = static_cast<uint32_t>(seconds_since_epoch());

			WriteLock lock(carrot_public_keys_lock);

			for (const size_t i : batch) {
				if (eph_pub_keys[i].second) {
					carrot_public_keys->emplace(eph_priv_keys[i], CarrotPublicKeyEntry{ eph_pub_keys[i].first, t });
				}
			}

			// There is normally one ephemeral key per wallet for each Monero height/tx key.
			limit_size(carrot_public_keys, 10'000, 5'000);
		}
#endif

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

#ifdef P2POOL_UNIT_TESTS
		m_lastSenderReceiverSecretBatchSize.store(0);
#endif

		const size_t N = eph_priv_keys.size();

		if (view_public_keys.size() != N) {
			return false;
		}

		if (N == 0) {
			return true;
		}

		secrets.assign(N, { hash(), true });

		std::array<uint8_t, HASH_SIZE * 2> index;
		std::vector<size_t> secret_batch;

		secret_batch.reserve(N);

		// First read all already cached secrets and save the indices we will need to fill in.
		{
			ReadLock lock(sender_receiver_secrets_lock);

			for (size_t i = 0; i < N; ++i) {
				memcpy(index.data(), view_public_keys[i].h, HASH_SIZE);
				memcpy(index.data() + HASH_SIZE, eph_priv_keys[i].h, HASH_SIZE);

				auto it = sender_receiver_secrets->find(index);
				if (it == sender_receiver_secrets->end()) {
					secret_batch.emplace_back(i);
				}
				else {
					secrets[i].first = it->second.m_secret;
				}
			}
		}

#ifdef P2POOL_UNIT_TESTS
		m_lastSenderReceiverSecretBatchSize.store(secret_batch.size());
#endif

		if (secret_batch.empty()) {
			return true;
		}

		const size_t batch_size = secret_batch.size();

		struct PublicKeyData {
			ge_p3 point = {};
			ge_dsmp precomp = {};

			bool valid = false;
			bool has_point = false;
			bool has_precomp = false;
			bool cache_update = false;
		};

		std::vector<PublicKeyData> public_key_data(batch_size);

		// Copy all available cache data while holding the read lock only once.
		{
			ReadLock lock(from_bytes_lock);

			for (size_t i = 0; i < batch_size; ++i) {
				const size_t j = secret_batch[i];
				auto it = from_bytes->find(view_public_keys[j]);

				if (it == from_bytes->end()) {
					continue;
				}

				const FromBytesEntry& entry = it->second;

				PublicKeyData& data = public_key_data[i];

				data.point = entry.m_point;
				data.valid = entry.m_valid;
				data.has_point = true;

				if (!entry.m_valid) {
					continue;
				}

				if (entry.m_hasAi) {
					memcpy(data.precomp, entry.m_Ai, sizeof(ge_dsmp));
					data.has_precomp = true;
				}
			}
		}

		struct M {
			fe Y;
			fe Z;
			fe D; // Z - Y
			fe P; // partial products of D (segmented, P_i = D_a*D_{a+1}*...*D_i for a <= i < b)
			fe Q; // inverses of D (Q_i = D_i^-1 for 0 <= i < batch_size). Calculated in segments.
		};

		// batch_size*200 bytes for the inversion scratchpad
		std::vector<M> scratchpad(batch_size);

		std::atomic<uint32_t> counter = 0;
		std::atomic<bool> result = true;
		std::atomic<bool> cache_update = false;

		// Montgomery's trick to batch invert all Z - Y values with a single fe_invert call (parallel version)
		parallel_run([&](uint32_t thread_index, uint32_t total_thread_count) {
			// Always have at least 1 element per active thread
			const uint32_t thread_count = static_cast<uint32_t>(std::min<size_t>(total_thread_count, batch_size));

			if (thread_index >= thread_count) {
				return;
			}

			// 0 <= thread_index < thread_count <= batch_size at this point, so
			// 0 <= a < b <= batch_size (non-empty segments with valid bounds) is guaranteed
			const size_t a = (batch_size * thread_index) / thread_count;
			const size_t b = (batch_size * (thread_index + 1)) / thread_count;

			uint32_t next_counter = thread_count;

			for (size_t i = a; i < b; ++i) {
				const size_t j = secret_batch[i];
				PublicKeyData& data = public_key_data[i];

				bool ok = false;

				if (!data.has_point) {
					data.valid = (ge_frombytes_vartime(&data.point, view_public_keys[j].h) == 0);
					data.has_point = true;
					data.cache_update = true;
					cache_update.store(true, std::memory_order_release);
				}

				if (data.valid) {
					if (!data.has_precomp) {
						ge_dsm_precomp(data.precomp, &data.point);
						data.has_precomp = true;
						data.cache_update = true;
						cache_update.store(true, std::memory_order_release);
					}

					signed char scalar_slide[256];
					ge_scalarmult_slide(scalar_slide, eph_priv_keys[j].h);

					ge_p2 point;
					ge_scalarmult_vartime_precomp(&point, data.precomp, scalar_slide);

					memcpy(scratchpad[i].Y, point.Y, sizeof(fe));
					memcpy(scratchpad[i].Z, point.Z, sizeof(fe));
					fe_sub(scratchpad[i].D, point.Z, point.Y);

					hash denominator;
					fe_tobytes(denominator.h, scratchpad[i].D);

					// d_e * K_v is the point at infinity, so ConvertPointE is not defined for it
					ok = !denominator.empty();
				}

				if (!ok) {
					secrets[j].second = false;
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
				// Work over the whole miss batch, but inverse only each segment's end
				// One fe_invert, thread_count*3 - 3 fe_mul calls

				// Calculate partial products of segment ends
				size_t k = batch_size * (0 + 1) / thread_count - 1;
				memcpy(scratchpad[k].Q, scratchpad[k].P, sizeof(fe));

				for (uint32_t i = 1; i < thread_count; ++i) {
					const size_t next_k = batch_size * (i + 1) / thread_count - 1;
					fe_mul(scratchpad[next_k].Q, scratchpad[k].Q, scratchpad[next_k].P);
					k = next_k;
				}

				// Invert the product of all segment ends. k == batch_size - 1 here (because see how the loop above exits).
				fe t;
				fe_invert(t, scratchpad[k].Q);

				// Walk back to calculate inverses of segment ends
				for (uint32_t i = thread_count - 1; i > 0; --i) {
					const size_t prev_k = batch_size * i / thread_count - 1;

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
				const size_t j = secret_batch[i];

				if (!secrets[j].second) {
					continue;
				}

				fe numerator;
				fe_add(numerator, scratchpad[i].Z, scratchpad[i].Y);
				fe_mul(numerator, numerator, scratchpad[i].Q);
				fe_tobytes(secrets[j].first.h, numerator);
			}
		}, true);

		if (cache_update.load(std::memory_order_acquire)) {
			const uint32_t t = static_cast<uint32_t>(seconds_since_epoch());

			WriteLock lock(from_bytes_lock);

			for (size_t i = 0; i < batch_size; ++i) {
				const size_t j = secret_batch[i];
				const PublicKeyData& data = public_key_data[i];

				if (!data.cache_update) {
					continue;
				}

				const ge_cached* precomp = data.has_precomp ? data.precomp : nullptr;

				auto it = from_bytes->emplace(view_public_keys[j], FromBytesEntry(data.valid, data.point, t, precomp));
				FromBytesEntry& entry = it.first->second;

				if (data.valid && data.has_precomp && !entry.m_hasAi) {
					entry.m_hasAi = true;
					memcpy(entry.m_Ai, data.precomp, sizeof(ge_dsmp));
				}
			}

			limit_size(from_bytes, 20'000, 10'000);
		}

		// When debugging, don't pollute the cache with the values calculated here.
		// Instead, compare them with gen_sender_receiver_secret() output below.
		// Unit test builds keep the cache because the tests check cache behavior explicitly,
		// and they compare every element (cached or not) against gen_sender_receiver_secret() themselves.
#if !defined(P2POOL_DEBUGGING) || defined(P2POOL_UNIT_TESTS)
		// Finally cache only the secrets that were missing when this batch started.
		{
			const uint32_t t = static_cast<uint32_t>(seconds_since_epoch());

			WriteLock lock(sender_receiver_secrets_lock);

			for (size_t i = 0; i < batch_size; ++i) {
				const size_t j = secret_batch[i];

				if (!secrets[j].second) {
					continue;
				}

				memcpy(index.data(), view_public_keys[j].h, HASH_SIZE);
				memcpy(index.data() + HASH_SIZE, eph_priv_keys[j].h, HASH_SIZE);
				sender_receiver_secrets->emplace(index, SenderReceiverSecretEntry{ secrets[j].first, t });
			}

			// There is normally one secret per wallet for each Monero height/tx key, and cache cleanup
			// retains no more than the current and previous miner-data generations.
			limit_size(sender_receiver_secrets, 10'000, 5'000);
		}
#endif

#ifdef P2POOL_DEBUGGING
		for (size_t i = 0; i < N; ++i) {
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
	//
	// Deliberately not cached: every new share re-splits the reward, and so does every transaction added to the
	// block template, so two peers on the same sidechain tip will rarely be hashing the same amounts.
	bool batch_coinbase_outputs(uint64_t height, const std::vector<carrot::coinbase_output_input>& in, std::vector<carrot::coinbase_output>& out)
	{
		out.clear();

		const size_t N = in.size();

		if (N == 0) {
			return true;
		}

		out.assign(N, carrot::coinbase_output{});

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

					ge_double_scalarmult_base_T_vartime(&point2, sender_extension_g.h, sender_extension_t.h);
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
		}, true);

		if (cache_update.load(std::memory_order_acquire)) {
			const uint32_t t = static_cast<uint32_t>(seconds_since_epoch());

			WriteLock lock(from_bytes_lock);

			for (size_t i = 0; i < N; ++i) {
				const SpendKeyData& data = spend_key_data[i];

				if (data.cache_update) {
					from_bytes->emplace(in[i].spend_public_key, FromBytesEntry(data.valid, data.point, t, nullptr));
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

#ifdef P2POOL_UNIT_TESTS
	size_t get_last_carrot_public_key_batch_size() const
	{
		return m_lastCarrotPublicKeyBatchSize.load();
	}

	size_t get_last_sender_receiver_secret_batch_size() const
	{
		return m_lastSenderReceiverSecretBatchSize.load();
	}

	uint32_t get_from_bytes_cache_state(const hash& public_key)
	{
		ReadLock lock(from_bytes_lock);

		auto it = from_bytes->find(public_key);
		if (it == from_bytes->end()) {
			return 0;
		}

		const FromBytesEntry& entry = it->second;
		return
			1U |
			(entry.m_valid ? 2U : 0U) |
			(entry.m_hasAi ? 4U : 0U) |
			(entry.m_torsionChecked ? 8U : 0U) |
			(entry.m_torsionFree ? 16U : 0U);
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
			ge_p3 point;
			ge_p2 point2;
			ge_p1p1 point3;
			ge_dsmp Ai;

			if (!get_from_bytes(key1, point, Ai)) {
				return false;
			}

			signed char aslide[256];
			ge_scalarmult_slide(aslide, key2.h);

			ge_scalarmult_vartime_precomp(&point2, Ai, aslide);
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

			signed char aslide[256];
			ge_scalarmult_slide(aslide, txkey_sec.h);

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
					ge_p3 point;
					ge_p2 point2;
					ge_p1p1 point3;
					ge_dsmp Ai;

					if (!get_from_bytes(in[derivation_batch[i]].first, point, Ai)) {
						out[derivation_batch[i]].second = -1;
						result = false;

						fe_1(point2.X);
						fe_1(point2.Y);
						fe_1(point2.Z);
					}
					else {
						ge_scalarmult_vartime_precomp(&point2, Ai, aslide);
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
			}, true);
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
			}, true);
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

		if (!get_from_bytes(base, point1, nullptr)) {
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
						ge_scalarmult_base_vartime(&point2, reinterpret_cast<uint8_t*>(&scalar));
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
			}, true);

			if (cache_update.load(std::memory_order_acquire)) {
				const uint32_t t = static_cast<uint32_t>(seconds_since_epoch());

				WriteLock lock(from_bytes_lock);

				for (size_t i = 0; i < N; ++i) {
					const BaseKeyData& data = base_key_data[i];

					if (data.cache_update) {
						from_bytes->emplace(in[batch[i]].base, FromBytesEntry(data.valid, data.point, t, nullptr));
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
				WriteLock lock(carrot_public_keys_lock);
				clean_old(carrot_public_keys, t);
			}
			{
				WriteLock lock(sender_receiver_secrets_lock);
				clean_old(sender_receiver_secrets, t);
			}
			{
				WriteLock lock(public_keys_lock);
				clean_old(public_keys, t);
			}
			{
				WriteLock lock(tx_keys_lock);
				clean_old(tx_keys, t);
			}
			// from_bytes is not cleaned of old entries because it has data for miner wallets which change rarely
			// limit_size is what limits from_bytes instead
			return;
		}

		{
			WriteLock lock(derivations_lock);
			delete derivations;
			derivations = new DerivationsMap();
			derivations->reserve(5000);
		}
		{
			WriteLock lock(carrot_public_keys_lock);
			delete carrot_public_keys;
			carrot_public_keys = new CarrotPublicKeysMap();
			carrot_public_keys->reserve(5000);
		}
		{
			WriteLock lock(sender_receiver_secrets_lock);
			delete sender_receiver_secrets;
			sender_receiver_secrets = new SenderReceiverSecretsMap();
			sender_receiver_secrets->reserve(5000);
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

	struct CarrotPublicKeyEntry
	{
		hash m_key;
		// cppcheck-suppress unusedStructMember
		uint32_t m_timestamp = 0;
	};

	struct SenderReceiverSecretEntry
	{
		hash m_secret;
		// cppcheck-suppress unusedStructMember
		uint32_t m_timestamp = 0;
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

	struct FromBytesEntry
	{
		FORCEINLINE FromBytesEntry(bool b, const ge_p3& p, uint32_t t, const ge_cached* Ai, bool torsion_checked = false, bool torsion_free = false)
			: m_valid(b)
			, m_point(p)
			, m_hasAi(b && Ai)
			, m_torsionChecked(b && torsion_checked)
			, m_torsionFree(b && torsion_checked && torsion_free)
			, m_timestamp(t)
		{
			if (b && Ai) {
				memcpy(m_Ai, Ai, sizeof(m_Ai));
			}
			else {
				memset(m_Ai, 0, sizeof(m_Ai));
			}
		}

		bool m_valid;
		ge_p3 m_point;

		bool m_hasAi;
		ge_dsmp m_Ai;

		// Whether this key has been through the FCMP++ torsion check, and the result
		bool m_torsionChecked;
		bool m_torsionFree;

		// cppcheck-suppress unusedStructMember
		uint32_t m_timestamp;
	};

	typedef unordered_map<std::array<uint8_t, HASH_SIZE * 2>, DerivationEntry> DerivationsMap;
	typedef unordered_map<hash, CarrotPublicKeyEntry> CarrotPublicKeysMap;
	typedef unordered_map<std::array<uint8_t, HASH_SIZE * 2>, SenderReceiverSecretEntry> SenderReceiverSecretsMap;
	typedef unordered_map<std::array<uint8_t, HASH_SIZE * 2 + sizeof(size_t)>, PublicKeyEntry> PublicKeysMap;
	typedef unordered_map<std::array<uint8_t, HASH_SIZE * 2>, TxKeyEntry> TxKeysMap;
	typedef unordered_map<hash, FromBytesEntry> FromBytesMap;

	uv_rwlock_t derivations_lock;
	DerivationsMap* derivations;

	uv_rwlock_t carrot_public_keys_lock;
	CarrotPublicKeysMap* carrot_public_keys;

	uv_rwlock_t sender_receiver_secrets_lock;
	SenderReceiverSecretsMap* sender_receiver_secrets;

	uv_rwlock_t public_keys_lock;
	PublicKeysMap* public_keys;

	uv_rwlock_t tx_keys_lock;
	TxKeysMap* tx_keys;

	uv_rwlock_t from_bytes_lock;
	FromBytesMap* from_bytes;

#ifdef P2POOL_UNIT_TESTS
	std::atomic<size_t> m_lastCarrotPublicKeyBatchSize{ 0 };
	std::atomic<size_t> m_lastSenderReceiverSecretBatchSize{ 0 };
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

bool batch_coinbase_outputs(uint64_t height, const std::vector<coinbase_output_input>& in, std::vector<coinbase_output>& out)
{
	return cache->batch_coinbase_outputs(height, in, out);
}

} // namespace carrot

#ifdef P2POOL_UNIT_TESTS
size_t get_last_carrot_public_key_batch_size()
{
	return cache->get_last_carrot_public_key_batch_size();
}

size_t get_last_sender_receiver_secret_batch_size()
{
	return cache->get_last_sender_receiver_secret_batch_size();
}

uint32_t get_from_bytes_cache_state(const hash& public_key)
{
	return cache->get_from_bytes_cache_state(public_key);
}
#endif

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
