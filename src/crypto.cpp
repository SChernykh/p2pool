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

#ifdef P2POOL_DEBUGGING
LOG_CATEGORY(Crypto)
#endif

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
		, from_bytes(new FromBytesMap())
	{
		uv_rwlock_init_checked(&derivations_lock);
		uv_rwlock_init_checked(&public_keys_lock);
		uv_rwlock_init_checked(&tx_keys_lock);
		uv_rwlock_init_checked(&from_bytes_lock);
	}

	~Cache()
	{
		delete derivations;
		delete public_keys;
		delete tx_keys;
		delete from_bytes;

		uv_rwlock_destroy(&derivations_lock);
		uv_rwlock_destroy(&public_keys_lock);
		uv_rwlock_destroy(&tx_keys_lock);
		uv_rwlock_destroy(&from_bytes_lock);
	}

	bool get_from_bytes(const hash& h, ge_p3& p, ge_cached* Ai)
	{
		{
			ReadLock lock(from_bytes_lock);

			auto it = from_bytes->find(h);

			if (it != from_bytes->end()) {
				if (!it->second.m_valid) {
					return false;
				}

				if (!Ai || it->second.m_hasAi) {
					p = it->second.m_point;
					if (Ai) {
						memcpy(Ai, it->second.m_Ai, sizeof(ge_dsmp));
					}
					return true;
				}
			}
		}

		ge_p3 point = {};
		const bool valid = (ge_frombytes_vartime(&point, h.h) == 0);

		if (valid && Ai) {
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

			struct M {
				ge_p2 p; // the original point p
				fe P;    // partial products of p.Z (segmented, P_i = Z_a*Z_{a+1}*...*Z_i for a <= i < b)
				fe Q;    // inverses of p.Z (Q_i = Z_i^-1 for 0 <= i < N). Calculated in segments.
			};

			// N*200 bytes for the scratchpad
			std::vector<M> scratchpad(N);

			std::atomic<uint32_t> counter = 0;

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

					ge_p3 point1;
					ge_p2 point5;

					if (!get_from_bytes(t.base, point1, nullptr)) {
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
						ge_add(&point4, &point1, &point3);
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
		FORCEINLINE FromBytesEntry(bool b, const ge_p3& p, uint32_t t, const ge_cached* Ai)
			: m_valid(b)
			, m_point(p)
			, m_hasAi(b && (Ai != nullptr))
			, m_timestamp(t)
		{
			if (m_hasAi) {
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

		// cppcheck-suppress unusedStructMember
		uint32_t m_timestamp;
	};

	typedef unordered_map<std::array<uint8_t, HASH_SIZE * 2>, DerivationEntry> DerivationsMap;
	typedef unordered_map<std::array<uint8_t, HASH_SIZE * 2 + sizeof(size_t)>, PublicKeyEntry> PublicKeysMap;
	typedef unordered_map<std::array<uint8_t, HASH_SIZE * 2>, TxKeyEntry> TxKeysMap;
	typedef unordered_map<hash, FromBytesEntry> FromBytesMap;

	uv_rwlock_t derivations_lock;
	DerivationsMap* derivations;

	uv_rwlock_t public_keys_lock;
	PublicKeysMap* public_keys;

	uv_rwlock_t tx_keys_lock;
	TxKeysMap* tx_keys;

	uv_rwlock_t from_bytes_lock;
	FromBytesMap* from_bytes;
};

static Cache* cache = nullptr;

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
