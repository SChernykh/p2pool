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
#include "carrot.h"
#include "wallet.h"
#include "uv_util.h"
#include "blake2/blake2.h"

extern "C" {
#include "crypto-ops.h"
}

#ifdef P2POOL_DEBUGGING
LOG_CATEGORY(Carrot)
#endif

namespace p2pool {

namespace carrot {

bool hash_to_bytes(const void* input, size_t in_len, void* output, size_t out_len, const void* key)
{
	if (!input || !output || !out_len || (out_len > BLAKE2B_OUTBYTES)) {
		return false;
	}

	blake2b_param param{};

	param.digest_length = static_cast<uint8_t>(out_len);
	param.key_length = key ? CARROT_HASH_KEY_BYTES : 0;
	param.fanout = 1;
	param.depth = 1;

	constexpr char personal[] = "Monero";
	memcpy(param.personal, personal, sizeof(personal) - 1);

	blake2b_state state;
	blake2b_init_param(&state, &param);

	if (key) {
		static_assert(CARROT_HASH_KEY_BYTES <= BLAKE2B_BLOCKBYTES);
		uint8_t key_buf[BLAKE2B_BLOCKBYTES];

		memcpy(key_buf, key, CARROT_HASH_KEY_BYTES);
		memset(key_buf + CARROT_HASH_KEY_BYTES, 0, BLAKE2B_BLOCKBYTES - CARROT_HASH_KEY_BYTES);

		blake2b_update(&state, key_buf, BLAKE2B_BLOCKBYTES);
	}

	blake2b_update(&state, input, in_len);
	blake2b_final(&state, output, out_len);

	return true;
}

bool hash_to_scalar(const void *data, const std::size_t data_length, void *hash_out, const void *key)
{
	uint8_t buf[64];

	if (!hash_out || !hash_to_bytes(data, data_length, buf, 64, key)) {
		return false;
	}

	sc_reduce(buf);
	memcpy(hash_out, buf, 32);

	return true;
}

janus_anchor gen_janus_anchor(const hash& txkey_sec, uint8_t retry_counter, const Wallet& w)
{
	auto t = transcript(
		"P2Pool Janus anchor",
		txkey_sec, retry_counter,
		w.spend_public_key(), w.view_public_key()
	);

	janus_anchor result;
	hash_to_bytes(t.data(), t.size(), result.data, CARROT_JANUS_ANCHOR_BYTES);

	return result;
}

bool gen_eph_privkey(const janus_anchor& anchor_norm, uint64_t height, const Wallet& w, hash& eph_priv_key)
{
	auto t = transcript(
		"Carrot sending key normal",
		anchor_norm,
		'C', height, padding<CARROT_INPUT_CONTEXT_PADDING_BYTES>(),
		w.spend_public_key(),
		padding<LEGACY_PAYMENT_ID_BYTES>()
	);

	return hash_to_scalar(t.data(), t.size(), eph_priv_key.h) && !eph_priv_key.empty();
}

bool gen_eph_pubkey(const hash& eph_priv_key, hash& eph_pub_key)
{
	ge_p3 point;
	ge_scalarmult_base_vartime(&point, eph_priv_key.h);
	ge_p3_to_x25519(eph_pub_key.h, &point);

	return true;
}

bool batch_eph_pubkeys(const std::vector<hash>& eph_priv_keys, std::vector<hash>& eph_pub_keys)
{
	eph_pub_keys.clear();

	const size_t N = eph_priv_keys.size();
	if (N == 0) {
		return true;
	}

	eph_pub_keys.resize(N);

	struct M {
		fe Y;
		fe Z;
		fe D; // Z - Y
		fe P; // partial products of D (segmented, P_i = D_a*D_{a+1}*...*D_i for a <= i < b)
		fe Q; // inverses of D (Q_i = D_i^-1 for 0 <= i < N). Calculated in segments.
	};

	// N*200 bytes for the scratchpad
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
			ge_scalarmult_base_vartime(&point, eph_priv_keys[i].h);

			memcpy(scratchpad[i].Y, point.Y, sizeof(fe));
			memcpy(scratchpad[i].Z, point.Z, sizeof(fe));
			fe_sub(scratchpad[i].D, point.Z, point.Y);

			hash denominator;
			fe_tobytes(denominator.h, scratchpad[i].D);

			if (denominator.empty()) {
				result = false;
				break;
			}

			if (i == a) {
				memcpy(scratchpad[i].P, scratchpad[i].D, sizeof(fe));
			}
			else {
				fe_mul(scratchpad[i].P, scratchpad[i - 1].P, scratchpad[i].D);
			}
		}

		const bool last = sync_point(counter, next_counter);

		// All denominators have been checked at this point, so every active worker can stop together.
		if (!result) {
			return;
		}

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
			fe numerator;
			fe_add(numerator, scratchpad[i].Z, scratchpad[i].Y);
			fe_mul(numerator, numerator, scratchpad[i].Q);
			fe_tobytes(eph_pub_keys[i].h, numerator);
		}
	}, true);

	if (!result) {
		eph_pub_keys.clear();
		return false;
	}

#ifdef P2POOL_DEBUGGING
	for (size_t i = 0; i < N; ++i) {
		hash eph_pub_key;
		if (!gen_eph_pubkey(eph_priv_keys[i], eph_pub_key) || (eph_pub_key != eph_pub_keys[i])) {
			LOGERR(1, "batch_eph_pubkeys error: wrong ephemeral public key at position " << i << '/' << N);
			PANIC_STOP();
		}
	}
#endif

	return true;
}

} // namespace carrot

} // namespace p2pool
