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

#pragma once

#include <array>

namespace p2pool {

class Wallet;

namespace carrot {
	template<size_t N, typename T>
	struct transcript_serializer {
		static constexpr size_t size = sizeof(T);

		FORCEINLINE static constexpr void run(const T& data, std::array<uint8_t, N>& output, size_t& offset)
		{
			static_assert(!std::is_pointer_v<T>);

			if constexpr (std::is_integral_v<T> && !std::is_signed_v<T>) {
				T k = data;
				for (size_t i = 0; i < sizeof(T); ++i, ++offset) {
					output[offset] = static_cast<uint8_t>(k);
					k >>= 8;
				}
			}
			else {
				static_assert(not_implemented<T>::value);
			}
		}
	};

	template<size_t N>
	struct transcript_serializer<N, uint8_t> {
		static constexpr size_t size = 1;

		FORCEINLINE static constexpr void run(const uint8_t& data, std::array<uint8_t, N>& output, size_t& offset)
		{
			output[offset++] = data;
		}
	};

	template<size_t N>
	struct transcript_serializer<N, char> {
		static constexpr size_t size = 1;

		FORCEINLINE static constexpr void run(const char& data, std::array<uint8_t, N>& output, size_t& offset)
		{
			output[offset++] = static_cast<uint8_t>(data);
		}
	};

	template<size_t N>
	struct transcript_serializer<N, hash> {
		static constexpr size_t size = HASH_SIZE;

		FORCEINLINE static constexpr void run(const hash& data, std::array<uint8_t, N>& output, size_t& offset)
		{
			for (size_t i = 0; i < HASH_SIZE; ++i, ++offset) {
				output[offset] = data.h[i];
			}
		}
	};

	template<size_t N>
	struct transcript_serializer<N, janus_anchor> {
		static constexpr size_t size = CARROT_JANUS_ANCHOR_BYTES;

		FORCEINLINE static constexpr void run(const janus_anchor& data, std::array<uint8_t, N>& output, size_t& offset)
		{
			for (size_t i = 0; i < CARROT_JANUS_ANCHOR_BYTES; ++i, ++offset) {
				output[offset] = data.data[i];
			}
		}
	};

	template<size_t N, uint8_t value = 0> struct padding {};

	template<size_t N, size_t M, uint8_t value>
	struct transcript_serializer<N, padding<M, value>> {
		static constexpr size_t size = M;

		FORCEINLINE static constexpr void run(const padding<M, value>&, std::array<uint8_t, N>& output, size_t& offset)
		{
			for (size_t e = offset + M; offset < e; ++offset) {
				output[offset] = value;
			}
		}
	};

	template<size_t N, typename T>
	FORCEINLINE constexpr void append_helper(const T& arg, std::array<uint8_t, N>& result, size_t& offset)
	{
		transcript_serializer<N, std::decay_t<T>>::run(arg, result, offset);
	}

	template<size_t N, typename... T>
	FORCEINLINE constexpr auto transcript(const char (&domain)[N], const T&... args)
	{
		constexpr size_t domain_len = N - 1;

		static_assert(domain_len > 0, "Domain must be non-empty");
		static_assert(domain_len <= 255, "Domain length must fit in one byte");

		constexpr size_t total_size = 1 + domain_len + (transcript_serializer<N, std::decay_t<T>>::size + ...);

		std::array<uint8_t, total_size> result{};

		size_t offset = 0;

		result[offset] = static_cast<uint8_t>(domain_len);

		do {
			const uint8_t t = domain[offset];
			++offset;
			result[offset] = t;
		} while (offset < domain_len);

		++offset;

		(append_helper<total_size>(args, result, offset), ...);

		return result;
	}

	bool hash_to_bytes(const void* input, size_t in_len, void* output, size_t out_len, const void* key = nullptr);
	bool hash_to_scalar(const void *data, const std::size_t data_length, void *hash_out, const void *key = nullptr);

	// TODO: when adding it to block generation/verification, make sure retry_counter is the smallest possible value
	// that makes generated anchors pass all Carrot checks (no zero/duplicate anchors, no zero/duplicate D_e, no duplicate K_o)
	// retry_counter is transaction-wide and must have a single canonical value, just like txkey_sec
	carrot::janus_anchor gen_janus_anchor(const hash& txkey_sec, uint8_t retry_counter, const Wallet& w);
	bool gen_eph_privkey(const janus_anchor& anchor_norm, uint64_t height, const Wallet& w, hash& eph_priv_key);

	bool gen_eph_pubkey(const hash& eph_priv_key, hash& eph_pub_key);
	bool gen_sender_receiver_secret(const hash& eph_priv_key, const hash& view_public_key, hash& secret);
	hash gen_contextualized_sender_receiver_secret(const hash& sender_receiver_secret, const hash& eph_pub_key, uint64_t height);

	hash gen_sender_extension_g(const hash& contextualized_sender_receiver_secret, uint64_t amount, const hash& spend_public_key);
	hash gen_sender_extension_t(const hash& contextualized_sender_receiver_secret, uint64_t amount, const hash& spend_public_key);

	view_tag gen_view_tag(const hash& sender_receiver_secret, uint64_t height, const hash& onetime_address);

	janus_anchor gen_encrypted_janus_anchor(const hash& contextualized_sender_receiver_secret, const janus_anchor& anchor, const hash& onetime_address);

	bool batch_eph_pubkeys(const std::vector<hash>& eph_priv_keys, std::vector<std::pair<hash, bool>>& eph_pub_keys);
	bool batch_sender_receiver_secrets(const std::vector<hash>& eph_priv_keys, const std::vector<hash>& view_public_keys, std::vector<std::pair<hash, bool>>& secrets);
} // namespace carrot

} // namespace p2pool
