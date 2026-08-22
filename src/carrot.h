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

namespace carrot {
	template<size_t N, typename T>
	struct transcript_serializer {
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
		FORCEINLINE static constexpr void run(const uint8_t& data, std::array<uint8_t, N>& output, size_t& offset)
		{
			output[offset++] = data;
		}
	};

	template<size_t N>
	struct transcript_serializer<N, hash> {
		FORCEINLINE static constexpr void run(const hash& data, std::array<uint8_t, N>& output, size_t& offset)
		{
			static_assert(sizeof(data) == HASH_SIZE);

			for (size_t i = 0; i < HASH_SIZE; ++i, ++offset) {
				output[offset] = data.h[i];
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

		constexpr size_t total_size = 1 + domain_len + (sizeof(std::decay_t<T>) + ...);

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
} // namespace carrot

} // namespace p2pool
