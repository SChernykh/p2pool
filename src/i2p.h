/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2026 SChernykh <https://github.com/SChernykh>
 * Copyright (c) 2026 jpk68
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

#include "common.h"
#include <string>
#include <uv.h>

namespace p2pool {

static FORCEINLINE constexpr hash from_i2p_b32_const(const char* dest_hash)
{
	uint8_t buf[HASH_SIZE + 4] = {};
	uint8_t* p = buf;

	uint64_t data = 0;
	uint64_t bit_size = 0;

	for (size_t i = 0; i < 52; ++i) {
		const char c = dest_hash[i];
		uint64_t digit = 0;

		if ('a' <= c && c <= 'z') {
			digit = static_cast<uint64_t>(c - 'a');
		}
		else if ('A' <= c && c <= 'Z') {
			digit = static_cast<uint64_t>(c - 'A');
		}
		else if ('2' <= c && c <= '7') {
			digit = static_cast<uint64_t>(c - '2') + 26;
		}
		else {
			return {};
		}

		data = (data << 5) | digit;
		bit_size += 5;

		while (bit_size >= 8) {
			bit_size -= 8;
			*(p++) = static_cast<uint8_t>(data >> bit_size);
		}
	}

	hash result;

	for (size_t i = 0; i < HASH_SIZE; ++i) {
		result.h[i] = buf[i];
	}

	return result;
}

hash from_i2p_b32(const std::string& address);
std::string to_i2p_b32(const hash& dest_hash);

} // namespace p2pool
