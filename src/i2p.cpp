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

#include <stdexcept>
#include <curl/curl.h>
#include <iostream>

#include "i2p.h"
#include "log.h"

LOG_CATEGORY(I2P)

namespace p2pool {

hash from_i2p_b32(const std::string& address)
{
	if ((address.length() < 8) || (address.find(".b32.i2p") != address.length() - 8)) {
		LOGWARN(3, "Invalid I2P address \"" << address << "\": doesn't end with \".b32.i2p\"");
		return {};
	}

	if (address.length() != 60) {
		LOGWARN(3, "Invalid I2P address \"" << address << "\": expected length 60, got " << address.length());
		return {};
	}

	size_t pos = address.find('.');
	const std::string dest_hash = address.substr(0, pos);
	const hash result = from_i2p_b32_const(dest_hash.c_str());

	if (result.empty()) {
		LOGWARN(3, "Invalid I2P address \"" << address << "\": has invalid character(s)");
		return {};
	}

	return result;
}

std::string to_i2p_b32(const hash& dest_hash)
{
	uint8_t buf[HASH_SIZE + 1];
	memcpy(buf, dest_hash.h, HASH_SIZE);
	buf[HASH_SIZE] = 0;

	std::string result;
	result.reserve(60);

	uint64_t data = 0;
	uint64_t bit_size = 0;

	for (size_t i = 0; i < HASH_SIZE + 1; ++i) {
		data = (data << 8) | buf[i];
		bit_size += 8;

		while (bit_size >= 5) {
			bit_size -= 5;
			result += "abcdefghijklmnopqrstuvwxyz234567"[(data >> bit_size) & 31];
		}
	}

	result.append(".b32.i2p");

	return result;
}

} // namespace p2pool
