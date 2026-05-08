/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2026 SChernykh <https://github.com/SChernykh>
 *
 * SPDX-License-Identifier: GPL-3.0-only OR BSD-3-Clause
 *
 * This file may be used under the terms of either:
 *
 *   (1) the GNU General Public License version 3
 *
 *   or
 *
 *   (2) the BSD 3-Clause License
 *
 * at your option.
 *
 * --------------------------------------------------------------------
 * GNU GENERAL PUBLIC LICENSE VERSION 3
 * --------------------------------------------------------------------
 *
 * See LICENSE file in the root of this repository
 *
 * --------------------------------------------------------------------
 * BSD 3-CLAUSE LICENSE
 * --------------------------------------------------------------------
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */

namespace p2pool {

static FORCEINLINE constexpr hash from_onion_v3_const(const char* address)
{
	uint8_t buf[HASH_SIZE + 4] = {};
	uint8_t* p = buf;

	uint64_t data = 0;
	uint64_t bit_size = 0;

	for (size_t i = 0; i < 56; ++i) {
		const char c = address[i];
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

} // namespace p2pool
