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
#include "blake2/blake2.h"

extern "C" {
#include "crypto-ops.h"
}

namespace p2pool {

namespace carrot {

bool hash_to_bytes(const void* input, size_t in_len, void* output, size_t out_len, const void* key)
{
	if (!input || !output || (out_len > BLAKE2B_OUTBYTES)) {
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

	if (!hash_to_bytes(data, data_length, buf, 64, key)) {
		return false;
	}

	sc_reduce(buf);
	memcpy(hash_out, buf, 32);

	return true;
}

} // namespace carrot

} // namespace p2pool
