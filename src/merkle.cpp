/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2023 SChernykh <https://github.com/SChernykh>
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
#include "keccak.h"
#include "merkle.h"

namespace p2pool {

void merkle_hash(const std::vector<hash>& hashes, hash& root)
{
	const size_t count = hashes.size();
	const uint8_t* h = hashes[0].h;

	if (count == 1) {
		root = hashes[0];
	}
	else if (count == 2) {
		keccak(h, HASH_SIZE * 2, root.h);
	}
	else {
		size_t cnt = 1;
		do { cnt <<= 1; } while (cnt <= count);
		cnt >>= 1;

		std::vector<hash> tmp_ints(cnt);

		const size_t k = cnt * 2 - count;
		memcpy(tmp_ints.data(), h, k * HASH_SIZE);

		for (size_t i = k, j = k; j < cnt; i += 2, ++j) {
			keccak(h + i * HASH_SIZE, HASH_SIZE * 2, tmp_ints[j].h);
		}

		while (cnt > 2) {
			cnt >>= 1;
			for (size_t i = 0, j = 0; j < cnt; i += 2, ++j) {
				keccak(tmp_ints[i].h, HASH_SIZE * 2, tmp_ints[j].h);
			}
		}

		keccak(tmp_ints[0].h, HASH_SIZE * 2, root.h);
	}
}

} // namespace p2pool
