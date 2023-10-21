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
#include "gtest/gtest.h"

namespace p2pool {

TEST(merkle, root_hash)
{
	hash input[5];
	uint8_t data[] = "data 0";

	for (size_t i = 0; i < 5; ++i, ++data[sizeof(data) - 2]) {
		keccak(data, sizeof(data) - 1, input[i].h);
	}

	hash root;
	std::vector<hash> hashes(1, input[0]);

	// 1 leaf
	merkle_hash(hashes, root);
	ASSERT_EQ(root, input[0]);

	// 2 leaves
	hashes.push_back(input[1]);
	merkle_hash(hashes, root);

	hash check[8];
	keccak(input[0].h, HASH_SIZE * 2, check[0].h);
	ASSERT_EQ(root, check[0]);

	// 3 leaves
	hashes.push_back(input[2]);
	merkle_hash(hashes, root);

	keccak(input[1].h, HASH_SIZE * 2, check[1].h);
	check[0] = input[0];
	keccak(check[0].h, HASH_SIZE * 2, check[0].h);
	ASSERT_EQ(root, check[0]);

	// 4 leaves
	hashes.push_back(input[3]);
	merkle_hash(hashes, root);

	keccak(input[0].h, HASH_SIZE * 2, check[0].h);
	keccak(input[2].h, HASH_SIZE * 2, check[1].h);
	keccak(check[0].h, HASH_SIZE * 2, check[0].h);
	ASSERT_EQ(root, check[0]);

	// 5 leaves
	hashes.push_back(input[4]);
	merkle_hash(hashes, root);

	check[0] = input[0];
	check[1] = input[1];
	check[2] = input[2];
	keccak(input[3].h, HASH_SIZE * 2, check[3].h);
	keccak(check[0].h, HASH_SIZE * 2, check[0].h);
	keccak(check[2].h, HASH_SIZE * 2, check[1].h);
	keccak(check[0].h, HASH_SIZE * 2, check[0].h);
	ASSERT_EQ(root, check[0]);
}

}
