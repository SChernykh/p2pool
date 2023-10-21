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
	hash input[10];
	uint8_t data[] = "data 0";

	for (size_t i = 0; i < 10; ++i, ++data[sizeof(data) - 2]) {
		keccak(data, sizeof(data) - 1, input[i].h);
	}

	hash root;
	std::vector<hash> hashes(1, input[0]);

	auto check_full_tree = [&hashes, &root]() {
		std::vector<std::vector<hash>> tree;
		merkle_hash_full_tree(hashes, tree);

		ASSERT_GE(tree.size(), 1);

		const std::vector<hash>& tree_root = tree.back();
		ASSERT_EQ(tree_root.size(), 1);
		ASSERT_EQ(tree_root[0], root);

		ASSERT_EQ(tree[0], hashes);

		if (tree.size() > 1) {
			ASSERT_LE(tree[1].size(), hashes.size());
			ASSERT_GE(tree[1].size() * 2, hashes.size());

			const size_t spill_size = tree[1].size() * 2 - hashes.size();
			for (size_t i = 0; i < spill_size; ++i) {
				ASSERT_EQ(tree[1][i], hashes[i]);
			}
			for (size_t i = spill_size, j = spill_size; i < tree[1].size(); ++i, j += 2) {
				hash tmp;
				keccak(hashes[j].h, HASH_SIZE * 2, tmp.h);
				ASSERT_EQ(tmp, tree[1][i]);
			}
		}

		for (size_t i = tree.size() - 1; i > 1; --i) {
			ASSERT_EQ(tree[i].size() * 2, tree[i - 1].size());
			for (size_t j = 0; j < tree[i].size(); ++j) {
				hash tmp;
				keccak(tree[i - 1][j * 2].h, HASH_SIZE * 2, tmp.h);
				ASSERT_EQ(tmp, tree[i][j]);
			}
		}
	};

	// 1 leaf
	merkle_hash(hashes, root);
	ASSERT_EQ(root, input[0]);
	check_full_tree();

	// 2 leaves
	hashes.push_back(input[1]);
	merkle_hash(hashes, root);

	hash check[8];
	keccak(input[0].h, HASH_SIZE * 2, check[0].h);
	ASSERT_EQ(root, check[0]);
	check_full_tree();

	// 3 leaves
	hashes.push_back(input[2]);
	merkle_hash(hashes, root);

	keccak(input[1].h, HASH_SIZE * 2, check[1].h);
	check[0] = input[0];
	keccak(check[0].h, HASH_SIZE * 2, check[0].h);
	ASSERT_EQ(root, check[0]);
	check_full_tree();

	// 4 leaves
	hashes.push_back(input[3]);
	merkle_hash(hashes, root);

	keccak(input[0].h, HASH_SIZE * 2, check[0].h);
	keccak(input[2].h, HASH_SIZE * 2, check[1].h);
	keccak(check[0].h, HASH_SIZE * 2, check[0].h);
	ASSERT_EQ(root, check[0]);
	check_full_tree();

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
	check_full_tree();

	// 6 leaves
	hashes.push_back(input[5]);
	merkle_hash(hashes, root);

	check[0] = input[0];
	check[1] = input[1];
	keccak(input[2].h, HASH_SIZE * 2, check[2].h);
	keccak(input[4].h, HASH_SIZE * 2, check[3].h);
	keccak(check[0].h, HASH_SIZE * 2, check[0].h);
	keccak(check[2].h, HASH_SIZE * 2, check[1].h);
	keccak(check[0].h, HASH_SIZE * 2, check[0].h);
	ASSERT_EQ(root, check[0]);
	check_full_tree();

	// 7 leaves
	hashes.push_back(input[6]);
	merkle_hash(hashes, root);

	check[0] = input[0];
	keccak(input[1].h, HASH_SIZE * 2, check[1].h);
	keccak(input[3].h, HASH_SIZE * 2, check[2].h);
	keccak(input[5].h, HASH_SIZE * 2, check[3].h);
	keccak(check[0].h, HASH_SIZE * 2, check[0].h);
	keccak(check[2].h, HASH_SIZE * 2, check[1].h);
	keccak(check[0].h, HASH_SIZE * 2, check[0].h);
	ASSERT_EQ(root, check[0]);
	check_full_tree();

	// 8 leaves
	hashes.push_back(input[7]);
	merkle_hash(hashes, root);

	keccak(input[0].h, HASH_SIZE * 2, check[0].h);
	keccak(input[2].h, HASH_SIZE * 2, check[1].h);
	keccak(input[4].h, HASH_SIZE * 2, check[2].h);
	keccak(input[6].h, HASH_SIZE * 2, check[3].h);
	keccak(check[0].h, HASH_SIZE * 2, check[0].h);
	keccak(check[2].h, HASH_SIZE * 2, check[1].h);
	keccak(check[0].h, HASH_SIZE * 2, check[0].h);
	ASSERT_EQ(root, check[0]);
	check_full_tree();

	// 9 leaves
	hashes.push_back(input[8]);
	merkle_hash(hashes, root);

	for (size_t i = 0; i < 7; ++i) {
		check[i] = input[i];
	}
	keccak(input[7].h, HASH_SIZE * 2, check[7].h);

	keccak(check[0].h, HASH_SIZE * 2, check[0].h);
	keccak(check[2].h, HASH_SIZE * 2, check[1].h);
	keccak(check[4].h, HASH_SIZE * 2, check[2].h);
	keccak(check[6].h, HASH_SIZE * 2, check[3].h);

	keccak(check[0].h, HASH_SIZE * 2, check[0].h);
	keccak(check[2].h, HASH_SIZE * 2, check[1].h);

	keccak(check[0].h, HASH_SIZE * 2, check[0].h);

	ASSERT_EQ(root, check[0]);
	check_full_tree();

	// 10 leaves
	hashes.push_back(input[9]);
	merkle_hash(hashes, root);

	for (size_t i = 0; i < 6; ++i) {
		check[i] = input[i];
	}
	keccak(input[6].h, HASH_SIZE * 2, check[6].h);
	keccak(input[8].h, HASH_SIZE * 2, check[7].h);

	keccak(check[0].h, HASH_SIZE * 2, check[0].h);
	keccak(check[2].h, HASH_SIZE * 2, check[1].h);
	keccak(check[4].h, HASH_SIZE * 2, check[2].h);
	keccak(check[6].h, HASH_SIZE * 2, check[3].h);

	keccak(check[0].h, HASH_SIZE * 2, check[0].h);
	keccak(check[2].h, HASH_SIZE * 2, check[1].h);

	keccak(check[0].h, HASH_SIZE * 2, check[0].h);

	ASSERT_EQ(root, check[0]);
	check_full_tree();
}

}
