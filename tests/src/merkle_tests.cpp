/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2024 SChernykh <https://github.com/SChernykh>
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
#include "pool_block.h"
#include "side_chain.h"
#include "keccak.h"
#include "gtest/gtest.h"

namespace p2pool {

// Original Monero's tree_path function to test against

size_t tree_hash_cnt(size_t count) {
	size_t pow = 2;
	while(pow < count) pow <<= 1;
	return pow >> 1;
}

bool tree_path(size_t count, size_t idx, uint32_t* path)
{
	if (count == 0)
		return false;

	if (count == 1) {
		*path = 0;
	}
	else if (count == 2) {
		*path = idx == 0 ? 0 : 1;
	}
	else {
		size_t i, j;

		*path = 0;
		size_t cnt = tree_hash_cnt(count);

		for (i = 2 * cnt - count, j = 2 * cnt - count; j < cnt; i += 2, ++j) {
			if (idx == i || idx == i + 1)
			{
				*path = (*path << 1) | (idx == i ? 0 : 1);
				idx = j;
			}
		}
		assert(i == count);

		while (cnt > 2) {
			cnt >>= 1;
			for (i = 0, j = 0; j < cnt; i += 2, ++j) {
				if (idx == i || idx == i + 1)
				{
					*path = (*path << 1) | (idx == i ? 0 : 1);
					idx = j;
				}
			}
		}

		if (idx == 0 || idx == 1)
		{
			*path = (*path << 1) | (idx == 0 ? 0 : 1);
			idx = 0;
		}
	}
	return true;
}

TEST(merkle, tree)
{
	hash input[10];
	uint8_t data[] = "data 0";

	for (size_t i = 0; i < 10; ++i, ++data[sizeof(data) - 2]) {
		keccak(data, sizeof(data) - 1, input[i].h);
	}

	root_hash root;
	std::vector<hash> hashes(1, input[0]);

	auto check_full_tree = [&hashes, &root]() {
		std::vector<std::vector<hash>> tree;

		{
			hash h;
			std::vector<hash> proof;
			uint32_t path;

			ASSERT_FALSE(get_merkle_proof(tree, h, proof, path));
		}

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

		const hash empty_hash;

		for (size_t i = 0, n = hashes.size(); i < n; ++i) {
			const hash& h = hashes[i];
			std::vector<hash> proof;
			uint32_t path;

			ASSERT_TRUE(get_merkle_proof(tree, h, proof, path));
			ASSERT_FALSE(get_merkle_proof(tree, empty_hash, proof, path));

			uint32_t path_monero;
			ASSERT_TRUE(tree_path(n, i, &path_monero));
			ASSERT_EQ(path, path_monero);

			ASSERT_TRUE(verify_merkle_proof(h, proof, i, n, root));
			ASSERT_TRUE(verify_merkle_proof(h, proof, path, root));

			ASSERT_FALSE(verify_merkle_proof(h, proof, n, n, root));
			ASSERT_FALSE(verify_merkle_proof(empty_hash, proof, i, n, root));
			ASSERT_FALSE(verify_merkle_proof(empty_hash, proof, path, root));

			while (!proof.empty()) {
				proof.pop_back();

				ASSERT_FALSE(verify_merkle_proof(h, proof, i, n, root));
				ASSERT_FALSE(verify_merkle_proof(h, proof, path, root));
			}

			ASSERT_EQ(get_position_from_path(n, path), i);
		}
	};

	// 0 leaves
	uint32_t path_monero;
	ASSERT_FALSE(tree_path(0, 0, &path_monero));

	merkle_hash(std::vector<hash>(), root);
	ASSERT_TRUE(root.empty());

	std::vector<std::vector<hash>> tree;
	merkle_hash_full_tree(std::vector<hash>(), tree);
	ASSERT_TRUE(tree.empty());

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

TEST(merkle, aux_slot)
{
	hash id;

	ASSERT_EQ(get_aux_slot(id, 0, 0), 0U);
	ASSERT_EQ(get_aux_slot(id, 0, 1), 0U);
	ASSERT_EQ(get_aux_slot(id, 0, 2), 0U);
	ASSERT_EQ(get_aux_slot(id, 0, 3), 0U);
	ASSERT_EQ(get_aux_slot(id, 0, 4), 0U);
	ASSERT_EQ(get_aux_slot(id, 0, 5), 1U);
	ASSERT_EQ(get_aux_slot(id, 0, 6), 0U);
	ASSERT_EQ(get_aux_slot(id, 0, 7), 5U);
	ASSERT_EQ(get_aux_slot(id, 0, 8), 0U);
	ASSERT_EQ(get_aux_slot(id, 0, 9), 6U);

	ASSERT_EQ(get_aux_slot(id, 0, std::numeric_limits<uint32_t>::max()), 2389612776U);
	ASSERT_EQ(get_aux_slot(id, 1, std::numeric_limits<uint32_t>::max()), 1080669337U);
}

TEST(merkle, aux_nonce)
{
	std::vector<hash> aux_id;
	uint32_t nonce;

	ASSERT_TRUE(find_aux_nonce(aux_id, nonce));
	ASSERT_EQ(nonce, 0U);

	uint8_t data[] = "aux0";

	const uint32_t nonces[] = { 0, 0, 0, 7, 16, 56, 1, 287, 1423, 1074 };
	hash h;

	for (size_t i = 0; i < 10; ++i, ++data[sizeof(data) - 2]) {
		keccak(data, sizeof(data) - 1, h.h);
		aux_id.push_back(h);

		ASSERT_TRUE(find_aux_nonce(aux_id, nonce));
		ASSERT_EQ(nonce, nonces[i]);
	}

	h = aux_id.front();

	aux_id.clear();
	aux_id.push_back(h);
	aux_id.push_back(h);

	ASSERT_FALSE(find_aux_nonce(aux_id, nonce));
}

TEST(merkle, params)
{
	ASSERT_EQ(PoolBlock::encode_merkle_tree_data(1, 0), 0U);
	ASSERT_EQ(PoolBlock::encode_merkle_tree_data(1, 0xFFFFFFFFU), 0xFFFFFFFF0ULL);
	ASSERT_EQ(PoolBlock::encode_merkle_tree_data(127, 0), 0x3F6U);
	ASSERT_EQ(PoolBlock::encode_merkle_tree_data(127, 0xFFFFFFFFU), 0x3FFFFFFFFF6ULL);
	ASSERT_EQ(PoolBlock::encode_merkle_tree_data(256, 0), 0x7FFU);
	ASSERT_EQ(PoolBlock::encode_merkle_tree_data(256, 0xFFFFFFFFU), 0x7FFFFFFFFFFULL);

	PoolBlock b;
	uint32_t n1, nonce1;

	b.m_merkleTreeData = 0;
	b.decode_merkle_tree_data(n1, nonce1);
	ASSERT_TRUE(n1 == 1 && nonce1 == 0);

	b.m_merkleTreeData = 0xFFFFFFFF0ULL;
	b.decode_merkle_tree_data(n1, nonce1);
	ASSERT_TRUE(n1 == 1 && nonce1 == 0xFFFFFFFFU);

	b.m_merkleTreeData = 0x3F6U;
	b.decode_merkle_tree_data(n1, nonce1);
	ASSERT_TRUE(n1 == 127 && nonce1 == 0);

	b.m_merkleTreeData = 0x3FFFFFFFFF6ULL;
	b.decode_merkle_tree_data(n1, nonce1);
	ASSERT_TRUE(n1 == 127 && nonce1 == 0xFFFFFFFFU);

	b.m_merkleTreeData = 0x7FFU;
	b.decode_merkle_tree_data(n1, nonce1);
	ASSERT_TRUE(n1 == 256 && nonce1 == 0);

	b.m_merkleTreeData = 0x7FFFFFFFFFFULL;
	b.decode_merkle_tree_data(n1, nonce1);
	ASSERT_TRUE(n1 == 256 && nonce1 == 0xFFFFFFFFU);

	for (uint32_t n_aux_chains = 1; n_aux_chains <= 256; ++n_aux_chains) {
		for (uint32_t nonce = 1; nonce; nonce <<= 1) {
			for (uint32_t i = 0; i <= 1; ++i) {
				b.m_merkleTreeData = PoolBlock::encode_merkle_tree_data(n_aux_chains, nonce - i);
				b.decode_merkle_tree_data(n1, nonce1);
				ASSERT_EQ(n1, n_aux_chains);
				ASSERT_EQ(nonce1, nonce - i);
			}
		}
	}
}

}
