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
#include "keccak.h"
#include "sha256.h"

namespace p2pool {

void merkle_hash(const std::vector<hash>& hashes, root_hash& root)
{
	const size_t count = hashes.size();
	const uint8_t* h = hashes[0].h;

	if (count == 1) {
		root = root_hash(hashes[0]);
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

void merkle_hash_full_tree(const std::vector<hash>& hashes, std::vector<std::vector<hash>>& tree)
{
	const size_t count = hashes.size();
	const uint8_t* h = hashes[0].h;

	tree.clear();

	if (count == 1) {
		tree.push_back(hashes);
	}
	else if (count == 2) {
		hash tmp;
		keccak(h, HASH_SIZE * 2, tmp.h);

		tree.reserve(2);
		tree.push_back(hashes);
		tree.emplace_back(1, tmp);
	}
	else {
		size_t cnt = 1, height = 1;
		do {
			cnt <<= 1;
			++height;
		} while (cnt <= count);
		cnt >>= 1;

		tree.reserve(height);
		tree.push_back(hashes);

		tree.emplace_back(cnt);
		{
			std::vector<hash>& cur = tree.back();

			const size_t k = cnt * 2 - count;
			memcpy(cur.data(), h, k * HASH_SIZE);

			for (size_t i = k, j = k; j < cnt; i += 2, ++j) {
				keccak(h + i * HASH_SIZE, HASH_SIZE * 2, cur[j].h);
			}
		}

		while (cnt > 1) {
			cnt >>= 1;

			tree.emplace_back(cnt);

			const std::vector<hash>& prev = tree[tree.size() - 2];
			std::vector<hash>& cur = tree[tree.size() - 1];

			cur.resize(cnt);

			for (size_t i = 0, j = 0; j < cnt; i += 2, ++j) {
				keccak(prev[i].h, HASH_SIZE * 2, cur[j].h);
			}
		}
	}
}

bool get_merkle_proof(const std::vector<std::vector<hash>>& tree, const hash& h, std::vector<hash>& proof, uint32_t& path)
{
	if (tree.empty()) {
		return false;
	}

	const std::vector<hash>& hashes = tree[0];
	const size_t count = hashes.size();

	size_t index = 0;

	while ((index < count) && (hashes[index] != h)) {
		++index;
	}

	if (index >= count) {
		return false;
	}

	proof.clear();
	path = 0;

	if (count == 1) {
		return true;
	}
	else if (count == 2) {
		proof.emplace_back(hashes[index ^ 1]);
		path = index & 1;
	}
	else {
		size_t cnt = 1;
		do { cnt <<= 1; } while (cnt <= count);
		cnt >>= 1;

		const size_t k = cnt * 2 - count;

		if (index >= k) {
			index -= k;
			const size_t j = (index ^ 1) + k;
			if (j >= count) {
				return false;
			}
			proof.emplace_back(hashes[j]);
			path = index & 1;
			index = (index >> 1) + k;
		}

		const size_t n = tree.size();

		for (size_t i = 1; cnt >= 2; ++i, index >>= 1, cnt >>= 1) {
			const size_t j = index ^ 1;
			if ((i >= n) || (j >= tree[i].size())) {
				return false;
			}
			proof.emplace_back(tree[i][j]);
			path = (static_cast<uint64_t>(path) << 1) | (index & 1);
		}
	}

	return true;
}

root_hash get_root_from_proof(hash h, const std::vector<hash>& proof, size_t index, size_t count)
{
	if (index >= count) {
		return root_hash();
	}

	if (count == 1) {
		return root_hash(h);
	}

	hash tmp[2];

	if (count == 2) {
		if (proof.empty()) {
			return root_hash();
		}

		if (index & 1) {
			tmp[0] = proof[0];
			tmp[1] = h;
		}
		else {
			tmp[0] = h;
			tmp[1] = proof[0];
		}

		keccak(tmp[0].h, HASH_SIZE * 2, h.h);
	}
	else {
		size_t cnt = 1;
		do { cnt <<= 1; } while (cnt <= count);
		cnt >>= 1;

		size_t proof_index = 0;

		const size_t k = cnt * 2 - count;

		if (index >= k) {
			index -= k;

			if (proof.empty()) {
				return root_hash();
			}

			if (index & 1) {
				tmp[0] = proof[0];
				tmp[1] = h;
			}
			else {
				tmp[0] = h;
				tmp[1] = proof[0];
			}

			keccak(tmp[0].h, HASH_SIZE * 2, h.h);

			index = (index >> 1) + k;
			proof_index = 1;
		}

		for (; cnt >= 2; ++proof_index, index >>= 1, cnt >>= 1) {
			if (proof_index >= proof.size()) {
				return root_hash();
			}

			if (index & 1) {
				tmp[0] = proof[proof_index];
				tmp[1] = h;
			}
			else {
				tmp[0] = h;
				tmp[1] = proof[proof_index];
			}

			keccak(tmp[0].h, HASH_SIZE * 2, h.h);
		}
	}

	return root_hash(h);
}

bool verify_merkle_proof(const hash& h, const std::vector<hash>& proof, size_t index, size_t count, const root_hash& root)
{
	return get_root_from_proof(h, proof, index, count) == root;
}

bool verify_merkle_proof(hash h, const std::vector<hash>& proof, uint32_t path, const root_hash& root)
{
	for (size_t d = 0, depth = proof.size(); d < depth; ++d) {
		hash tmp[2];

		if ((path >> (depth - d - 1)) & 1) {
			tmp[0] = proof[d];
			tmp[1] = h;
		}
		else {
			tmp[0] = h;
			tmp[1] = proof[d];
		}

		keccak(tmp[0].h, HASH_SIZE * 2, h.h);
	}

	return h == root;
}

uint32_t get_aux_slot(const hash &id, uint32_t nonce, uint32_t n_aux_chains)
{
	if (n_aux_chains <= 1) {
		return 0;
	}

	constexpr uint8_t HASH_KEY_MM_SLOT = 'm';

	uint8_t buf[HASH_SIZE + sizeof(uint32_t) + 1];

	memcpy(buf, &id, HASH_SIZE);
	memcpy(buf + HASH_SIZE, &nonce, sizeof(uint32_t));
	buf[HASH_SIZE + sizeof(uint32_t)] = HASH_KEY_MM_SLOT;

	hash res;
	sha256(buf, sizeof(buf), res.h);

	return *reinterpret_cast<uint32_t*>(res.h) % n_aux_chains;
}

bool find_aux_nonce(const std::vector<hash>& aux_id, uint32_t& nonce, uint32_t max_nonce)
{
	const uint32_t n_aux_chains = static_cast<uint32_t>(aux_id.size());

	if (n_aux_chains <= 1) {
		nonce = 0;
		return true;
	}

	std::vector<bool> slots;

	for (uint32_t i = 0;; ++i) {
		slots.assign(n_aux_chains, false);

		uint32_t j;
		for (j = 0; j < n_aux_chains; ++j) {
			const uint32_t k = get_aux_slot(aux_id[j], i, n_aux_chains);
			if (slots[k]) {
				break;
			}
			slots[k] = true;
		}

		if (j >= n_aux_chains) {
			nonce = i;
			return true;
		}

		if (i == max_nonce) {
			return false;
		}
	}
}

size_t get_position_from_path(size_t count, uint32_t path)
{
	if (count <= 1) {
		return 0;
	}

	size_t depth = 0;
	size_t k = 1;

	while (k < count) {
		++depth;
		k <<= 1;
	}

	k -= count;

	size_t pos = 0;

	for (size_t i = 1; i < depth; ++i) {
		pos = (pos << 1) | (path & 1);
		path >>= 1;
	}

	if (pos < k) {
		return pos;
	}

	return (((pos - k) << 1) | (path & 1)) + k;
}

} // namespace p2pool
