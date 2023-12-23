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

#pragma once

namespace p2pool {

void merkle_hash(const std::vector<hash>& hashes, root_hash& root);
void merkle_hash_full_tree(const std::vector<hash>& hashes, std::vector<std::vector<hash>>& tree);

bool get_merkle_proof(const std::vector<std::vector<hash>>& tree, const hash& h, std::vector<hash>& proof);

root_hash get_root_from_proof(hash h, const std::vector<hash>& proof, size_t index, size_t count);
bool verify_merkle_proof(hash h, const std::vector<hash>& proof, size_t index, size_t count, const root_hash& root);

uint32_t get_aux_slot(const hash &id, uint32_t nonce, uint32_t n_aux_chains);
bool find_aux_nonce(const std::vector<hash>& aux_id, uint32_t& nonce, uint32_t max_nonce = 0xFFFF);

} // namespace p2pool
