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
#include "merge_mining_client.h"
#include "merge_mining_client_json_rpc.h"

#if defined(WITH_GRPC) && !defined(P2POOL_UNIT_TESTS)
#include "merge_mining_client_tari.h"
#endif

#include "p2pool.h"
#include "params.h"
#include "pool_block.h"
#include "keccak_constexpr.h"
#include "side_chain.h"
#include "merkle.h"

static thread_local const char* log_category_prefix = "MergeMiningClient ";

namespace p2pool {

static constexpr hash Tari_ChainID{ "01f0cf665bd4cd31cbb2b2470236389c483522b350335e10a4a5dca34cb85990" };

IMergeMiningClient* IMergeMiningClient::create(p2pool* pool, const std::string& host, const std::string& wallet) noexcept
{
	try {
#if defined(WITH_GRPC) && !defined(P2POOL_UNIT_TESTS)
		if (host.find(MergeMiningClientTari::TARI_PREFIX) == 0) {
			return new MergeMiningClientTari(pool, host, wallet);
		}
#endif
		return new MergeMiningClientJSON_RPC(pool, host, wallet);
	}
	catch (...) {
		LOGERR(1, "Failed to create merge mining client for " << host);
	}
	return nullptr;
}

MergeMiningClientShared::MergeMiningClientShared(p2pool* pool, const std::string& wallet)
	: m_chainParamsLock{}
	, m_chainParams{}
	, m_chainParamsTimestamp(0)
	, m_auxWallet(wallet)
	, m_pool(pool)
	, m_previousAuxHashes{}
	, m_previousAuxHashesIndex(0)
	, m_previousAuxHashesFoundIndex(std::numeric_limits<uint32_t>::max())
{
	uv_rwlock_init_checked(&m_chainParamsLock);
}

MergeMiningClientShared::~MergeMiningClientShared()
{
	uv_rwlock_destroy(&m_chainParamsLock);
}

void MergeMiningClientShared::on_external_block(const PoolBlock& block)
{
#ifdef WITH_MERGE_MINING_DONATION
	// The rest of the code is needed only when this node is sending donation messages
	if (m_pool->params().m_authorKeyFile.empty()) {
		return;
	}

	const char* old_log_category_prefix = log_category_prefix;
	log_category_prefix = get_log_category();
	ON_SCOPE_LEAVE([old_log_category_prefix]() { log_category_prefix = old_log_category_prefix; });

	// Sanity check
	if (block.m_transactions.empty() || block.m_hashingBlob.empty() || (block.m_hashingBlob.size() > 128)) {
		LOGWARN(3, "on_external_block: sanity check failed - " << block.m_transactions.size() << " transactions, hashing blob size = " << block.m_hashingBlob.size());
		return;
	}

	ChainParameters chain_params;
	hash previous_aux_hashes[NUM_PREVIOUS_HASHES];
	{
		ReadLock lock(m_chainParamsLock);

		chain_params = m_chainParams;
		std::copy(m_previousAuxHashes, m_previousAuxHashes + NUM_PREVIOUS_HASHES, previous_aux_hashes);
	}

	// Don't continue if our aux chain is not there
	if (block.m_mergeMiningExtra.find(chain_params.aux_id) == block.m_mergeMiningExtra.end()) {
		return;
	}

	// All aux chains in this block + the P2Pool sidechain
	std::vector<hash> aux_ids;

	// All aux chains in this block
	std::vector<AuxChainData> aux_chains;

	aux_ids.reserve(block.m_mergeMiningExtra.size() + 1);
	aux_chains.reserve(block.m_mergeMiningExtra.size() + 1);

	uint64_t mm_extra_size = 0;

	for (const auto& i : block.m_mergeMiningExtra) {
		// Filter aux chain data only
		if ((i.first == keccak_subaddress_viewpub) || (i.first == keccak_onion_address_v3) || (i.first == keccak_i2p_b32_address)) {
			continue;
		}
		++mm_extra_size;

		hash data;
		difficulty_type diff;
		{
			const std::vector<uint8_t>& v = i.second;

			const uint8_t* p = v.data();
			const uint8_t* e = v.data() + v.size();

			if (p + HASH_SIZE > e) {
				LOGWARN(3, "on_external_block: sanity check failed - invalid merge mining extra data " << '1');
				return;
			}

			memcpy(data.h, p, HASH_SIZE);
			p += HASH_SIZE;

			p = readVarint(p, e, diff.lo);
			if (!p) {
				LOGWARN(3, "on_external_block: sanity check failed - invalid merge mining extra data " << '2');
				diff.lo = 0;
			}
			else {
				p = readVarint(p, e, diff.hi);
				if (!p) {
					LOGWARN(3, "on_external_block: sanity check failed - invalid merge mining extra data " << '3');
					diff.hi = 0;
				}
			}
		}

		// If it's our aux chain, check that it's the same job and that there is enough PoW
		if (i.first == chain_params.aux_id) {
			const bool different_hash = (data != chain_params.aux_hash);

			if (different_hash || (diff != chain_params.aux_diff)) {
				uint32_t index = std::numeric_limits<uint32_t>::max();

				if (different_hash) {
					for (uint32_t k = 0; k < NUM_PREVIOUS_HASHES; ++k) {
						if (previous_aux_hashes[k] == data) {
							index = k;
							break;
						}
					}
				}

				m_previousAuxHashesFoundIndex = index;

				if (different_hash && (index == std::numeric_limits<uint32_t>::max())) {
					LOGINFO(4, "External aux job solution found, but it's for another miner");
					return;
				}

				LOGINFO(4, "External aux job solution found, but it's stale");
				chain_params.aux_hash = data;
				chain_params.aux_diff = diff;
			}
			else {
				m_previousAuxHashesFoundIndex = std::numeric_limits<uint32_t>::max();
			}

			if (!diff.check_pow(block.m_powHash)) {
#ifndef P2POOL_LOG_DISABLE
				const char* name = ((chain_params.aux_id == Tari_ChainID) ? "Tari" : "aux");
#endif
				LOGINFO(4, "External aux job solution found, but it doesn't have enough PoW (block diff = " << block.m_difficulty << ", " << name << " diff = " << diff << ')');
				return;
			}
		}

		aux_ids.emplace_back(i.first);
		aux_chains.emplace_back(i.first, data, diff);
	}

	aux_ids.emplace_back(m_pool->side_chain().consensus_hash());

	LOGINFO(0, log::LightGreen() << "External aux job solution found. Processing it!");

	// coinbase_merkle_proof
	root_hash root;
	std::vector<hash> proof;
	uint32_t path;

#ifdef WITH_INDEXED_HASHES
	std::vector<hash> transactions;
	transactions.reserve(block.m_transactions.size());

	for (const auto& h : block.m_transactions) {
		transactions.emplace_back(h);
	}
#else
	const std::vector<hash>& transactions = block.m_transactions;
#endif

	if (!merkle_hash_with_proof(transactions, 0, proof, path, root)) {
		LOGWARN(3, "on_external_block: merkle_hash_with_proof failed for coinbase transaction");
		return;
	}

	if (!verify_merkle_proof(transactions[0], proof, path, root)) {
		LOGWARN(3, "on_external_block: verify_merkle_proof failed for coinbase transaction");
		return;
	}

	std::vector<uint8_t> coinbase_merkle_proof;
	coinbase_merkle_proof.reserve(proof.size() * HASH_SIZE);

	for (const hash& h : proof) {
		coinbase_merkle_proof.insert(coinbase_merkle_proof.end(), h.h, h.h + HASH_SIZE);
	}

	// hashing_blob

	uint8_t hashing_blob[128] = {};
	memcpy(hashing_blob, block.m_hashingBlob.data(), block.m_hashingBlob.size());

	// nonce_offset and blob

	size_t header_size = 0;
	const std::vector<uint8_t> blob = block.serialize_mainchain_data(&header_size);

	if (header_size <= NONCE_SIZE) {
		LOGWARN(3, "on_external_block: invalid header_size");
		return;
	}

	const uint32_t nonce_offset = static_cast<uint32_t>(header_size - NONCE_SIZE);

	// aux_merkle_proof, aux_merkle_proof_path

	std::vector<hash> aux_merkle_proof;
	uint32_t aux_merkle_proof_path = 0;

	const hash sidechain_id = block.m_sidechainId;
	const uint32_t n_aux_chains = static_cast<uint32_t>(mm_extra_size + 1);

	std::vector<hash> hashes(n_aux_chains);

	uint32_t aux_nonce;
	if (!find_aux_nonce(aux_ids, aux_nonce, 1000)) {
		LOGWARN(3, "on_external_block: failed to find aux_nonce");
		return;
	}

	for (const AuxChainData& aux_data : aux_chains) {
		const uint32_t aux_slot = get_aux_slot(aux_data.unique_id, aux_nonce, n_aux_chains);

		if (!hashes[aux_slot].empty()) {
			LOGWARN(3, "on_external_block: found an incorrect aux_nonce " << '1');
			return;
		}

		hashes[aux_slot] = aux_data.data;
	}

	const uint32_t aux_slot = get_aux_slot(m_pool->side_chain().consensus_hash(), aux_nonce, n_aux_chains);

	if (!hashes[aux_slot].empty()) {
		LOGWARN(3, "on_external_block: found an incorrect aux_nonce " << '2');
		return;
	}

	hashes[aux_slot] = sidechain_id;

	if (!merkle_hash_with_proof(hashes, chain_params.aux_hash, aux_merkle_proof, aux_merkle_proof_path, root)) {
		LOGWARN(3, "on_external_block: merkle_hash_with_proof failed for the aux hash");
		return;
	}

	if (root != block.m_merkleRoot) {
		LOGWARN(3, "on_external_block: merkle root didn't match");
		return;
	}

	if (!verify_merkle_proof(chain_params.aux_hash, aux_merkle_proof, aux_merkle_proof_path, root)) {
		LOGWARN(3, "on_external_block: verify_merkle_proof failed for the aux hash");
		return;
	}

	submit_solution(coinbase_merkle_proof, hashing_blob, nonce_offset, block.m_seed, blob, aux_merkle_proof, aux_merkle_proof_path);
#else // WITH_MERGE_MINING_DONATION
	(void)block;
#endif // WITH_MERGE_MINING_DONATION
}

} // namespace p2pool
