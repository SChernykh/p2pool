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

#include "uv_util.h"

#define TEST_MEMPOOL_PICKING_ALGORITHM 0

namespace p2pool {

class SideChain;
class RandomX_Hasher_Base;
class Mempool;
class Wallet;
struct PoolBlock;
struct MinerShare;

class BlockTemplate
{
public:
	explicit BlockTemplate(SideChain* sidechain, RandomX_Hasher_Base* hasher);
	~BlockTemplate();

	BlockTemplate(const BlockTemplate& b);
	BlockTemplate& operator=(const BlockTemplate& b);

	void update(const MinerData& data, const Mempool& mempool, Wallet* miner_wallet);
	uint64_t last_updated() const { return m_lastUpdated.load(); }

	bool get_difficulties(const uint32_t template_id, uint64_t& height, uint64_t& sidechain_height, difficulty_type& mainchain_difficulty, difficulty_type& sidechain_difficulty) const;
	uint32_t get_hashing_blob(const uint32_t template_id, uint32_t extra_nonce, uint8_t (&blob)[128], uint64_t& height, difficulty_type& difficulty, difficulty_type& sidechain_difficulty, hash& seed_hash, size_t& nonce_offset) const;

	uint32_t get_hashing_blob(uint32_t extra_nonce, uint8_t (&blob)[128], uint64_t& height, uint64_t& sidechain_height, difficulty_type& difficulty, difficulty_type& sidechain_difficulty, hash& seed_hash, size_t& nonce_offset, uint32_t& template_id) const;
	uint32_t get_hashing_blobs(uint32_t extra_nonce_start, uint32_t count, std::vector<uint8_t>& blobs, uint64_t& height, difficulty_type& difficulty, difficulty_type& sidechain_difficulty, hash& seed_hash, size_t& nonce_offset, uint32_t& template_id) const;

	std::vector<uint8_t> get_block_template_blob(uint32_t template_id, size_t& nonce_offset, size_t& extra_nonce_offset) const;

	FORCEINLINE uint64_t height() const { return m_height; }
	FORCEINLINE difficulty_type difficulty() const { return m_difficulty; }

	bool submit_sidechain_block(uint32_t template_id, uint32_t nonce, uint32_t extra_nonce);

	FORCEINLINE const std::vector<MinerShare>& shares() const { return m_shares; }

#ifdef P2POOL_UNIT_TESTS
	FORCEINLINE const PoolBlock* pool_block_template() const { return m_poolBlockTemplate; }
	FORCEINLINE std::mt19937_64& rng() { return m_rng; }
#endif

private:
	SideChain* m_sidechain;
	RandomX_Hasher_Base* m_hasher;

private:
	int create_miner_tx(const MinerData& data, const std::vector<MinerShare>& shares, uint64_t max_reward_amounts_weight, bool dry_run);
	hash calc_sidechain_hash(uint32_t sidechain_extra_nonce) const;
	hash calc_miner_tx_hash(uint32_t extra_nonce) const;
	void calc_merkle_tree_main_branch();

	uint32_t get_hashing_blob_nolock(uint32_t extra_nonce, uint8_t* blob) const;

	mutable uv_rwlock_t m_lock;

	uint32_t m_templateId;
	std::atomic<uint64_t> m_lastUpdated;

	std::vector<uint8_t> m_blockTemplateBlob;
	std::vector<uint8_t> m_fullDataBlob;
	std::vector<uint8_t> m_merkleTreeMainBranch;

	size_t m_blockHeaderSize;
	size_t m_minerTxOffsetInTemplate;
	size_t m_minerTxSize;
	size_t m_nonceOffset;
	size_t m_extraNonceOffsetInTemplate;

	size_t m_numTransactionHashes;
	hash m_prevId;
	std::atomic<uint64_t> m_height;
	difficulty_type m_difficulty;
	hash m_seedHash;

	uint64_t m_timestamp;

	PoolBlock* m_poolBlockTemplate;

	BlockTemplate* m_oldTemplates[4] = {};

	uint64_t m_finalReward;

	// Temp vectors, will be cleaned up after use and skipped in copy constructor/assignment operators
	std::vector<uint8_t> m_minerTx;
	uint64_t m_minerTxKeccakState[25];
	size_t m_minerTxKeccakStateInputLength;

	std::vector<uint8_t> m_sidechainHashBlob;
	uint64_t m_sidechainHashKeccakState[25];
	size_t m_sidechainHashInputLength;

	std::vector<uint8_t> m_blockHeader;
	std::vector<uint8_t> m_minerTxExtra;
	std::vector<uint8_t> m_transactionHashes;
	unordered_set<hash> m_transactionHashesSet;
	std::vector<uint64_t> m_rewards;
	std::vector<TxMempoolData> m_mempoolTxs;
	std::vector<int> m_mempoolTxsOrder;
	std::vector<int> m_mempoolTxsOrder2;
	std::vector<MinerShare> m_shares;

	std::mt19937_64 m_rng;

	void shuffle_tx_order();

#if TEST_MEMPOOL_PICKING_ALGORITHM
	void fill_optimal_knapsack(const MinerData& data, uint64_t base_reward, uint64_t miner_tx_weight, uint64_t& best_reward, uint64_t& final_fees, uint64_t& final_weight);

	std::vector<uint32_t> m_knapsack;
#endif
};

} // namespace p2pool
