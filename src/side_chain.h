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
#include "pool_block.h"
#include <map>
#include <thread>

namespace p2pool {

class p2pool;
class P2PServer;

struct MinerShare
{
	FORCEINLINE MinerShare() : m_weight(), m_wallet(nullptr) {}
	FORCEINLINE MinerShare(const difficulty_type& w, const Wallet* x) : m_weight(w), m_wallet(x) {}

	FORCEINLINE bool operator==(const MinerShare& s) const { return *m_wallet == *s.m_wallet; }

	difficulty_type m_weight;
	const Wallet* m_wallet;
};

class SideChain : public nocopy_nomove
{
public:
	SideChain(p2pool* pool, NetworkType type, const char* pool_name = nullptr);
	~SideChain();

	void fill_sidechain_data(PoolBlock& block, std::vector<MinerShare>& shares) const;

	bool incoming_block_seen(const PoolBlock& block);
	void forget_incoming_block(const PoolBlock& block);
	void cleanup_incoming_blocks();

	bool add_external_block(PoolBlock& block, std::vector<hash>& missing_blocks);
	bool add_block(const PoolBlock& block);
	void get_missing_blocks(unordered_set<hash>& missing_blocks) const;

	PoolBlock* find_block(const hash& id) const;
	PoolBlock* find_block_by_merkle_root(const root_hash& merkle_root) const;
	void watch_mainchain_block(const ChainMain& data, const hash& possible_merkle_root);

	const PoolBlock* get_block_blob(const hash& id, std::vector<uint8_t>& blob) const;
	bool get_outputs_blob(PoolBlock* block, uint64_t total_reward, std::vector<uint8_t>& blob, uv_loop_t* loop) const;

	void print_status(bool obtain_sidechain_lock = true) const;
	double get_reward_share(const Wallet& w) const;

	// Consensus ID can be used to spawn independent P2Pools with their own sidechains
	// It's never sent over the network to avoid revealing it to the possible man in the middle
	// Consensus ID can therefore be used as a password to create private P2Pools
	const std::vector<uint8_t>& consensus_id() const { return m_consensusId; }
	const hash& consensus_hash() const { return m_consensusHash; }
	uint64_t chain_window_size() const { return m_chainWindowSize; }
	static NetworkType network_type() { return s_networkType; }
	static uint64_t network_major_version(uint64_t height);
	FORCEINLINE difficulty_type difficulty() const { ReadLock lock(m_curDifficultyLock); return m_curDifficulty; }
	difficulty_type total_hashes() const;
	uint64_t block_time() const { return m_targetBlockTime; }
	uint64_t miner_count();
	uint64_t last_updated() const;
	bool is_default() const;
	bool is_mini() const;
	uint64_t bottom_height(const PoolBlock* tip) const;

	const PoolBlock* chainTip() const { return m_chainTip; }
	bool precalcFinished() const { return m_precalcFinished.load(); }

	bool p2pool_update_available() const;

#ifdef P2POOL_UNIT_TESTS
	difficulty_type m_testMainChainDiff;
	const unordered_map<hash, PoolBlock*>& blocksById() const { return m_blocksById; }
#endif

	static bool split_reward(uint64_t reward, const std::vector<MinerShare>& shares, std::vector<uint64_t>& rewards);

private:
	p2pool* m_pool;
	P2PServer* p2pServer() const;
	static NetworkType s_networkType;

private:
	bool get_shares(const PoolBlock* tip, std::vector<MinerShare>& shares, uint64_t* bottom_height = nullptr, bool quiet = false) const;
	bool get_difficulty(const PoolBlock* tip, std::vector<DifficultyData>& difficultyData, difficulty_type& curDifficulty) const;
	void verify_loop(PoolBlock* block);
	void verify(PoolBlock* block);
	void update_chain_tip(const PoolBlock* block);
	PoolBlock* get_parent(const PoolBlock* block) const;

	// Checks if "candidate" has longer (higher difficulty) chain than "block"
	bool is_longer_chain(const PoolBlock* block, const PoolBlock* candidate, bool& is_alternative) const;
	void update_depths(PoolBlock* block);
	void prune_old_blocks();

	bool load_config(const std::string& filename);
	bool check_config() const;

	mutable uv_rwlock_t m_sidechainLock;
	std::atomic<PoolBlock*> m_chainTip;
	std::map<uint64_t, std::vector<PoolBlock*>> m_blocksByHeight;
	unordered_map<hash, PoolBlock*> m_blocksById;
	unordered_map<root_hash, PoolBlock*> m_blocksByMerkleRoot;

	uv_mutex_t m_seenWalletsLock;
	unordered_map<hash, uint64_t> m_seenWallets;
	uint64_t m_seenWalletsLastPruneTime;

	// Used to quickly cut off multiple broadcasts of the same block by different peers. Only the first broadcast will be processed.
	uv_mutex_t m_incomingBlocksLock;
	unordered_map<PoolBlock::full_id, uint64_t> m_incomingBlocks;

	std::vector<DifficultyData> m_difficultyData;

	std::string m_poolName;
	std::string m_poolPassword;
	uint64_t m_targetBlockTime;
	difficulty_type m_minDifficulty;
	uint64_t m_chainWindowSize;
	uint64_t m_unclePenalty;

	std::vector<uint8_t> m_consensusId;
	std::string m_consensusIdDisplayStr;

	mutable uv_rwlock_t m_curDifficultyLock;
	difficulty_type m_curDifficulty;

	ChainMain m_watchBlock;
	hash m_watchBlockMerkleRoot;

	struct PrecalcJob
	{
		const PoolBlock* b;
		std::vector<MinerShare> shares;
	};

	uv_cond_t m_precalcJobsCond;
	uv_mutex_t m_precalcJobsMutex;

	std::vector<PrecalcJob*> m_precalcJobs;
	std::vector<std::thread> m_precalcWorkers;
	unordered_set<size_t>* m_uniquePrecalcInputs;

	std::atomic<bool> m_precalcFinished;

#ifdef DEV_TEST_SYNC
	uint64_t m_firstPruneTime;
#endif

	hash m_consensusHash;

	void launch_precalc(const PoolBlock* block);
	void precalc_worker();
	void finish_precalc();
};

} // namespace p2pool

namespace robin_hood {

	template<>
	struct hash<p2pool::MinerShare>
	{
		FORCEINLINE size_t operator()(const p2pool::MinerShare& value) const noexcept
		{
			return hash_bytes(value.m_wallet->spend_public_key().h, p2pool::HASH_SIZE);
		}
	};

} // namespace robin_hood
