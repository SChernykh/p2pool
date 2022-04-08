/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2022 SChernykh <https://github.com/SChernykh>
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
#include <map>

namespace p2pool {

class p2pool;
class P2PServer;
struct DifficultyData;
struct PoolBlock;
class Wallet;

struct MinerShare
{
	FORCEINLINE MinerShare() : m_weight(0), m_wallet(nullptr) {}
	FORCEINLINE MinerShare(uint64_t w, Wallet* x) : m_weight(w), m_wallet(x) {}

	uint64_t m_weight;
	Wallet* m_wallet;
};

class SideChain
{
public:
	SideChain(p2pool* pool, NetworkType type, const char* pool_name = nullptr);
	~SideChain();

	void fill_sidechain_data(PoolBlock& block, Wallet* w, const hash& txkeySec, std::vector<MinerShare>& shares);

	bool block_seen(const PoolBlock& block);
	void unsee_block(const PoolBlock& block);
	bool add_external_block(PoolBlock& block, std::vector<hash>& missing_blocks);
	void add_block(const PoolBlock& block);
	void get_missing_blocks(std::vector<hash>& missing_blocks);

	PoolBlock* find_block(const hash& id);
	void watch_mainchain_block(const ChainMain& data, const hash& possible_id);

	bool get_block_blob(const hash& id, std::vector<uint8_t>& blob);
	bool get_outputs_blob(PoolBlock* block, uint64_t total_reward, std::vector<uint8_t>& blob);

	void print_status();

	// Consensus ID can be used to spawn independent P2Pools with their own sidechains
	// It's never sent over the network to avoid revealing it to the possible man in the middle
	// Consensus ID can therefore be used as a password to create private P2Pools
	const std::vector<uint8_t>& consensus_id() const { return m_consensusId; }
	uint64_t chain_window_size() const { return m_chainWindowSize; }
	NetworkType network_type() const { return m_networkType; }
	const difficulty_type& difficulty() const { return m_curDifficulty; }
	difficulty_type total_hashes() const;
	uint64_t block_time() const { return m_targetBlockTime; }
	uint64_t miner_count();
	uint64_t last_updated() const;
	bool is_default() const;
	bool is_mini() const;

	const PoolBlock* chainTip() const { return m_chainTip; }

	static bool split_reward(uint64_t reward, const std::vector<MinerShare>& shares, std::vector<uint64_t>& rewards);

private:
	p2pool* m_pool;
	P2PServer* p2pServer() const;
	NetworkType m_networkType;

private:
	bool get_shares(PoolBlock* tip, std::vector<MinerShare>& shares) const;
	bool get_difficulty(PoolBlock* tip, std::vector<DifficultyData>& difficultyData, difficulty_type& curDifficulty) const;
	void verify_loop(PoolBlock* block);
	void verify(PoolBlock* block);
	void update_chain_tip(PoolBlock* block);
	PoolBlock* get_parent(const PoolBlock* block);

	// Checks if "candidate" has longer (higher difficulty) chain than "block"
	bool is_longer_chain(const PoolBlock* block, const PoolBlock* candidate, bool& is_alternative);
	void update_depths(PoolBlock* block);
	void prune_old_blocks();

	bool load_config(const std::string& filename);
	bool check_config();

	mutable uv_mutex_t m_sidechainLock;
	std::atomic<PoolBlock*> m_chainTip;
	std::map<uint64_t, std::vector<PoolBlock*>> m_blocksByHeight;
	unordered_map<hash, PoolBlock*> m_blocksById;
	unordered_map<hash, uint64_t> m_seenWallets;
	std::vector<MinerShare> m_tmpShares;
	std::vector<uint64_t> m_tmpRewards;

	uv_mutex_t m_seenBlocksLock;
	unordered_set<hash> m_seenBlocks;

	std::vector<DifficultyData> m_difficultyData;

	std::string m_poolName;
	std::string m_poolPassword;
	uint64_t m_targetBlockTime;
	difficulty_type m_minDifficulty;
	uint64_t m_chainWindowSize;
	uint64_t m_unclePenalty;

	std::vector<uint8_t> m_consensusId;
	std::string m_consensusIdDisplayStr;

	difficulty_type m_curDifficulty;

	ChainMain m_watchBlock;
	hash m_watchBlockSidechainId;
};

} // namespace p2pool
