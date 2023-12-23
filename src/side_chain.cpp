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
#include "p2pool.h"
#include "side_chain.h"
#include "pool_block.h"
#include "wallet.h"
#include "block_template.h"
#ifdef WITH_RANDOMX
#include "randomx.h"
#include "dataset.hpp"
#include "configuration.h"
#include "intrin_portable.h"
#endif
#include "keccak.h"
#include "p2p_server.h"
#include "stratum_server.h"
#include "params.h"
#include "json_parsers.h"
#include "crypto.h"
#include "hardforks/hardforks.h"
#include <rapidjson/document.h>
#include <rapidjson/istreamwrapper.h>
#include <fstream>
#include <iterator>
#include <numeric>

LOG_CATEGORY(SideChain)

static constexpr uint64_t MIN_DIFFICULTY = 1000;
static constexpr size_t UNCLE_BLOCK_DEPTH = 3;

static_assert(1 <= UNCLE_BLOCK_DEPTH && UNCLE_BLOCK_DEPTH <= 10, "Invalid UNCLE_BLOCK_DEPTH");

static constexpr uint64_t MONERO_BLOCK_TIME = 120;

namespace p2pool {

static constexpr uint8_t default_consensus_id[HASH_SIZE] = { 34,175,126,231,181,11,104,146,227,153,218,107,44,108,68,39,178,81,4,212,169,4,142,0,177,110,157,240,68,7,249,24 };
static constexpr uint8_t mini_consensus_id[HASH_SIZE] = { 57,130,201,26,149,174,199,250,66,80,189,18,108,216,194,220,136,23,63,24,64,113,221,44,219,86,39,163,53,24,126,196 };

NetworkType SideChain::s_networkType = NetworkType::Invalid;

SideChain::SideChain(p2pool* pool, NetworkType type, const char* pool_name)
	: m_pool(pool)
	, m_chainTip{ nullptr }
	, m_seenWalletsLastPruneTime(0)
	, m_poolName(pool_name ? pool_name : "default")
	, m_targetBlockTime(10)
	, m_minDifficulty(MIN_DIFFICULTY, 0)
	, m_chainWindowSize(216)
	, m_unclePenalty(20)
	, m_precalcFinished(false)
#ifdef DEV_TEST_SYNC
	, m_firstPruneTime(0)
#endif
{
	if (s_networkType == NetworkType::Invalid) {
		s_networkType = type;
	}
	else if (s_networkType != type) {
		LOGERR(1, "can't run both " << s_networkType << " and " << type << " at the same time");
		PANIC_STOP();
	}

	LOGINFO(1, log::LightCyan() << "network type  = " << type);

	if (m_pool && !load_config(m_pool->params().m_config)) {
		PANIC_STOP();
	}

	if (!check_config()) {
		PANIC_STOP();
	}

	m_curDifficulty = m_minDifficulty;

	uv_rwlock_init_checked(&m_sidechainLock);
	uv_mutex_init_checked(&m_seenWalletsLock);
	uv_mutex_init_checked(&m_incomingBlocksLock);
	uv_rwlock_init_checked(&m_curDifficultyLock);

	m_difficultyData.reserve(m_chainWindowSize);

	LOGINFO(1, "generating consensus ID");

	char buf[log::Stream::BUF_SIZE + 1];
	// cppcheck-suppress uninitvar
	log::Stream s(buf);

	s << "mm"              << '\0'
	  << s_networkType     << '\0'
	  << m_poolName        << '\0'
	  << m_poolPassword    << '\0'
	  << m_targetBlockTime << '\0'
	  << m_minDifficulty   << '\0'
	  << m_chainWindowSize << '\0'
	  << m_unclePenalty    << '\0';

	constexpr char default_config[] = "mainnet\0" "default\0" "\0" "10\0" "100000\0" "2160\0" "20\0";
	constexpr char mini_config[] = "mainnet\0" "mini\0" "\0" "10\0" "100000\0" "2160\0" "20\0";

	// Hardcoded default consensus ID
	if ((s.m_pos == sizeof(default_config) - 1) && (memcmp(buf, default_config, sizeof(default_config) - 1) == 0)) {
		m_consensusId.assign(default_consensus_id, default_consensus_id + HASH_SIZE);
	}
	// Hardcoded mini consensus ID
	else if ((s.m_pos == sizeof(mini_config) - 1) && (memcmp(buf, mini_config, sizeof(mini_config) - 1) == 0)) {
		m_consensusId.assign(mini_consensus_id, mini_consensus_id + HASH_SIZE);
	}
	else {
#ifdef WITH_RANDOMX
		const randomx_flags flags = randomx_get_flags();
		randomx_cache* cache = randomx_alloc_cache(flags | RANDOMX_FLAG_LARGE_PAGES);
		if (!cache) {
			LOGWARN(1, "couldn't allocate RandomX cache using large pages");
			cache = randomx_alloc_cache(flags);
			if (!cache) {
				LOGERR(1, "couldn't allocate RandomX cache, aborting");
				PANIC_STOP();
			}
		}

		randomx_init_cache(cache, buf, s.m_pos);

		// Intentionally not a power of 2
		constexpr size_t scratchpad_size = 1009;

		rx_vec_i128* scratchpad = reinterpret_cast<rx_vec_i128*>(cache->memory);
		rx_vec_i128* scratchpad_end = scratchpad + scratchpad_size;
		rx_vec_i128* scratchpad_ptr = scratchpad;
		rx_vec_i128* cache_ptr = scratchpad_end;

		for (uint64_t i = scratchpad_size, n = RANDOMX_ARGON_MEMORY * 1024 / sizeof(rx_vec_i128); i < n; ++i) {
			*scratchpad_ptr = rx_xor_vec_i128(*scratchpad_ptr, *cache_ptr);
			++cache_ptr;
			++scratchpad_ptr;
			if (scratchpad_ptr == scratchpad_end) {
				scratchpad_ptr = scratchpad;
			}
		}

		hash id;
		keccak(reinterpret_cast<uint8_t*>(scratchpad), static_cast<int>(scratchpad_size * sizeof(rx_vec_i128)), id.h);
		randomx_release_cache(cache);
		m_consensusId.assign(id.h, id.h + HASH_SIZE);
#else
		LOGERR(1, "Can't calculate consensus ID without RandomX library");
		PANIC_STOP();
#endif
	}

	s.m_pos = 0;
	s << log::hex_buf(m_consensusId.data(), m_consensusId.size()) << '\0';

	// Hide most consensus ID bytes, we only want it on screen to show that we're on the right sidechain
	memset(buf + 8, '*', HASH_SIZE * 2 - 16);
	m_consensusIdDisplayStr = buf;

	LOGINFO(1, "consensus ID = " << log::LightCyan() << m_consensusIdDisplayStr.c_str());

	memcpy(m_consensusHash.h, m_consensusId.data(), HASH_SIZE);

	uv_cond_init_checked(&m_precalcJobsCond);
	uv_mutex_init_checked(&m_precalcJobsMutex);
	m_precalcJobs.reserve(16);

	uint32_t numThreads = std::thread::hardware_concurrency();

	// Leave 1 CPU core free from worker threads
	if (numThreads > 1) {
		--numThreads;
	}

	// Use between 1 and 8 threads
	if (numThreads < 1) numThreads = 1;

	// Don't limit thread count when debugging because debug builds are slow
#ifndef P2POOL_DEBUGGING
	if (numThreads > 8) numThreads = 8;
#endif

	LOGINFO(4, "running " << numThreads << " pre-calculation workers");

	m_precalcWorkers.reserve(numThreads);
	for (uint32_t i = 0; i < numThreads; ++i) {
		m_precalcWorkers.emplace_back(&SideChain::precalc_worker, this);
	}

	m_uniquePrecalcInputs = new unordered_set<size_t>();
	m_uniquePrecalcInputs->reserve(1 << 18);
}

SideChain::~SideChain()
{
	finish_precalc();

	uv_rwlock_destroy(&m_sidechainLock);
	uv_mutex_destroy(&m_seenWalletsLock);
	uv_mutex_destroy(&m_incomingBlocksLock);
	uv_rwlock_destroy(&m_curDifficultyLock);

	for (const auto& it : m_blocksById) {
		delete it.second;
	}

	s_networkType = NetworkType::Invalid;
}

void SideChain::fill_sidechain_data(PoolBlock& block, std::vector<MinerShare>& shares) const
{
	block.m_uncles.clear();

	ReadLock lock(m_sidechainLock);

	const PoolBlock* tip = m_chainTip;

	if (!tip) {
		block.m_parent = {};
		block.m_sidechainHeight = 0;
		block.m_difficulty = m_minDifficulty;
		block.m_cumulativeDifficulty = m_minDifficulty;
		block.m_txkeySecSeed = m_consensusHash;
		get_tx_keys(block.m_txkeyPub, block.m_txkeySec, block.m_txkeySecSeed, block.m_prevId);

		get_shares(&block, shares);
		return;
	}

	block.m_txkeySecSeed = (block.m_prevId == tip->m_prevId) ? tip->m_txkeySecSeed : tip->calculate_tx_key_seed();
	get_tx_keys(block.m_txkeyPub, block.m_txkeySec, block.m_txkeySecSeed, block.m_prevId);

	block.m_parent = tip->m_sidechainId;
	block.m_sidechainHeight = tip->m_sidechainHeight + 1;

	// Collect uncles from 3 previous block heights

	// First get a list of already mined blocks at these heights
	std::vector<hash> mined_blocks;
	mined_blocks.reserve(UNCLE_BLOCK_DEPTH * 2 + 1);

	const PoolBlock* tmp = tip;
	for (uint64_t i = 0, n = std::min<uint64_t>(UNCLE_BLOCK_DEPTH, tip->m_sidechainHeight + 1); tmp && (i < n); ++i) {
		mined_blocks.push_back(tmp->m_sidechainId);
		mined_blocks.insert(mined_blocks.end(), tmp->m_uncles.begin(), tmp->m_uncles.end());
		tmp = get_parent(tmp);
	}

	for (uint64_t i = 0, n = std::min<uint64_t>(UNCLE_BLOCK_DEPTH, tip->m_sidechainHeight + 1); i < n; ++i) {
		auto it = m_blocksByHeight.find(tip->m_sidechainHeight - i);
		if (it == m_blocksByHeight.end()) {
			continue;
		}
		for (const PoolBlock* uncle : it->second) {
			// Only add verified and valid blocks
			if (!uncle || !uncle->m_verified || uncle->m_invalid) {
				continue;
			}

			// Only add it if it hasn't been mined already
			if (std::find(mined_blocks.begin(), mined_blocks.end(), uncle->m_sidechainId) != mined_blocks.end()) {
				continue;
			}

			// Only add it if it's on the same chain
			bool same_chain = false;
			do {
				tmp = tip;
				while (tmp && (tmp->m_sidechainHeight > uncle->m_sidechainHeight)) {
					tmp = get_parent(tmp);
				}
				if (!tmp || (tmp->m_sidechainHeight < uncle->m_sidechainHeight)) {
					break;
				}
				const PoolBlock* tmp2 = uncle;
				for (size_t j = 0; (j < UNCLE_BLOCK_DEPTH) && tmp && tmp2 && (tmp->m_sidechainHeight + UNCLE_BLOCK_DEPTH >= block.m_sidechainHeight); ++j) {
					if (tmp->m_parent == tmp2->m_parent) {
						same_chain = true;
						break;
					}
					tmp = get_parent(tmp);
					tmp2 = get_parent(tmp2);
				}
			} while (0);

			if (same_chain) {
				block.m_uncles.emplace_back(uncle->m_sidechainId);
				LOGINFO(4, "block template at height " << block.m_sidechainHeight <<
					": added " << uncle->m_sidechainId <<
					" (height " << uncle->m_sidechainHeight <<
					") as an uncle block, depth " << block.m_sidechainHeight - uncle->m_sidechainHeight);
			}
			else {
				LOGINFO(4, "block template at height " << block.m_sidechainHeight <<
					": uncle block " << uncle->m_sidechainId <<
					" (height " << uncle->m_sidechainHeight <<
					") is not on the same chain, depth " << block.m_sidechainHeight - uncle->m_sidechainHeight);
			}
		}
	}

	// Sort uncles and remove duplicates
	if (block.m_uncles.size() > 1) {
		std::sort(block.m_uncles.begin(), block.m_uncles.end());
		block.m_uncles.erase(std::unique(block.m_uncles.begin(), block.m_uncles.end()), block.m_uncles.end());
	}

	block.m_difficulty = difficulty();
	block.m_cumulativeDifficulty = tip->m_cumulativeDifficulty + block.m_difficulty;

	for (const hash& uncle_id : block.m_uncles) {
		auto it = m_blocksById.find(uncle_id);
		if (it == m_blocksById.end()) {
			LOGERR(1, "block template has an unknown uncle block " << uncle_id << ". Fix the code!");
			continue;
		}
		block.m_cumulativeDifficulty += it->second->m_difficulty;
	}

	get_shares(&block, shares);
}

P2PServer* SideChain::p2pServer() const
{
	return m_pool ? m_pool->p2p_server() : nullptr;
}

bool SideChain::get_shares(const PoolBlock* tip, std::vector<MinerShare>& shares, uint64_t* bottom_height, bool quiet) const
{
	if (tip->m_txkeySecSeed.empty()) {
		LOGERR(1, "tx key seed is not set, fix the code!");
	}

	const int L = quiet ? 6 : 3;

	// Collect shares from each block in the PPLNS window, starting from the "tip"

	uint64_t block_depth = 0;
	const PoolBlock* cur = tip;

	difficulty_type mainchain_diff
#ifdef P2POOL_UNIT_TESTS
		= m_testMainChainDiff
#endif
	;

	if (m_pool && !tip->m_parent.empty()) {
		const uint64_t h = p2pool::get_seed_height(tip->m_txinGenHeight);
		if (!m_pool->get_difficulty_at_height(h, mainchain_diff)) {
			LOGWARN(L, "get_shares: couldn't get mainchain difficulty for height = " << h);
			return false;
		}
	}

	// Dynamic PPLNS window starting from v2
	// Limit PPLNS weight to 2x of the Monero difficulty (max 2 blocks per PPLNS window on average)
	const difficulty_type max_pplns_weight = mainchain_diff * 2;
	difficulty_type pplns_weight;

	unordered_set<MinerShare> shares_set;
	shares_set.reserve(m_chainWindowSize * 2);

	do {
		difficulty_type cur_weight = cur->m_difficulty;

		for (const hash& uncle_id : cur->m_uncles) {
			auto it = m_blocksById.find(uncle_id);
			if (it == m_blocksById.end()) {
				LOGWARN(L, "get_shares: can't find uncle block at height = " << cur->m_sidechainHeight << ", id = " << uncle_id);
				LOGWARN(L, "get_shares: can't calculate shares for block at height = " << tip->m_sidechainHeight << ", id = " << tip->m_sidechainId << ", mainchain height = " << tip->m_txinGenHeight);
				return false;
			}

			PoolBlock* uncle = it->second;

			// Skip uncles which are already out of PPLNS window
			if (tip->m_sidechainHeight - uncle->m_sidechainHeight >= m_chainWindowSize) {
				continue;
			}

			// Take some % of uncle's weight into this share
			const difficulty_type uncle_penalty = uncle->m_difficulty * m_unclePenalty / 100;
			const difficulty_type uncle_weight = uncle->m_difficulty - uncle_penalty;
			const difficulty_type new_pplns_weight = pplns_weight + uncle_weight;

			// Skip uncles that push PPLNS weight above the limit
			if (new_pplns_weight > max_pplns_weight) {
				continue;
			}

			cur_weight += uncle_penalty;

			auto result = shares_set.emplace(uncle_weight, &uncle->m_minerWallet);
			if (!result.second) {
				result.first->m_weight += uncle_weight;
			}
			pplns_weight = new_pplns_weight;
		}

		// Always add non-uncle shares even if PPLNS weight goes above the limit
		auto result = shares_set.emplace(cur_weight, &cur->m_minerWallet);
		if (!result.second) {
			result.first->m_weight += cur_weight;
		}
		pplns_weight += cur_weight;

		// One non-uncle share can go above the limit, but it will also guarantee that "shares" is never empty
		if (pplns_weight > max_pplns_weight) {
			break;
		}

		++block_depth;
		if (block_depth >= m_chainWindowSize) {
			break;
		}

		// Reached the genesis block so we're done
		if (cur->m_sidechainHeight == 0) {
			break;
		}

		auto it = m_blocksById.find(cur->m_parent);
		if (it == m_blocksById.end()) {
			LOGWARN(L, "get_shares: can't find parent block at height = " << cur->m_sidechainHeight - 1 << ", id = " << cur->m_parent);
			LOGWARN(L, "get_shares: can't calculate shares for block at height = " << tip->m_sidechainHeight << ", id = " << tip->m_sidechainId << ", mainchain height = " << tip->m_txinGenHeight);
			return false;
		}

		cur = it->second;
	} while (true);

	if (bottom_height) {
		*bottom_height = cur->m_sidechainHeight;
	}

	shares.assign(shares_set.begin(), shares_set.end());
	std::sort(shares.begin(), shares.end(), [](const auto& a, const auto& b) { return *a.m_wallet < *b.m_wallet; });

	const uint64_t n = shares.size();

	// Shuffle shares
	if (n > 1) {
		hash h;
		keccak(tip->m_txkeySecSeed.h, HASH_SIZE, h.h);

		uint64_t seed = *h.u64();
		if (seed == 0) seed = 1;

		for (uint64_t i = 0, k; i < n - 1; ++i) {
			seed = xorshift64star(seed);
			umul128(seed, n - i, &k);
			std::swap(shares[i], shares[i + k]);
		}
	}

	LOGINFO(6, "get_shares: " << n << " unique wallets in PPLNS window");
	return true;
}

bool SideChain::incoming_block_seen(const PoolBlock& block)
{
	// Check if it's some old block
	const PoolBlock* tip = m_chainTip;

	if (tip && tip->m_sidechainHeight > block.m_sidechainHeight + m_chainWindowSize * 2 &&
		block.m_cumulativeDifficulty < tip->m_cumulativeDifficulty) {
		return true;
	}

	const uint64_t cur_time = seconds_since_epoch();

	// Check if it was received before
	MutexLock lock(m_incomingBlocksLock);
	return !m_incomingBlocks.emplace(block.get_full_id(), cur_time).second;
}

void SideChain::forget_incoming_block(const PoolBlock& block)
{
	MutexLock lock(m_incomingBlocksLock);
	m_incomingBlocks.erase(block.get_full_id());
}

void SideChain::cleanup_incoming_blocks()
{
	const uint64_t cur_time = seconds_since_epoch();

	MutexLock lock(m_incomingBlocksLock);

	// Forget seen blocks that were added more than 10 minutes ago
	hash h;
	for (auto i = m_incomingBlocks.begin(); i != m_incomingBlocks.end();) {
		if (cur_time < i->second + 10 * 60) {
			++i;
		}
		else {
			i = m_incomingBlocks.erase(i);
		}
	}
}

bool SideChain::add_external_block(PoolBlock& block, std::vector<hash>& missing_blocks)
{
	if (block.m_difficulty < m_minDifficulty) {
		LOGWARN(3, "add_external_block: block mined by " << block.m_minerWallet << " has invalid difficulty " << block.m_difficulty << ", expected >= " << m_minDifficulty);
		return false;
	}

	const difficulty_type expected_diff = difficulty();
	bool too_low_diff = (block.m_difficulty < expected_diff);
	{
		ReadLock lock(m_sidechainLock);
		if (m_blocksById.find(block.m_sidechainId) != m_blocksById.end()) {
			LOGINFO(4, "add_external_block: block " << block.m_sidechainId << " is already added");
			return true;
		}

		// This is mainly an anti-spam measure, not an actual verification step
		if (too_low_diff) {
			// Reduce required diff by 50% (by doubling this block's diff) to account for alternative chains
			difficulty_type diff2 = block.m_difficulty;
			diff2 += block.m_difficulty;

			const PoolBlock* tip = m_chainTip;

			for (const PoolBlock* tmp = tip; tmp && (tmp->m_sidechainHeight + m_chainWindowSize > tip->m_sidechainHeight); tmp = get_parent(tmp)) {
				if (diff2 >= tmp->m_difficulty) {
					too_low_diff = false;
					break;
				}
			}
		}
	}

	LOGINFO(4, "add_external_block: height = " << block.m_sidechainHeight << ", id = " << block.m_sidechainId << ", mainchain height = " << block.m_txinGenHeight);

	if (too_low_diff) {
		LOGWARN(4, "add_external_block: block mined by " << block.m_minerWallet << " has too low difficulty " << block.m_difficulty << ", expected >= ~" << expected_diff << ". Ignoring it.");
		return true;
	}

	// This check is not always possible to perform because of mainchain reorgs
	ChainMain data;
	if (m_pool->chainmain_get_by_hash(block.m_prevId, data)) {
		if (data.height + 1 != block.m_txinGenHeight) {
			LOGWARN(3, "add_external_block mined by " << block.m_minerWallet << ": wrong mainchain height " << block.m_txinGenHeight << ", expected " << data.height + 1);
			return false;
		}
	}
	else {
		LOGWARN(3, "add_external_block: block is built on top of an unknown mainchain block " << block.m_prevId << ", mainchain reorg might've happened");
	}

	hash seed;
	if (!m_pool->get_seed(block.m_txinGenHeight, seed)) {
		LOGWARN(3, "add_external_block mined by " << block.m_minerWallet << ": couldn't get seed hash for mainchain height " << block.m_txinGenHeight);
		forget_incoming_block(block);
		return false;
	}

	hash pow_hash;
	if (!block.get_pow_hash(m_pool->hasher(), block.m_txinGenHeight, seed, pow_hash)) {
		LOGWARN(3, "add_external_block: couldn't get PoW hash for height = " << block.m_sidechainHeight << ", mainchain height " << block.m_txinGenHeight << ". Ignoring it.");
		forget_incoming_block(block);
		return true;
	}

	// Check if it has the correct parent and difficulty to go right to monerod for checking
	MinerData miner_data = m_pool->miner_data();
	if ((block.m_prevId == miner_data.prev_id) && miner_data.difficulty.check_pow(pow_hash)) {
		LOGINFO(0, log::LightGreen() << "add_external_block: block " << block.m_sidechainId << " has enough PoW for Monero network, submitting it");
		m_pool->submit_block_async(block.serialize_mainchain_data());
	}
	else {
		difficulty_type diff;
		if (!m_pool->get_difficulty_at_height(block.m_txinGenHeight, diff)) {
			LOGWARN(3, "add_external_block: couldn't get mainchain difficulty for height = " << block.m_txinGenHeight);
		}
		else if (diff.check_pow(pow_hash)) {
			LOGINFO(0, log::LightGreen() << "add_external_block: block " << block.m_sidechainId << " has enough PoW for Monero height " << block.m_txinGenHeight << ", submitting it");
			m_pool->submit_block_async(block.serialize_mainchain_data());
		}
	}

	if (!block.m_difficulty.check_pow(pow_hash)) {
		LOGWARN(3,
			"add_external_block mined by " << block.m_minerWallet <<
			": not enough PoW for height = " << block.m_sidechainHeight <<
			", id = " << block.m_sidechainId <<
			", nonce = " << block.m_nonce <<
			", mainchain height = " << block.m_txinGenHeight
		);

		bool not_enough_pow = true;

		// Calculate the same hash second time to check if it's an unstable hardware that caused this
		hash pow_hash2;
		if (block.get_pow_hash(m_pool->hasher(), block.m_txinGenHeight, seed, pow_hash2, true) && (pow_hash2 != pow_hash)) {
			LOGERR(0, "UNSTABLE HARDWARE DETECTED: Calculated the same hash twice, got different results: " << pow_hash << " != " << pow_hash2 << " (sidechain id = " << block.m_sidechainId << ')');
			if (block.m_difficulty.check_pow(pow_hash2)) {
				LOGINFO(3, "add_external_block second result has enough PoW for height = " << block.m_sidechainHeight << ", id = " << block.m_sidechainId);
				not_enough_pow = false;
			}
		}

		if (not_enough_pow) {
			return false;
		}
	}

	bool block_found = false;

	missing_blocks.clear();
	{
		WriteLock lock(m_sidechainLock);
		if (!block.m_parent.empty() && (m_blocksById.find(block.m_parent) == m_blocksById.end())) {
			missing_blocks.push_back(block.m_parent);
		}

		for (const hash& h : block.m_uncles) {
			if (!h.empty() && (m_blocksById.find(h) == m_blocksById.end())) {
				missing_blocks.push_back(h);
			}
		}

		if (block.m_merkleRoot == m_watchBlockMerkleRoot) {
			const Wallet& w = m_pool->params().m_wallet;

			const char* who = (block.m_minerWallet == w) ? "you" : "someone else in this p2pool";
			LOGINFO(0, log::LightGreen() << "BLOCK FOUND: main chain block at height " << m_watchBlock.height << " was mined by " << who << BLOCK_FOUND);

			m_watchBlockMerkleRoot = {};
			data = m_watchBlock;
			block_found = true;

			const uint64_t payout = block.get_payout(w);
			if (payout) {
				LOGINFO(0, log::LightCyan() << "Your wallet " << log::LightGreen() << w << log::LightCyan() << " got a payout of " << log::LightGreen() << log::XMRAmount(payout) << log::LightCyan() << " in block " << log::LightGreen() << data.height);
			}
			else {
				LOGINFO(0, log::LightCyan() << "Your wallet " << log::LightYellow() << w << log::LightCyan() << " didn't get a payout in block " << log::LightYellow() << data.height << log::LightCyan() << " because you had no shares in PPLNS window");
			}
		}
	}

	if (block_found) {
		m_pool->api_update_block_found(&data, &block);
	}

	add_block(block);
	return true;
}

bool SideChain::add_block(const PoolBlock& block)
{
	LOGINFO(3, "add_block: height = " << block.m_sidechainHeight <<
		", id = " << block.m_sidechainId <<
		", mainchain height = " << block.m_txinGenHeight <<
		", verified = " << (block.m_verified ? 1 : 0)
	);

	PoolBlock* new_block = new PoolBlock(block);
	{
		MutexLock lock(m_seenWalletsLock);
		m_seenWallets[new_block->m_minerWallet.spend_public_key()] = new_block->m_localTimestamp;
	}

	WriteLock lock(m_sidechainLock);

	auto result = m_blocksById.insert({ new_block->m_sidechainId, new_block });
	if (!result.second) {
		const PoolBlock* old_block = result.first->second;

		LOGWARN(3, "add_block: trying to add the same block twice:"
			<< "\nnew block id = " << new_block->m_sidechainId
			<< ", sidechain height = " << new_block->m_sidechainHeight
			<< ", height = " << new_block->m_txinGenHeight
			<< ", nonce = " << new_block->m_nonce
			<< ", extra_nonce = " << new_block->m_extraNonce
			<< "\nold block id = " << old_block->m_sidechainId
			<< ", sidechain height = " << old_block->m_sidechainHeight
			<< ", height = " << old_block->m_txinGenHeight
			<< ", nonce = " << old_block->m_nonce
			<< ", extra_nonce = " << old_block->m_extraNonce
		);

		delete new_block;
		return false;
	}

	m_blocksByHeight[new_block->m_sidechainHeight].push_back(new_block);
	m_blocksByMerkleRoot.insert({ new_block->m_merkleRoot, new_block });

	update_depths(new_block);

	if (new_block->m_verified) {
		if (!new_block->m_invalid) {
			update_chain_tip(new_block);

			// Save it for faster syncing on the next p2pool start
			if (P2PServer* server = p2pServer()) {
				server->store_in_cache(*new_block);
			}
		}
	}
	else {
		verify_loop(new_block);
	}

	return true;
}

PoolBlock* SideChain::find_block(const hash& id) const
{
	ReadLock lock(m_sidechainLock);

	auto it = m_blocksById.find(id);
	if (it != m_blocksById.end()) {
		return it->second;
	}

	return nullptr;
}

PoolBlock* SideChain::find_block_by_merkle_root(const root_hash& merkle_root) const
{
	ReadLock lock(m_sidechainLock);

	auto it = m_blocksByMerkleRoot.find(merkle_root);
	if (it != m_blocksByMerkleRoot.end()) {
		return it->second;
	}

	return nullptr;
}

void SideChain::watch_mainchain_block(const ChainMain& data, const hash& possible_merkle_root)
{
	WriteLock lock(m_sidechainLock);
	m_watchBlock = data;
	m_watchBlockMerkleRoot = possible_merkle_root;
}

const PoolBlock* SideChain::get_block_blob(const hash& id, std::vector<uint8_t>& blob) const
{
	ReadLock lock(m_sidechainLock);

	const PoolBlock* block = nullptr;

	// Empty hash means we return current sidechain tip
	if (id.empty()) {
		block = m_chainTip;

		// Don't return stale chain tip
		if (block && (block->m_txinGenHeight + 2 < m_pool->miner_data().height)) {
			return nullptr;
		}
	}
	else {
		auto it = m_blocksById.find(id);
		if (it != m_blocksById.end()) {
			block = it->second;
		}
	}

	if (!block) {
		return nullptr;
	}

	blob = block->serialize_mainchain_data();
	const std::vector<uint8_t> sidechain_data = block->serialize_sidechain_data();
	blob.insert(blob.end(), sidechain_data.begin(), sidechain_data.end());

	return block;
}

bool SideChain::get_outputs_blob(PoolBlock* block, uint64_t total_reward, std::vector<uint8_t>& blob, uv_loop_t* loop) const
{
	blob.clear();

	struct Data
	{
		FORCEINLINE Data() : blockMinerWallet(nullptr), counter(0) {}
		Data(Data&&) = delete;
		Data& operator=(Data&&) = delete;

		std::vector<MinerShare> tmpShares;
		Wallet blockMinerWallet;
		hash txkeySec;
		std::atomic<int> counter;
	};

	std::shared_ptr<Data> data;
	std::vector<uint64_t> tmpRewards;
	{
		ReadLock lock(m_sidechainLock);

		auto it = block->m_sidechainId.empty() ? m_blocksById.end() : m_blocksById.find(block->m_sidechainId);
		if (it != m_blocksById.end()) {
			PoolBlock* b = it->second;
			const size_t n = b->m_outputs.size();

			blob.reserve(n * 39 + 64);
			writeVarint(n, blob);

			const uint8_t tx_type = b->get_tx_type();

			for (const PoolBlock::TxOutput& output : b->m_outputs) {
				writeVarint(output.m_reward, blob);
				blob.emplace_back(tx_type);
				blob.insert(blob.end(), output.m_ephPublicKey.h, output.m_ephPublicKey.h + HASH_SIZE);

				if (tx_type == TXOUT_TO_TAGGED_KEY) {
					blob.emplace_back(static_cast<uint8_t>(output.m_viewTag));
				}
			}

			block->m_outputs = b->m_outputs;
			return true;
		}

		data = std::make_shared<Data>();
		data->blockMinerWallet = block->m_minerWallet;
		data->txkeySec = block->m_txkeySec;

		if (!get_shares(block, data->tmpShares) || !split_reward(total_reward, data->tmpShares, tmpRewards) || (tmpRewards.size() != data->tmpShares.size())) {
			return false;
		}
	}

	const size_t n = data->tmpShares.size();
	data->counter = static_cast<int>(n) - 1;

	// Helper jobs call get_eph_public_key with indices in descending order
	// Current thread will process indices in ascending order so when they meet, everything will be cached
	if (loop) {
		// Avoid accessing block->m_minerWallet from other threads in "parallel_run" below
		for (MinerShare& share : data->tmpShares) {
			if (share.m_wallet == &block->m_minerWallet) {
				share.m_wallet = &data->blockMinerWallet;
				break;
			}
		}

		parallel_run(loop, [data]() {
			Data* d = data.get();
			hash eph_public_key;

			int index;
			while ((index = d->counter.fetch_sub(1)) >= 0) {
				uint8_t view_tag;
				if (!d->tmpShares[index].m_wallet->get_eph_public_key(d->txkeySec, static_cast<size_t>(index), eph_public_key, view_tag)) {
					LOGWARN(6, "get_eph_public_key failed at index " << index);
				}
			}
		});
	}

	blob.reserve(n * 39 + 64);

	writeVarint(n, blob);

	block->m_outputs.clear();
	block->m_outputs.reserve(n);

	const uint8_t tx_type = block->get_tx_type();

	hash eph_public_key;
	for (size_t i = 0; i < n; ++i) {
		// stop helper jobs when they meet with current thread
		const int c = data->counter.load();
		if ((c >= 0) && (static_cast<int>(i) >= c)) {
			// this will cause all helper jobs to finish immediately
			data->counter = -1;
		}

		writeVarint(tmpRewards[i], blob);

		blob.emplace_back(tx_type);

		uint8_t view_tag;
		if (!data->tmpShares[i].m_wallet->get_eph_public_key(data->txkeySec, i, eph_public_key, view_tag)) {
			LOGWARN(6, "get_eph_public_key failed at index " << i);
		}
		blob.insert(blob.end(), eph_public_key.h, eph_public_key.h + HASH_SIZE);

		if (tx_type == TXOUT_TO_TAGGED_KEY) {
			blob.emplace_back(view_tag);
		}

		block->m_outputs.emplace_back(tmpRewards[i], eph_public_key, view_tag);
	}

	block->m_outputs.shrink_to_fit();
	return true;
}

void SideChain::print_status(bool obtain_sidechain_lock) const
{
	unordered_set<hash> blocks_in_window;
	blocks_in_window.reserve(m_chainWindowSize * 9 / 8);

	const difficulty_type diff = difficulty();

	if (obtain_sidechain_lock) uv_rwlock_rdlock(&m_sidechainLock);
	ON_SCOPE_LEAVE([this, obtain_sidechain_lock]() { if (obtain_sidechain_lock) uv_rwlock_rdunlock(&m_sidechainLock); });

	const uint64_t pool_hashrate = (diff / m_targetBlockTime).lo;

	const difficulty_type network_diff = m_pool->miner_data().difficulty;
	const uint64_t network_hashrate = (network_diff / MONERO_BLOCK_TIME).lo;

	const PoolBlock* tip = m_chainTip;

	std::vector<MinerShare> shares;
	uint64_t bh = 0;
	if (tip) {
		get_shares(tip, shares, &bh, true);
	}

	const uint64_t window_size = (tip && bh) ? (tip->m_sidechainHeight - bh + 1U) : m_chainWindowSize;

	uint64_t block_depth = 0;
	const PoolBlock* cur = tip;
	const uint64_t tip_height = tip ? tip->m_sidechainHeight : 0;

	uint64_t total_blocks_in_window = 0;
	uint64_t total_uncles_in_window = 0;

	// each dot corresponds to window_size / 30 shares, with current values, 2160 / 30 = 72
	constexpr size_t N = 30;
	std::array<uint64_t, N> our_blocks_in_window{};
	std::array<uint64_t, N> our_uncles_in_window{};

	const Wallet& w = m_pool->params().m_wallet;

	while (cur) {
		blocks_in_window.emplace(cur->m_sidechainId);
		++total_blocks_in_window;

		// "block_depth <= window_size - 1" here (see the check below), so window_index will be <= N - 1
		// This will map the range [0, window_size - 1] into [0, N - 1]
		const size_t window_index = (window_size > 1) ? (block_depth * (N - 1) / (window_size - 1)) : 0;

		if (cur->m_minerWallet == w) {
			++our_blocks_in_window[window_index];
		}

		++block_depth;
		if (block_depth >= window_size) {
			break;
		}

		for (const hash& uncle_id : cur->m_uncles) {
			blocks_in_window.emplace(uncle_id);
			auto it = m_blocksById.find(uncle_id);
			if (it != m_blocksById.end()) {
				const PoolBlock* uncle = it->second;
				if (tip_height - uncle->m_sidechainHeight < window_size) {
					++total_uncles_in_window;
					if (uncle->m_minerWallet == w) {
						++our_uncles_in_window[window_index];
					}
				}
			}
		}

		cur = get_parent(cur);
	}

	uint64_t total_orphans = 0;
	uint64_t our_orphans = 0;

	if (tip) {
		for (uint64_t i = 0; (i < window_size) && (i <= tip_height); ++i) {
			auto it = m_blocksByHeight.find(tip_height - i);
			if (it == m_blocksByHeight.end()) {
				continue;
			}
			for (const PoolBlock* block : it->second) {
				if (blocks_in_window.find(block->m_sidechainId) == blocks_in_window.end()) {
					LOGINFO(4, "orphan block at height " << log::Gray() << block->m_sidechainHeight << log::NoColor() << ": " << log::Gray() << block->m_sidechainId);
					++total_orphans;
					if (block->m_minerWallet == w) {
						++our_orphans;
					}
				}
			}
		}
	}

	difficulty_type your_shares_weight, pplns_weight;
	for (const MinerShare& s : shares) {
		if (*s.m_wallet == w) {
			your_shares_weight = s.m_weight;
		}
		pplns_weight += s.m_weight;
	}

	if (pplns_weight == 0) {
		pplns_weight = m_minDifficulty;
	}

	const uint64_t total_reward = m_pool->block_template().get_reward();
	const uint64_t your_reward = ((your_shares_weight * total_reward) / pplns_weight).lo;
	const uint64_t hashrate_est = ((your_shares_weight * pool_hashrate) / pplns_weight).lo;

	const double block_share = total_reward ? ((static_cast<double>(your_reward) * 100.0) / static_cast<double>(total_reward)) : 0.0;

	const uint64_t our_blocks_in_window_total = std::accumulate(our_blocks_in_window.begin(), our_blocks_in_window.end(), 0ULL);
	const uint64_t our_uncles_in_window_total = std::accumulate(our_uncles_in_window.begin(), our_uncles_in_window.end(), 0ULL);

	std::string our_blocks_in_window_chart;
	if (our_blocks_in_window_total) {
		our_blocks_in_window_chart.reserve(our_blocks_in_window.size() + 32);
		our_blocks_in_window_chart = "\nYour shares position      = [";
		for (uint64_t p : our_blocks_in_window) {
			our_blocks_in_window_chart += (p ? ((p > 9) ? '+' : static_cast<char>('0' + p)) : '.');
		}
		our_blocks_in_window_chart += ']';
	}

	std::string our_uncles_in_window_chart;
	if (our_uncles_in_window_total) {
		our_uncles_in_window_chart.reserve(our_uncles_in_window.size() + 32);
		our_uncles_in_window_chart = "\nYour uncles position      = [";
		for (uint64_t p : our_uncles_in_window) {
			our_uncles_in_window_chart += (p ? ((p > 9) ? '+' : static_cast<char>('0' + p)) : '.');
		}
		our_uncles_in_window_chart += ']';
	}

	LOGINFO(0, "status" <<
		"\nMonero node               = " << m_pool->current_host().m_displayName <<
		"\nMain chain height         = " << m_pool->block_template().height() <<
		"\nMain chain hashrate       = " << log::Hashrate(network_hashrate) <<
		"\nSide chain ID             = " << (is_default() ? "default" : (is_mini() ? "mini" : m_consensusIdDisplayStr.c_str())) <<
		"\nSide chain height         = " << tip_height + 1 <<
		"\nSide chain hashrate       = " << log::Hashrate(pool_hashrate) <<
		(hashrate_est ? "\nYour hashrate (pool-side) = " : "") << (hashrate_est ? log::Hashrate(hashrate_est) : log::Hashrate()) <<
		"\nPPLNS window              = " << total_blocks_in_window << " blocks (+" << total_uncles_in_window << " uncles, " << total_orphans << " orphans)" <<
		"\nPPLNS window duration     = " << log::Duration((pplns_weight / pool_hashrate).lo) <<
		"\nYour wallet address       = " << w <<
		"\nYour shares               = " << our_blocks_in_window_total << " blocks (+" << our_uncles_in_window_total << " uncles, " << our_orphans << " orphans)"
										 << our_blocks_in_window_chart << our_uncles_in_window_chart <<
		"\nBlock reward share        = " << block_share << "% (" << log::XMRAmount(your_reward) << ')'
	);
}

double SideChain::get_reward_share(const Wallet& w) const
{
	uint64_t reward = 0;
	uint64_t total_reward = 0;
	{
		ReadLock lock(m_sidechainLock);

		const PoolBlock* tip = m_chainTip;
		if (tip) {
			const uint8_t tx_type = tip->get_tx_type();
			hash eph_public_key;
			for (size_t i = 0, n = tip->m_outputs.size(); i < n; ++i) {
				const PoolBlock::TxOutput& out = tip->m_outputs[i];
				if (!reward) {
					if (tx_type == TXOUT_TO_TAGGED_KEY) {
						uint8_t view_tag;
						const uint8_t expected_view_tag = out.m_viewTag;
						if (w.get_eph_public_key(tip->m_txkeySec, i, eph_public_key, view_tag, &expected_view_tag) && (out.m_ephPublicKey == eph_public_key)) {
							reward = out.m_reward;
						}
					}
					else {
						uint8_t view_tag;
						if (w.get_eph_public_key(tip->m_txkeySec, i, eph_public_key, view_tag) && (out.m_ephPublicKey == eph_public_key)) {
							reward = out.m_reward;
						}
					}
				}
				total_reward += out.m_reward;
			}
		}
	}
	return total_reward ? (static_cast<double>(reward) / static_cast<double>(total_reward)) : 0.0;
}

uint64_t SideChain::network_major_version(uint64_t height)
{
	const hardfork_t* hard_forks;
	size_t num_hard_forks;

	switch (s_networkType)
	{
	case NetworkType::Mainnet:
	default:
		hard_forks = mainnet_hard_forks;
		num_hard_forks = num_mainnet_hard_forks;
		break;

	case NetworkType::Testnet:
		hard_forks = testnet_hard_forks;
		num_hard_forks = num_testnet_hard_forks;
		break;

	case NetworkType::Stagenet:
		hard_forks = stagenet_hard_forks;
		num_hard_forks = num_stagenet_hard_forks;
		break;
	}

	uint64_t result = 1;
	for (size_t i = 1; (i < num_hard_forks) && (height >= hard_forks[i].height); ++i) {
		result = hard_forks[i].version;
	}
	return result;
}

difficulty_type SideChain::total_hashes() const
{
	const PoolBlock* tip = m_chainTip;
	return tip ? tip->m_cumulativeDifficulty : difficulty_type();
}

uint64_t SideChain::miner_count()
{
	const uint64_t cur_time = seconds_since_epoch();

	MutexLock lock(m_seenWalletsLock);

	// Every 5 minutes, delete wallets that weren't seen for more than 72 hours
	if (m_seenWalletsLastPruneTime + 5 * 60 <= cur_time) {
		for (auto it = m_seenWallets.begin(); it != m_seenWallets.end();) {
			if (it->second + 72 * 60 * 60 < cur_time) {
				it = m_seenWallets.erase(it);
			}
			else {
				++it;
			}
		}
		m_seenWalletsLastPruneTime = cur_time;
	}

	return m_seenWallets.size();
}

uint64_t SideChain::last_updated() const
{
	const PoolBlock* tip = m_chainTip;
	return tip ? tip->m_localTimestamp : 0;
}

bool SideChain::is_default() const
{
	return (memcmp(m_consensusId.data(), default_consensus_id, HASH_SIZE) == 0);
}

bool SideChain::is_mini() const
{
	return (memcmp(m_consensusId.data(), mini_consensus_id, HASH_SIZE) == 0);
}

uint64_t SideChain::bottom_height(const PoolBlock* tip) const
{
	if (!tip) {
		return 0;
	}

	uint64_t bottom_height;
	std::vector<MinerShare> shares;

	ReadLock lock(m_sidechainLock);

	if (!get_shares(tip, shares, &bottom_height, true)) {
		return 0;
	}

	return bottom_height;
}

bool SideChain::split_reward(uint64_t reward, const std::vector<MinerShare>& shares, std::vector<uint64_t>& rewards)
{
	const size_t num_shares = shares.size();

	const difficulty_type total_weight = std::accumulate(shares.begin(), shares.end(), difficulty_type(), [](const difficulty_type& a, const MinerShare& b) { return a + b.m_weight; });

	if (total_weight.empty()) {
		LOGERR(1, "total_weight is 0. Check the code!");
		return false;
	}

	rewards.clear();
	rewards.reserve(num_shares);

	// Each miner gets a proportional fraction of the block reward
	difficulty_type w;
	uint64_t reward_given = 0;
	for (uint64_t i = 0; i < num_shares; ++i) {
		w += shares[i].m_weight;

		const difficulty_type next_value = w * reward / total_weight;
		rewards.emplace_back(next_value.lo - reward_given);
		reward_given = next_value.lo;
	}

	// Double check that we gave out the exact amount
	if (std::accumulate(rewards.begin(), rewards.end(), 0ULL) != reward) {
		LOGERR(1, "miners got incorrect reward. This should never happen because math says so. Check the code!");
		return false;
	}

	return true;
}

bool SideChain::get_difficulty(const PoolBlock* tip, std::vector<DifficultyData>& difficultyData, difficulty_type& curDifficulty) const
{
	difficultyData.clear();

	const PoolBlock* cur = tip;
	uint64_t oldest_timestamp = std::numeric_limits<uint64_t>::max();

	uint64_t block_depth = 0;
	do {
		oldest_timestamp = std::min(oldest_timestamp, cur->m_timestamp);
		difficultyData.emplace_back(cur->m_timestamp, cur->m_cumulativeDifficulty);

		for (const hash& uncle_id : cur->m_uncles) {
			auto it = m_blocksById.find(uncle_id);
			if (it == m_blocksById.end()) {
				LOGWARN(3, "get_difficulty: can't find uncle block at height = " << cur->m_sidechainHeight << ", id = " << uncle_id);
				LOGWARN(3, "get_difficulty: can't calculate diff for block at height = " << tip->m_sidechainHeight << ", id = " << tip->m_sidechainId << ", mainchain height = " << tip->m_txinGenHeight);
				return false;
			}

			const PoolBlock* uncle = it->second;
			if (tip->m_sidechainHeight - uncle->m_sidechainHeight < m_chainWindowSize) {
				oldest_timestamp = std::min(oldest_timestamp, uncle->m_timestamp);
				difficultyData.emplace_back(uncle->m_timestamp, uncle->m_cumulativeDifficulty);
			}
		}

		++block_depth;
		if (block_depth >= m_chainWindowSize) {
			break;
		}

		// Reached the genesis block so we're done
		if (cur->m_sidechainHeight == 0) {
			break;
		}

		auto it = m_blocksById.find(cur->m_parent);
		if (it == m_blocksById.end()) {
			LOGWARN(3, "get_difficulty: can't find parent block at height = " << cur->m_sidechainHeight - 1 << ", id = " << cur->m_parent);
			LOGWARN(3, "get_difficulty: can't calculate diff for block at height = " << tip->m_sidechainHeight << ", id = " << tip->m_sidechainId << ", mainchain height = " << tip->m_txinGenHeight);
			return false;
		}

		cur = it->second;
	} while (true);

	// Discard 10% oldest and 10% newest (by timestamp) blocks
	std::vector<uint32_t> tmpTimestamps;
	tmpTimestamps.reserve(difficultyData.size());

	std::transform(difficultyData.begin(), difficultyData.end(), std::back_inserter(tmpTimestamps),
		[oldest_timestamp](const DifficultyData& d)
		{
			return static_cast<uint32_t>(d.m_timestamp - oldest_timestamp);
		});

	const uint64_t cut_size = (difficultyData.size() + 9) / 10;
	const uint64_t index1 = cut_size - 1;
	const uint64_t index2 = difficultyData.size() - cut_size;

	std::nth_element(tmpTimestamps.begin(), tmpTimestamps.begin() + index1, tmpTimestamps.end());
	const uint64_t timestamp1 = oldest_timestamp + tmpTimestamps[index1];

	std::nth_element(tmpTimestamps.begin(), tmpTimestamps.begin() + index2, tmpTimestamps.end());
	const uint64_t timestamp2 = oldest_timestamp + tmpTimestamps[index2];

	// Make a reasonable assumption that each block has higher timestamp, so delta_t can't be less than delta_index
	// Because if it is, someone is trying to mess with timestamps
	// In reality, delta_t ~ delta_index*10 (sidechain block time)
	const uint64_t delta_index = (index2 > index1) ? (index2 - index1) : 1U;
	const uint64_t delta_t = (timestamp2 > timestamp1 + delta_index) ? (timestamp2 - timestamp1) : delta_index;

	difficulty_type diff1{ std::numeric_limits<uint64_t>::max(), std::numeric_limits<uint64_t>::max() };
	difficulty_type diff2{ 0, 0 };

	for (const DifficultyData& d : difficultyData) {
		if (timestamp1 <= d.m_timestamp && d.m_timestamp <= timestamp2) {
			if (d.m_cumulativeDifficulty < diff1) {
				diff1 = d.m_cumulativeDifficulty;
			}
			if (diff2 < d.m_cumulativeDifficulty) {
				diff2 = d.m_cumulativeDifficulty;
			}
		}
	}

	curDifficulty = (diff2 - diff1) * m_targetBlockTime / delta_t;

	if (curDifficulty < m_minDifficulty) {
		curDifficulty = m_minDifficulty;
	}

	return true;
}

bool SideChain::p2pool_update_available() const
{
	constexpr uint32_t version = (P2POOL_VERSION_MAJOR << 16) | P2POOL_VERSION_MINOR;

	difficulty_type total_p2pool_diff, newer_p2pool_diff;
	{
		ReadLock lock(m_sidechainLock);

		const PoolBlock* cur = m_chainTip;

		for (uint64_t i = 0; (i < m_chainWindowSize) && cur; ++i, cur = get_parent(cur)) {
			if (cur->m_sidechainExtraBuf[0] == static_cast<uint32_t>(SoftwareID::P2Pool)) {
				total_p2pool_diff += cur->m_difficulty;
				if (cur->m_sidechainExtraBuf[1] > version) {
					newer_p2pool_diff += cur->m_difficulty;
				}
			}
		}
	}

	// Assume that a new version is out if >= 20% of hashrate is using it already
	return newer_p2pool_diff * 5 >= total_p2pool_diff;
}

void SideChain::verify_loop(PoolBlock* block)
{
	// PoW is already checked at this point

	std::vector<PoolBlock*> blocks_to_verify(1, block);
	PoolBlock* highest_block = nullptr;

	while (!blocks_to_verify.empty()) {
		block = blocks_to_verify.back();
		blocks_to_verify.pop_back();

		if (block->m_verified) {
			continue;
		}

		verify(block);

		if (!block->m_verified) {
			LOGINFO(6, "can't verify block at height = " << block->m_sidechainHeight <<
				", id = " << block->m_sidechainId <<
				", mainchain height = " << block->m_txinGenHeight << ": parent or uncle blocks are not available)");
			continue;
		}

		if (block->m_invalid) {
			LOGWARN(3, "block at height = " << block->m_sidechainHeight <<
				", id = " << block->m_sidechainId <<
				", mainchain height = " << block->m_txinGenHeight << ", mined by " << block->m_minerWallet << " is invalid");
		}
		else {
			LOGINFO(3, "verified block at height = " << block->m_sidechainHeight <<
				", depth = " << block->m_depth <<
				", id = " << block->m_sidechainId <<
				", mainchain height = " << block->m_txinGenHeight);

			// This block is now verified

			bool is_alternative;
			if (is_longer_chain(highest_block, block, is_alternative)) {
				highest_block = block;
			}
			else if (highest_block && (highest_block->m_sidechainHeight > block->m_sidechainHeight)) {
				LOGINFO(4, "block " << highest_block->m_sidechainId <<
					", height = " << highest_block->m_sidechainHeight <<
					" is not a longer chain than " << block->m_sidechainId <<
					", height " << block->m_sidechainHeight);
			}

			P2PServer* server = p2pServer();

			// If it came through a broadcast, send it to our peers
			if (block->m_wantBroadcast && !block->m_broadcasted) {
				block->m_broadcasted = true;
				if (server && (block->m_depth < UNCLE_BLOCK_DEPTH)) {
					if (m_pool && (block->m_minerWallet == m_pool->params().m_wallet)) {
						LOGINFO(0, log::Green() << "SHARE ADDED: height = " << block->m_sidechainHeight << ", id = " << block->m_sidechainId << ", mainchain height = " << block->m_txinGenHeight);
					}
					server->broadcast(*block, get_parent(block));
				}
			}

			// Save it for faster syncing on the next p2pool start
			if (server) {
				server->store_in_cache(*block);
			}

			// Try to verify blocks on top of this one
			for (size_t i = 1; i <= UNCLE_BLOCK_DEPTH; ++i) {
				auto it = m_blocksByHeight.find(block->m_sidechainHeight + i);
				if (it == m_blocksByHeight.end()) {
					continue;
				}

				const std::vector<PoolBlock*>& next_blocks = it->second;
				if (!next_blocks.empty()) {
					blocks_to_verify.insert(blocks_to_verify.end(), next_blocks.begin(), next_blocks.end());
				}
			}
		}
	}

	if (highest_block) {
		update_chain_tip(highest_block);
	}

	return;
}

void SideChain::verify(PoolBlock* block)
{
	// Genesis block
	if (block->m_sidechainHeight == 0) {
		if (!block->m_parent.empty() ||
			!block->m_uncles.empty() ||
			(block->m_difficulty != m_minDifficulty) ||
			(block->m_cumulativeDifficulty != m_minDifficulty) ||
			(block->m_txkeySecSeed != m_consensusHash))
		{
			block->m_invalid = true;
		}

		block->m_verified = true;
		return;
	}

	// Deep block
	//
	// Blocks in PPLNS window (m_chainWindowSize) require up to m_chainWindowSize earlier blocks to verify
	// If a block is deeper than (m_chainWindowSize - 1) * 2 + UNCLE_BLOCK_DEPTH it can't influence blocks in PPLNS window
	// Also, having so many blocks on top of this one means it was verified by the network at some point
	// We skip checks in this case to make pruning possible
	if (block->m_depth > (m_chainWindowSize - 1) * 2 + UNCLE_BLOCK_DEPTH) {
		LOGINFO(4, "block " << block->m_sidechainId << " skipped verification");
		block->m_verified = true;
		block->m_invalid = false;
		return;
	}

	// Regular block

	// Must have a parent
	if (block->m_parent.empty()) {
		block->m_verified = true;
		block->m_invalid = true;
		return;
	}

	// Check parent
	auto it = m_blocksById.find(block->m_parent);
	if ((it == m_blocksById.end()) || !it->second->m_verified) {
		block->m_verified = false;
		return;
	}

	// If it's invalid then this block is also invalid
	PoolBlock* parent = it->second;
	if (parent->m_invalid) {
		block->m_verified = true;
		block->m_invalid = true;
		return;
	}

	// Check m_txkeySecSeed
	const hash h = (block->m_prevId == parent->m_prevId) ? parent->m_txkeySecSeed : parent->calculate_tx_key_seed();
	if (block->m_txkeySecSeed != h) {
		LOGWARN(3, "block " << block->m_sidechainId << " has invalid tx key seed: expected " << h << ", got " << block->m_txkeySecSeed);
		block->m_verified = true;
		block->m_invalid = true;
		return;
	}

	const uint64_t expectedHeight = parent->m_sidechainHeight + 1;
	if (block->m_sidechainHeight != expectedHeight) {
		LOGWARN(3, "block at height = " << block->m_sidechainHeight <<
			", id = " << block->m_sidechainId <<
			", mainchain height = " << block->m_txinGenHeight <<
			" has wrong height: expected " << expectedHeight);
		block->m_verified = true;
		block->m_invalid = true;
		return;
	}

	// Uncle hashes must be sorted in the ascending order to prevent cheating when the same hash is repeated multiple times
	for (size_t i = 1, n = block->m_uncles.size(); i < n; ++i) {
		if (!(block->m_uncles[i - 1] < block->m_uncles[i])) {
			LOGWARN(3, "block at height = " << block->m_sidechainHeight <<
				", id = " << block->m_sidechainId <<
				", mainchain height = " << block->m_txinGenHeight << " has invalid uncle order");
			block->m_verified = true;
			block->m_invalid = true;
			return;
		}
	}

	difficulty_type expectedCumulativeDifficulty = parent->m_cumulativeDifficulty + block->m_difficulty;

	// Check uncles

	// First get a list of already mined blocks at possible uncle heights
	std::vector<hash> mined_blocks;

	if (!block->m_uncles.empty()) {
		mined_blocks.reserve(UNCLE_BLOCK_DEPTH * 2 + 1);

		PoolBlock* tmp = parent;
		for (uint64_t i = 0, n = std::min<uint64_t>(UNCLE_BLOCK_DEPTH, block->m_sidechainHeight + 1); tmp && (i < n); ++i) {
			mined_blocks.push_back(tmp->m_sidechainId);
			mined_blocks.insert(mined_blocks.end(), tmp->m_uncles.begin(), tmp->m_uncles.end());
			tmp = get_parent(tmp);
		}
	}

	for (const hash& uncle_id : block->m_uncles) {
		// Empty hash is only used in the genesis block and only for its parent
		// Uncles can't be empty
		if (uncle_id.empty()) {
			LOGWARN(3, "block at height = " << block->m_sidechainHeight <<
				", id = " << block->m_sidechainId <<
				", mainchain height = " << block->m_txinGenHeight << " has empty uncle hash");
			block->m_verified = true;
			block->m_invalid = true;
			return;
		}

		// Can't mine the same uncle block twice
		if (std::find(mined_blocks.begin(), mined_blocks.end(), uncle_id) != mined_blocks.end()) {
			LOGWARN(3, "block at height = " << block->m_sidechainHeight <<
				", id = " << block->m_sidechainId <<
				", mainchain height = " << block->m_txinGenHeight << " has an uncle (" << uncle_id << ") that's already been mined");
			block->m_verified = true;
			block->m_invalid = true;
			return;
		}

		it = m_blocksById.find(uncle_id);
		if ((it == m_blocksById.end()) || !it->second->m_verified) {
			block->m_verified = false;
			return;
		}

		PoolBlock* uncle = it->second;

		// If it's invalid then this block is also invalid
		if (uncle->m_invalid) {
			block->m_verified = true;
			block->m_invalid = true;
			return;
		}

		// Check that it has correct height
		if ((uncle->m_sidechainHeight >= block->m_sidechainHeight) || (uncle->m_sidechainHeight + UNCLE_BLOCK_DEPTH < block->m_sidechainHeight)) {
			LOGWARN(3, "block at height = " << block->m_sidechainHeight <<
				", id = " << block->m_sidechainId <<
				", mainchain height = " << block->m_txinGenHeight << " has an uncle at the wrong height (" << uncle->m_sidechainHeight << ')');
			block->m_verified = true;
			block->m_invalid = true;
			return;
		}

		// Check that uncle and parent have the same ancestor (they must be on the same chain)
		const PoolBlock* tmp = parent;
		while (tmp->m_sidechainHeight > uncle->m_sidechainHeight) {
			tmp = get_parent(tmp);
			if (!tmp) {
				LOGWARN(3, "block at height = " << block->m_sidechainHeight <<
					", id = " << block->m_sidechainId <<
					", mainchain height = " << block->m_txinGenHeight << " has an uncle from a different chain (check 1 failed)");
				block->m_verified = true;
				block->m_invalid = true;
				return;
			}
		}

		if (tmp->m_sidechainHeight < uncle->m_sidechainHeight) {
			LOGWARN(3, "block at height = " << block->m_sidechainHeight <<
				", id = " << block->m_sidechainId <<
				", mainchain height = " << block->m_txinGenHeight << " has an uncle from a different chain (check 2 failed)");
			block->m_verified = true;
			block->m_invalid = true;
			return;
		}

		bool same_chain = false;
		const PoolBlock* tmp2 = uncle;
		for (size_t j = 0; (j < UNCLE_BLOCK_DEPTH) && tmp && tmp2 && (tmp->m_sidechainHeight + UNCLE_BLOCK_DEPTH >= block->m_sidechainHeight); ++j) {
			if (tmp->m_parent == tmp2->m_parent) {
				same_chain = true;
				break;
			}
			tmp = get_parent(tmp);
			tmp2 = get_parent(tmp2);
		}

		if (!same_chain) {
			LOGWARN(3, "block at height = " << block->m_sidechainHeight <<
				", id = " << block->m_sidechainId <<
				", mainchain height = " << block->m_txinGenHeight << " has an uncle from a different chain (check 3 failed)");
			block->m_verified = true;
			block->m_invalid = true;
			return;
		}

		expectedCumulativeDifficulty += uncle->m_difficulty;
	}

	// We can verify this block now (all previous blocks in the window are verified and valid)
	// It can still turn out to be invalid
	block->m_verified = true;

	if (block->m_cumulativeDifficulty != expectedCumulativeDifficulty) {
		LOGWARN(3, "block at height = " << block->m_sidechainHeight <<
			", id = " << block->m_sidechainId <<
			", mainchain height = " << block->m_txinGenHeight <<
			" has wrong cumulative difficulty: got " << block->m_cumulativeDifficulty << ", expected " << expectedCumulativeDifficulty);
		block->m_invalid = true;
		return;
	}

	// Verify difficulty and miner rewards only for blocks in PPLNS window
	if (block->m_depth >= m_chainWindowSize) {
		LOGINFO(4, "block " << block->m_sidechainId << " skipped diff/reward verification");
		block->m_invalid = false;
		return;
	}

	difficulty_type diff;
	if (parent == m_chainTip) {
		LOGINFO(6, "block " << block->m_sidechainId << " is built on top of the current chain tip, using current difficulty for verification");
		diff = difficulty();
	}
	else if (!get_difficulty(parent, m_difficultyData, diff)) {
		block->m_invalid = true;
		return;
	}

	if (diff != block->m_difficulty) {
		LOGWARN(3, "block at height = " << block->m_sidechainHeight <<
			", id = " << block->m_sidechainId <<
			", mainchain height = " << block->m_txinGenHeight <<
			" has wrong difficulty: got " << block->m_difficulty << ", expected " << diff);
		block->m_invalid = true;
		return;
	}

	std::vector<MinerShare> shares;
	if (!get_shares(block, shares)) {
		block->m_invalid = true;
		return;
	}

	if (shares.size() != block->m_outputs.size()) {
		LOGWARN(3, "block at height = " << block->m_sidechainHeight <<
			", id = " << block->m_sidechainId <<
			", mainchain height = " << block->m_txinGenHeight
			<< " has invalid number of outputs: got " << block->m_outputs.size() << ", expected " << shares.size());
		block->m_invalid = true;
		return;
	}

	uint64_t total_reward = std::accumulate(block->m_outputs.begin(), block->m_outputs.end(), 0ULL,
		[](uint64_t a, const PoolBlock::TxOutput& b)
		{
			return a + b.m_reward;
		});

	std::vector<uint64_t> rewards;
	if (!split_reward(total_reward, shares, rewards)) {
		LOGWARN(3, "block at height = " << block->m_sidechainHeight <<
			", id = " << block->m_sidechainId <<
			", mainchain height = " << block->m_txinGenHeight << ": split_reward failed");
		block->m_invalid = true;
		return;
	}

	if (rewards.size() != block->m_outputs.size()) {
		LOGWARN(3, "block at height = " << block->m_sidechainHeight <<
			", id = " << block->m_sidechainId <<
			", mainchain height = " << block->m_txinGenHeight
			<< " has invalid number of outputs: got " << block->m_outputs.size() << ", expected " << rewards.size());
		block->m_invalid = true;
		return;
	}

	const uint8_t tx_type = block->get_tx_type();

	for (size_t i = 0, n = rewards.size(); i < n; ++i) {
		const PoolBlock::TxOutput& out = block->m_outputs[i];

		if (rewards[i] != out.m_reward) {
			LOGWARN(3, "block at height = " << block->m_sidechainHeight <<
				", id = " << block->m_sidechainId <<
				", mainchain height = " << block->m_txinGenHeight <<
				" has invalid reward at index " << i << ": got " << out.m_reward << ", expected " << rewards[i]);
			block->m_invalid = true;
			return;
		}

		hash eph_public_key;
		uint8_t view_tag;
		if (!shares[i].m_wallet->get_eph_public_key(block->m_txkeySec, i, eph_public_key, view_tag)) {
			LOGWARN(3, "block at height = " << block->m_sidechainHeight <<
				", id = " << block->m_sidechainId <<
				", mainchain height = " << block->m_txinGenHeight <<
				" failed to eph_public_key at index " << i);
			block->m_invalid = true;
			return;
		}

		if ((tx_type == TXOUT_TO_TAGGED_KEY) && (out.m_viewTag != view_tag)) {
			LOGWARN(3, "block at height = " << block->m_sidechainHeight <<
				", id = " << block->m_sidechainId <<
				", mainchain height = " << block->m_txinGenHeight <<
				" has an incorrect view tag at index " << i);
			block->m_invalid = true;
			return;
		}

		if (eph_public_key != out.m_ephPublicKey) {
			LOGWARN(3, "block at height = " << block->m_sidechainHeight <<
				", id = " << block->m_sidechainId <<
				", mainchain height = " << block->m_txinGenHeight <<
				" pays out to a wrong wallet at index " << i);
			block->m_invalid = true;
			return;
		}
	}

	// All checks passed
	block->m_invalid = false;
}

void SideChain::update_chain_tip(const PoolBlock* block)
{
	if (!block->m_verified || block->m_invalid) {
		LOGERR(1, "trying to update chain tip to an unverified or invalid block, fix the code!");
		return;
	}

	if (block->m_depth >= m_chainWindowSize) {
		LOGINFO(5, "Trying to update chain tip to a block with depth " << block->m_depth << ". Ignoring it.");
		return;
	}

	const PoolBlock* tip = m_chainTip;

	if (block == tip) {
		LOGINFO(5, "Trying to update chain tip to the same block again. Ignoring it.");
		return;
	}

	bool is_alternative;
	if (is_longer_chain(tip, block, is_alternative)) {
		difficulty_type diff;
		if (get_difficulty(block, m_difficultyData, diff)) {
			m_chainTip = const_cast<PoolBlock*>(block);
			{
				WriteLock lock(m_curDifficultyLock);
				m_curDifficulty = diff;
			}

			LOGINFO(2, "new chain tip: next height = " << log::Gray() << block->m_sidechainHeight + 1 << log::NoColor() <<
				", next difficulty = " << log::Gray() << diff << log::NoColor() <<
				", main chain height = " << log::Gray() << block->m_txinGenHeight);

			block->m_wantBroadcast = true;
			if (m_pool) {
				m_pool->update_block_template_async(is_alternative);

				// Reset stratum share counters when switching to an alternative chain to avoid confusion
				if (is_alternative) {
					StratumServer* s = m_pool->stratum_server();
					if (s) {
						s->reset_share_counters();
					}
					// Also clear cache because it has data from all old blocks now
					clear_crypto_cache();
					LOGINFO(0, log::LightCyan() << "SYNCHRONIZED");
				}
			}
			prune_old_blocks();
			cleanup_incoming_blocks();
		}
	}
	else if (block->m_sidechainHeight > tip->m_sidechainHeight) {
		LOGINFO(4, "block " << block->m_sidechainId <<
			", height = " << block->m_sidechainHeight <<
			" is not a longer chain than " << tip->m_sidechainId <<
			", height " << tip->m_sidechainHeight);
	}
	else if (m_pool && (block->m_sidechainHeight + UNCLE_BLOCK_DEPTH > tip->m_sidechainHeight)) {
		LOGINFO(4, "possible uncle block: id = " << log::Gray() << block->m_sidechainId << log::NoColor() <<
			", height = " << log::Gray() << block->m_sidechainHeight);
		m_pool->update_block_template_async();
	}

	if (p2pServer() && block->m_wantBroadcast && !block->m_broadcasted) {
		block->m_broadcasted = true;
		p2pServer()->broadcast(*block, get_parent(block));
	}
}

PoolBlock* SideChain::get_parent(const PoolBlock* block) const
{
	auto it = m_blocksById.find(block->m_parent);
	return (it != m_blocksById.end()) ? it->second : nullptr;
}

bool SideChain::is_longer_chain(const PoolBlock* block, const PoolBlock* candidate, bool& is_alternative) const
{
	is_alternative = false;

	if (!candidate || !candidate->m_verified || candidate->m_invalid) {
		return false;
	}

	if (!block) {
		// Switching from an empty to a non-empty chain
		is_alternative = true;
		return true;
	}

	// If these two blocks are on the same chain, they must have a common ancestor

	const PoolBlock* block_ancestor = block;
	while (block_ancestor && (block_ancestor->m_sidechainHeight > candidate->m_sidechainHeight)) {
		const hash& id = block_ancestor->m_parent;
		block_ancestor = get_parent(block_ancestor);
		if (!block_ancestor) {
			LOGINFO(4, "couldn't find ancestor " << id << " of block " << block->m_sidechainId << " at height " << block->m_sidechainHeight);
			break;
		}
	}

	if (block_ancestor) {
		const PoolBlock* candidate_ancestor = candidate;
		while (candidate_ancestor->m_sidechainHeight > block_ancestor->m_sidechainHeight) {
			const hash& id = candidate_ancestor->m_parent;
			candidate_ancestor = get_parent(candidate_ancestor);
			if (!candidate_ancestor) {
				LOGINFO(4, "couldn't find ancestor " << id << " of block " << candidate->m_sidechainId << " at height " << candidate->m_sidechainHeight);
				break;
			}
		}

		// cppcheck-suppress knownConditionTrueFalse
		while (block_ancestor && candidate_ancestor) {
			if (block_ancestor->m_parent == candidate_ancestor->m_parent) {
				// If they are really on the same chain, we can just compare cumulative difficulties
				return block->m_cumulativeDifficulty < candidate->m_cumulativeDifficulty;
			}
			block_ancestor = get_parent(block_ancestor);
			candidate_ancestor = get_parent(candidate_ancestor);
		}
	}

	// They're on totally different chains. Compare total difficulties over the last m_chainWindowSize blocks
	is_alternative = true;

	difficulty_type block_total_diff;
	difficulty_type candidate_total_diff;

	const PoolBlock* old_chain = block;
	const PoolBlock* new_chain = candidate;

	uint64_t candidate_mainchain_height = 0;
	uint64_t candidate_mainchain_min_height = 0;

	unordered_set<hash> current_chain_monero_blocks, candidate_chain_monero_blocks;
	{
		const uint64_t k = m_chainWindowSize * m_targetBlockTime * 2 / MONERO_BLOCK_TIME;
		current_chain_monero_blocks.reserve(k);
		candidate_chain_monero_blocks.reserve(k);
	}

	for (uint64_t i = 0; (i < m_chainWindowSize) && (old_chain || new_chain); ++i) {
		if (old_chain) {
			block_total_diff += old_chain->m_difficulty;

			for (const hash& uncle : old_chain->m_uncles) {
				auto it = m_blocksById.find(uncle);
				if (it != m_blocksById.end()) {
					block_total_diff += it->second->m_difficulty;
				}
			}

			ChainMain data;
			const hash& h = old_chain->m_prevId;

			if ((current_chain_monero_blocks.count(h) == 0) && m_pool->chainmain_get_by_hash(h, data)) {
				current_chain_monero_blocks.insert(h);
			}

			old_chain = get_parent(old_chain);
		}

		if (new_chain) {
			candidate_mainchain_min_height = candidate_mainchain_min_height ? std::min(candidate_mainchain_min_height, new_chain->m_txinGenHeight) : new_chain->m_txinGenHeight;
			candidate_total_diff += new_chain->m_difficulty;

			for (const hash& uncle : new_chain->m_uncles) {
				auto it = m_blocksById.find(uncle);
				if (it != m_blocksById.end()) {
					candidate_total_diff += it->second->m_difficulty;
				}
			}

			ChainMain data;
			const hash& h = new_chain->m_prevId;

			if ((candidate_chain_monero_blocks.count(h) == 0) && m_pool->chainmain_get_by_hash(h, data)) {
				candidate_chain_monero_blocks.insert(h);
				candidate_mainchain_height = std::max(candidate_mainchain_height, data.height);
			}

			new_chain = get_parent(new_chain);
		}
	}

	if (block_total_diff >= candidate_total_diff) {
		return false;
	}

	// Candidate chain must be built on top of recent mainchain blocks
	MinerData data = m_pool->miner_data();
	if (candidate_mainchain_height + 10 < data.height) {
		LOGWARN(3, "received a longer alternative chain but it's stale: height " << candidate_mainchain_height << ", current height " << data.height);
		return false;
	}

	const uint64_t limit = m_chainWindowSize * 4 * m_targetBlockTime / MONERO_BLOCK_TIME;
	if (candidate_mainchain_min_height + limit < data.height) {
		LOGWARN(3, "received a longer alternative chain but it's stale: min height " << candidate_mainchain_min_height << ", must be >= " << (data.height - limit));
		return false;
	}

	// Candidate chain must have been mined on top of at least half as many known Monero blocks, compared to the current chain
	if (candidate_chain_monero_blocks.size() * 2 < current_chain_monero_blocks.size()) {
		LOGWARN(3, "received a longer alternative chain but it wasn't mined on current Monero blockchain: only " << candidate_chain_monero_blocks.size() << '/' << current_chain_monero_blocks.size() << " blocks found");
		return false;
	}

	LOGINFO(3, "received a longer alternative chain: height " <<
		log::Gray() << block->m_sidechainHeight << log::NoColor() << " -> " <<
		log::Gray() << candidate->m_sidechainHeight << log::NoColor() << ", cumulative difficulty " <<
		log::Gray() << block->m_cumulativeDifficulty << log::NoColor() << " -> " <<
		log::Gray() << candidate->m_cumulativeDifficulty);

	return true;
}

void SideChain::update_depths(PoolBlock* block)
{
	const uint64_t precalc_depth = m_chainWindowSize + UNCLE_BLOCK_DEPTH - 1;

	auto update_depth = [this, precalc_depth](PoolBlock* b, const uint64_t new_depth) {
		const uint64_t old_depth = b->m_depth;
		if (old_depth < new_depth) {
			b->m_depth = new_depth;
			if ((old_depth < precalc_depth) && (new_depth >= precalc_depth)) {
				launch_precalc(b);
			}
		}
	};

	for (size_t i = 1; i <= UNCLE_BLOCK_DEPTH; ++i) {
		auto it = m_blocksByHeight.find(block->m_sidechainHeight + i);
		if (it == m_blocksByHeight.end()) {
			continue;
		}
		for (PoolBlock* child : it->second) {
			if (child->m_parent == block->m_sidechainId) {
				if (i != 1) {
					LOGWARN(3, "Block " << block->m_sidechainId << ": m_sidechainHeight is inconsistent with child's m_sidechainHeight.");
					return;
				}
				else {
					update_depth(block, child->m_depth + 1);
				}
			}

			if (std::find(child->m_uncles.begin(), child->m_uncles.end(), block->m_sidechainId) != child->m_uncles.end()) {
				update_depth(block, child->m_depth + i);
			}
		}
	}

	std::vector<PoolBlock*> blocks_to_update(1, block);

	do {
		block = blocks_to_update.back();
		blocks_to_update.pop_back();

		// Verify this block and possibly other blocks on top of it when we're sure it will get verified
		if (!block->m_verified && ((block->m_depth > (m_chainWindowSize - 1) * 2 + UNCLE_BLOCK_DEPTH) || (block->m_sidechainHeight == 0))) {
			verify_loop(block);
		}

		for (size_t i = 1; i <= UNCLE_BLOCK_DEPTH; ++i) {
			auto it = m_blocksByHeight.find(block->m_sidechainHeight + i);
			if (it == m_blocksByHeight.end()) {
				continue;
			}
			for (PoolBlock* child : it->second) {
				const uint64_t old_depth = child->m_depth;

				if (child->m_parent == block->m_sidechainId) {
					if (i != 1) {
						LOGWARN(3, "Block " << block->m_sidechainId << ": m_sidechainHeight is inconsistent with child's m_sidechainHeight.");
						return;
					}
					else if (block->m_depth > 0) {
						update_depth(child, block->m_depth - 1);
					}
				}

				if (std::find(child->m_uncles.begin(), child->m_uncles.end(), block->m_sidechainId) != child->m_uncles.end()) {
					if (block->m_depth > i) {
						update_depth(child, block->m_depth - i);
					}
				}

				if (child->m_depth > old_depth) {
					blocks_to_update.push_back(child);
				}
			}
		}

		auto it = m_blocksById.find(block->m_parent);
		if (it != m_blocksById.end()) {
			if (it->second->m_sidechainHeight + 1 != block->m_sidechainHeight) {
				LOGWARN(3, "Block " << block->m_sidechainId << ": m_sidechainHeight is inconsistent with parent's m_sidechainHeight.");
				return;
			}

			if (it->second->m_depth < block->m_depth + 1) {
				update_depth(it->second, block->m_depth + 1);
				blocks_to_update.push_back(it->second);
			}
		}

		for (const hash& uncle_id : block->m_uncles) {
			it = m_blocksById.find(uncle_id);
			if (it == m_blocksById.end()) {
				continue;
			}

			if ((it->second->m_sidechainHeight >= block->m_sidechainHeight) || (it->second->m_sidechainHeight + UNCLE_BLOCK_DEPTH < block->m_sidechainHeight)) {
				LOGWARN(3, "Block " << block->m_sidechainId << ": m_sidechainHeight is inconsistent with uncle's m_sidechainHeight.");
				return;
			}

			const uint64_t d = block->m_sidechainHeight - it->second->m_sidechainHeight;
			if (it->second->m_depth < block->m_depth + d) {
				update_depth(it->second, block->m_depth + d);
				blocks_to_update.push_back(it->second);
			}
		}
	} while (!blocks_to_update.empty());
}

void SideChain::prune_old_blocks()
{
	// Leave 2 minutes worth of spare blocks in addition to 2xPPLNS window for lagging nodes which need to sync
	const uint64_t prune_distance = m_chainWindowSize * 2 + MONERO_BLOCK_TIME / m_targetBlockTime;

	// Remove old blocks from alternative unconnected chains after long enough time
	const uint64_t cur_time = seconds_since_epoch();
	const uint64_t prune_delay = m_chainWindowSize * 4 * m_targetBlockTime;

	const PoolBlock* tip = m_chainTip;

	if (tip->m_sidechainHeight < prune_distance) {
		return;
	}

	const uint64_t h = tip->m_sidechainHeight - prune_distance;

	std::vector<PoolBlock*> blocks_to_prune;

	for (auto it = m_blocksByHeight.begin(); (it != m_blocksByHeight.end()) && (it->first <= h);) {
		const uint64_t height = it->first;
		std::vector<PoolBlock*>& v = it->second;

		v.erase(std::remove_if(v.begin(), v.end(),
			[this, prune_distance, cur_time, prune_delay, &blocks_to_prune, height](PoolBlock* block)
			{
				if ((block->m_depth >= prune_distance) || (cur_time >= block->m_localTimestamp + prune_delay)) {
					auto it2 = m_blocksById.find(block->m_sidechainId);
					if (it2 != m_blocksById.end()) {
						m_blocksById.erase(it2);
						blocks_to_prune.push_back(block);
					}
					else {
						LOGERR(1, "m_blocksByHeight and m_blocksById are inconsistent at height " << height << ". Fix the code!");
					}

					auto it3 = m_blocksByMerkleRoot.find(block->m_merkleRoot);
					if (it3 != m_blocksByMerkleRoot.end()) {
						m_blocksByMerkleRoot.erase(it3);
					}
					else {
						LOGERR(1, "m_blocksByHeight and m_blocksByMerkleRoot are inconsistent at height " << height << ". Fix the code!");
					}

					return true;
				}
				return false;
			}), v.end());

		if (v.empty()) {
			it = m_blocksByHeight.erase(it);
		}
		else {
			++it;
		}
	}

	if (!blocks_to_prune.empty()) {
		LOGINFO(4, "pruned " << blocks_to_prune.size() << " old blocks at heights <= " << h);

		// If side-chain started pruning blocks it means the initial sync is complete
		// It's now safe to delete cached blocks
		if (p2pServer()) {
			p2pServer()->clear_cached_blocks();
		}

		// Pre-calc workers are not needed anymore
		finish_precalc();

		// We can only delete old blocks after the precalc is stopped because it can still use some of them
		for (const PoolBlock* b : blocks_to_prune) {
			delete b;
		}

#ifdef DEV_TEST_SYNC
		if (m_firstPruneTime == 0) {
			m_firstPruneTime = seconds_since_epoch();

			// Test Monero node switching
			m_pool->reconnect_to_host();
		}

		if ((cur_time >= m_firstPruneTime + 120) && !m_pool->stopped()) {
			LOGINFO(0, log::LightGreen() << "[DEV] Synchronization finished successfully, stopping P2Pool now");
#ifdef DEV_TRACK_MEMORY
			show_top_10_allocations();
#endif
			print_status(false);

			StratumServer* server1 = m_pool->stratum_server();
			P2PServer* server2 = m_pool->p2p_server();

			if (server1 && server2) {
				server1->print_status();
				server2->print_status();

				server1->print_bans();
				server2->print_bans();

				server1->show_workers_async();
				server2->show_peers_async();
			}

			m_pool->print_hosts();
			bkg_jobs_tracker.print_status();
			m_pool->stop();
		}
#endif
	}
}

void SideChain::get_missing_blocks(unordered_set<hash>& missing_blocks) const
{
	missing_blocks.clear();

	ReadLock lock(m_sidechainLock);

	for (auto& b : m_blocksById) {
		if (b.second->m_verified) {
			continue;
		}

		if (!b.second->m_parent.empty() && (m_blocksById.find(b.second->m_parent) == m_blocksById.end())) {
			missing_blocks.insert(b.second->m_parent);
		}

		int num_missing_uncles = 0;

		for (const hash& h : b.second->m_uncles) {
			if (!h.empty() && (m_blocksById.find(h) == m_blocksById.end())) {
				missing_blocks.insert(h);

				// Get no more than 2 first missing uncles at a time from each block
				// Blocks with more than 2 uncles are very rare and they will be processed in several steps
				++num_missing_uncles;
				if (num_missing_uncles >= 2) {
					break;
				}
			}
		}
	}
}

bool SideChain::load_config(const std::string& filename)
{
	if (filename.empty()) {
		LOGINFO(1, "using default config");
		return true;
	}

	LOGINFO(1, "loading config from " << log::Gray() << filename);

	std::ifstream f(filename);
	if (!f.is_open()) {
		LOGERR(1, "can't open " << filename);
		return false;
	}

	rapidjson::Document doc;
	rapidjson::IStreamWrapper s(f);
	if (doc.ParseStream<rapidjson::kParseCommentsFlag | rapidjson::kParseTrailingCommasFlag>(s).HasParseError()) {
		LOGERR(1, "failed to parse JSON data in " << filename);
		return false;
	}

	if (!doc.IsObject()) {
		LOGERR(1, "invalid JSON data in " << filename << ": top level is not an object");
		return false;
	}

	parseValue(doc, "name", m_poolName);
	parseValue(doc, "password", m_poolPassword);
	parseValue(doc, "block_time", m_targetBlockTime);

	uint64_t min_diff;
	if (parseValue(doc, "min_diff", min_diff) && min_diff) {
		m_minDifficulty = { min_diff, 0 };
	}

	parseValue(doc, "pplns_window", m_chainWindowSize);
	parseValue(doc, "uncle_penalty", m_unclePenalty);

	return true;
}

bool SideChain::check_config() const
{
	if (m_poolName.empty()) {
		LOGERR(1, "name can't be empty");
		return false;
	}

	if (m_poolName.length() > 128) {
		LOGERR(1, "name is too long (must be 128 characters max)");
		return false;
	}

	if (m_poolPassword.length() > 128) {
		LOGERR(1, "password is too long (must be 128 characters max)");
		return false;
	}

	if ((m_targetBlockTime < 1) || (m_targetBlockTime > MONERO_BLOCK_TIME)) {
		LOGERR(1, "block_time is invalid (must be between 1 and " << MONERO_BLOCK_TIME << ")");
		return false;
	}

	if (s_networkType == NetworkType::Mainnet) {
		const difficulty_type min_diff{ MIN_DIFFICULTY, 0 };
		const difficulty_type max_diff{ 1000000000, 0 };

		if ((m_minDifficulty < min_diff) || (max_diff < m_minDifficulty)) {
			LOGERR(1, "min_diff is invalid (must be between " << min_diff << " and " << max_diff << ')');
			return false;
		}
	}

	if ((m_chainWindowSize < 60) || (m_chainWindowSize > 2160)) {
		LOGERR(1, "pplns_window is invalid (must be between 60 and 2160)");
		return false;
	}

	if ((m_unclePenalty < 1) || (m_unclePenalty > 99)) {
		LOGERR(1, "uncle_penalty is invalid (must be between 1 and 99)");
		return false;
	}

	LOGINFO(1, log::LightCyan() << "pool name     = " << m_poolName);
	LOGINFO(1, log::LightCyan() << "block time    = " << m_targetBlockTime << " seconds");
	LOGINFO(1, log::LightCyan() << "min diff      = " << m_minDifficulty);
	LOGINFO(1, log::LightCyan() << "PPLNS window  = " << m_chainWindowSize << " blocks");
	LOGINFO(1, log::LightCyan() << "uncle penalty = " << m_unclePenalty << '%');

	return true;
}

void SideChain::launch_precalc(const PoolBlock* block)
{
	if (m_precalcFinished) {
		return;
	}

	for (int h = UNCLE_BLOCK_DEPTH; h >= 0; --h) {
		auto it = m_blocksByHeight.find(block->m_sidechainHeight + m_chainWindowSize + h - 1);
		if (it == m_blocksByHeight.end()) {
			continue;
		}
		for (PoolBlock* b : it->second) {
			if (b->m_precalculated) {
				continue;
			}
			std::vector<MinerShare> shares;
			if (get_shares(b, shares, nullptr, true)) {
				b->m_precalculated = true;
				PrecalcJob* job = new PrecalcJob{ b, std::move(shares) };
				{
					MutexLock lock2(m_precalcJobsMutex);
					m_precalcJobs.push_back(job);
				}
				uv_cond_signal(&m_precalcJobsCond);
			}
		}
	}
}

void SideChain::precalc_worker()
{
	do {
		PrecalcJob* job;
		size_t num_inputs;
		{
			MutexLock lock(m_precalcJobsMutex);

			if (m_precalcFinished) {
				return;
			}

			while (m_precalcJobs.empty()) {
				uv_cond_wait(&m_precalcJobsCond, &m_precalcJobsMutex);

				if (m_precalcFinished) {
					return;
				}
			}

			job = m_precalcJobs.back();
			m_precalcJobs.pop_back();

			// Filter out duplicate inputs for get_eph_public_key()
			uint8_t t[HASH_SIZE * 2 + sizeof(size_t)];
			memcpy(t, job->b->m_txkeySec.h, HASH_SIZE);

			const size_t n = job->shares.size();
			num_inputs = n;

			for (size_t i = 0; i < n; ++i) {
				memcpy(t + HASH_SIZE, job->shares[i].m_wallet->view_public_key().h, HASH_SIZE);
				memcpy(t + HASH_SIZE * 2, &i, sizeof(i));
				if (!m_uniquePrecalcInputs->insert(robin_hood::hash_bytes(t, array_size(t))).second) {
					job->shares[i].m_wallet = nullptr;
					--num_inputs;
				}
			}
		}

		if (num_inputs) {
			for (size_t i = 0, n = job->shares.size(); i < n; ++i) {
				if (job->shares[i].m_wallet) {
					hash eph_public_key;
					uint8_t view_tag;
					job->shares[i].m_wallet->get_eph_public_key(job->b->m_txkeySec, i, eph_public_key, view_tag);
				}
			}
		}

		delete job;
	} while (true);
}

void SideChain::finish_precalc()
{
	if (m_precalcFinished.exchange(true)) {
		return;
	}

	try
	{
		{
			MutexLock lock(m_precalcJobsMutex);
			for (PrecalcJob* job : m_precalcJobs) {
				delete job;
			}
			m_precalcJobs.clear();
			m_precalcJobs.shrink_to_fit();
			uv_cond_broadcast(&m_precalcJobsCond);
		}

		for (std::thread& t : m_precalcWorkers) {
			t.join();
		}
		m_precalcWorkers.clear();
		m_precalcWorkers.shrink_to_fit();

		delete m_uniquePrecalcInputs;
		m_uniquePrecalcInputs = nullptr;

		uv_mutex_destroy(&m_precalcJobsMutex);
		uv_cond_destroy(&m_precalcJobsCond);

		// Also clear cache because it has data from all old blocks now
		clear_crypto_cache();

		LOGINFO(4, "pre-calculation workers stopped");
	}
	catch (const std::exception& e)
	{
		LOGERR(1, "exception in finish_precalc(): " << e.what());
	}
}

} // namespace p2pool
