/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2025 SChernykh <https://github.com/SChernykh>
 * Portions Copyright (c) 2012-2013 The Cryptonote developers
 * Portions Copyright (c) 2014-2021 The Monero Project
 * Portions Copyright (c) 2021 XMRig <https://github.com/xmrig>
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
#include "block_template.h"
#include "wallet.h"
#include "crypto.h"
#include "keccak.h"
#include "mempool.h"
#include "p2pool.h"
#include "side_chain.h"
#include "pool_block.h"
#include "params.h"
#include "merkle.h"
#include <zmq.hpp>
#include <ctime>
#include <numeric>

LOG_CATEGORY(BlockTemplate)

namespace p2pool {

BlockTemplate::BlockTemplate(SideChain* sidechain, RandomX_Hasher_Base* hasher)
	: m_sidechain(sidechain)
	, m_hasher(hasher)
	, m_templateId(0)
	, m_lastUpdated(seconds_since_epoch())
	, m_blockHeaderSize(0)
	, m_minerTxOffsetInTemplate(0)
	, m_minerTxSize(0)
	, m_nonceOffset(0)
	, m_extraNonceOffsetInTemplate(0)
	, m_numTransactionHashes(0)
	, m_prevId{}
	, m_height(0)
	, m_difficulty{}
	, m_auxDifficulty{}
	, m_seedHash{}
	, m_timestamp(0)
	, m_poolBlockTemplate(new PoolBlock())
	, m_finalReward(0)
	, m_minerTxKeccakState{}
	, m_minerTxKeccakStateInputLength(0)
	, m_sidechainHashKeccakState{}
	, m_sidechainHashInputLength(0)
	, m_rng(RandomDeviceSeed::instance)
{
	// Diffuse the initial state in case it has low quality
	m_rng.discard(10000);

	uv_rwlock_init_checked(&m_lock);

	m_blockHeader.reserve(64);
	m_minerTx.reserve(49152);
	m_minerTxExtra.reserve(64);
	m_transactionHashes.reserve(8192);
	m_rewards.reserve(100);
	m_blockTemplateBlob.reserve(65536);
	m_fullDataBlob.reserve(65536);
	m_sidechainHashBlob.reserve(65536);
	m_merkleTreeMainBranch.reserve(HASH_SIZE * 10);
	m_mempoolTxs.reserve(1024);
	m_mempoolTxsOrder.reserve(1024);
	m_mempoolTxsOrder2.reserve(1024);
	m_shares.reserve(m_sidechain->chain_window_size() * 2);

	for (size_t i = 0; i < array_size(&BlockTemplate::m_oldTemplates); ++i) {
		m_oldTemplates[i] = new BlockTemplate(*this);
	}

#if TEST_MEMPOOL_PICKING_ALGORITHM
	m_knapsack.reserve(512 * 309375);
#endif
}

BlockTemplate::~BlockTemplate()
{
	for (size_t i = 0; i < array_size(&BlockTemplate::m_oldTemplates); ++i) {
		delete m_oldTemplates[i];
	}

	uv_rwlock_destroy(&m_lock);

	delete m_poolBlockTemplate;
}

BlockTemplate::BlockTemplate(const BlockTemplate& b)
	: m_poolBlockTemplate(new PoolBlock())
{
	uv_rwlock_init_checked(&m_lock);
	*this = b;
}

// cppcheck-suppress operatorEqVarError
BlockTemplate& BlockTemplate::operator=(const BlockTemplate& b)
{
	if (this == &b) {
		return *this;
	}

	WriteLock lock(m_lock);

	m_sidechain = b.m_sidechain;
	m_hasher = b.m_hasher;
	m_templateId = b.m_templateId;
	m_lastUpdated = b.m_lastUpdated.load();
	m_blockTemplateBlob = b.m_blockTemplateBlob;
	m_fullDataBlob = b.m_fullDataBlob;
	m_sidechainHashBlob = b.m_sidechainHashBlob;
	m_merkleTreeMainBranch = b.m_merkleTreeMainBranch;
	m_blockHeaderSize = b.m_blockHeaderSize;
	m_minerTxOffsetInTemplate = b.m_minerTxOffsetInTemplate;
	m_minerTxSize = b.m_minerTxSize;
	m_nonceOffset = b.m_nonceOffset;
	m_extraNonceOffsetInTemplate = b.m_extraNonceOffsetInTemplate;
	m_numTransactionHashes = b.m_numTransactionHashes;
	m_prevId = b.m_prevId;
	m_height = b.m_height.load();
	m_difficulty = b.m_difficulty;
	m_auxDifficulty = b.m_auxDifficulty;
	m_seedHash = b.m_seedHash;
	m_timestamp = b.m_timestamp;
	*m_poolBlockTemplate = *b.m_poolBlockTemplate;
	m_finalReward = b.m_finalReward.load();

	m_minerTxKeccakState = b.m_minerTxKeccakState;
	m_minerTxKeccakStateInputLength = b.m_minerTxKeccakStateInputLength;

	m_sidechainHashKeccakState = b.m_sidechainHashKeccakState;
	m_sidechainHashInputLength = b.m_sidechainHashInputLength;

	m_minerTx.clear();
	m_blockHeader.clear();
	m_minerTxExtra.clear();
	m_transactionHashes.clear();
	m_rewards.clear();
	m_mempoolTxs.clear();
	m_mempoolTxsOrder.clear();
	m_mempoolTxsOrder2.clear();
	m_shares.clear();

	m_rng = b.m_rng;

#if TEST_MEMPOOL_PICKING_ALGORITHM
	m_knapsack.clear();
#endif

	return *this;
}

static FORCEINLINE uint64_t get_base_reward(uint64_t already_generated_coins)
{
	const uint64_t result = ~already_generated_coins >> 19;
	return (result < BASE_BLOCK_REWARD) ? BASE_BLOCK_REWARD : result;
}

static FORCEINLINE uint64_t get_block_reward(uint64_t base_reward, uint64_t median_weight, uint64_t fees, uint64_t weight)
{
	if (weight <= median_weight) {
		return base_reward + fees;
	}

	if (weight > median_weight * 2) {
		return 0;
	}

	// This will overflow if median_weight >= 2^32
	// Maybe fix it later like in Monero code, but it'll be fiiiine for now...
	// Performance of this code is more important

	uint64_t product[2];
	product[0] = umul128(base_reward, (median_weight * 2 - weight) * weight, &product[1]);

	uint64_t rem;
	uint64_t reward = udiv128(product[1], product[0], median_weight * median_weight, &rem);

	return reward + fees;
}

void BlockTemplate::shuffle_tx_order()
{
	const uint64_t n = m_mempoolTxsOrder.size();
	if (n > 1) {
		for (uint64_t i = 0, k; i < n - 1; ++i) {
			umul128(m_rng(), n - i, &k);
			std::swap(m_mempoolTxsOrder[i], m_mempoolTxsOrder[i + k]);
		}
	}
}

void BlockTemplate::update(const MinerData& data, const Mempool& mempool, const Wallet* miner_wallet)
{
	if (data.major_version > HARDFORK_SUPPORTED_VERSION) {
		LOGERR(1, "got hardfork version " << data.major_version << ", expected <= " << HARDFORK_SUPPORTED_VERSION);
		return;
	}

	// Block template construction is relatively slow, but it's better to keep the lock the whole time
	// instead of using temporary variables and making a quick swap in the end
	// 
	// All readers will line up for the new template instead of using the outdated template
	WriteLock lock(m_lock);

	if (m_templateId > 0) {
		*m_oldTemplates[m_templateId % array_size(&BlockTemplate::m_oldTemplates)] = *this;
	}

	++m_templateId;
	m_lastUpdated = seconds_since_epoch();

	// When block template generation fails for any reason
	auto use_old_template = [this]() {
		const uint32_t id = m_templateId - 1;
		LOGWARN(4, "using old block template with ID = " << id);
		*this = *m_oldTemplates[id % array_size(&BlockTemplate::m_oldTemplates)];
	};

	m_height = data.height;
	m_difficulty = data.difficulty;
	m_seedHash = data.seed_hash;

	m_blockHeader.clear();
	m_poolBlockTemplate->m_verified = false;

	// Major and minor hardfork version
	m_blockHeader.push_back(data.major_version);
	m_blockHeader.push_back(HARDFORK_SUPPORTED_VERSION);
	m_poolBlockTemplate->m_majorVersion = data.major_version;
	m_poolBlockTemplate->m_minorVersion = HARDFORK_SUPPORTED_VERSION;

	// Timestamp
	m_timestamp = time(nullptr);
	if (m_timestamp <= data.median_timestamp) {
		LOGWARN(2, "timestamp adjusted from " << m_timestamp << " to " << data.median_timestamp + 1 << ". Fix your system time!");
		m_timestamp = data.median_timestamp + 1;
	}

	writeVarint(m_timestamp, m_blockHeader);
	m_poolBlockTemplate->m_timestamp = m_timestamp;

	// Previous block id
	m_blockHeader.insert(m_blockHeader.end(), data.prev_id.h, data.prev_id.h + HASH_SIZE);
	m_prevId = data.prev_id;
	m_poolBlockTemplate->m_prevId = m_prevId;

	// Miner nonce
	m_nonceOffset = m_blockHeader.size();
	m_blockHeader.insert(m_blockHeader.end(), NONCE_SIZE, 0);
	m_poolBlockTemplate->m_nonce = 0;

	// Fill in m_txinGenHeight here so get_shares() can use it to calculate the correct PPLNS window
	m_poolBlockTemplate->m_txinGenHeight = data.height;

	m_blockHeaderSize = m_blockHeader.size();

	m_poolBlockTemplate->m_minerWallet = *miner_wallet;

	m_sidechain->fill_sidechain_data(*m_poolBlockTemplate, m_shares);

	// Pre-calculate outputs to speed up miner tx generation
	if (!m_shares.empty()) {
		struct Precalc
		{
			FORCEINLINE Precalc(const std::vector<MinerShare>& s, const hash& k) : txKeySec(k)
			{
				const size_t N = s.size();
				counter = static_cast<int>(N) - 1;
				shares = reinterpret_cast<std::pair<hash, hash>*>(malloc_hook(sizeof(std::pair<hash, hash>) * N));
				if (shares) {
					const MinerShare* src = &s[0];
					std::pair<hash, hash>* dst = shares;
					const std::pair<hash, hash>* e = shares + N;

					for (; dst < e; ++src, ++dst) {
						const Wallet* w = src->m_wallet;
						dst->first = w->view_public_key();
						dst->second = w->spend_public_key();
					}
				}
			}

			FORCEINLINE Precalc(Precalc&& rhs) noexcept : txKeySec(rhs.txKeySec), counter(rhs.counter.load()), shares(rhs.shares) { rhs.shares = nullptr; }
			FORCEINLINE ~Precalc() { free_hook(shares); }

			// Disable any other way of copying/moving Precalc
			Precalc(const Precalc&) = delete;
			Precalc& operator=(const Precalc&) = delete;
			Precalc& operator=(Precalc&&) = delete;

			FORCEINLINE void operator()()
			{
				if (shares) {
					hash derivation, eph_public_key;
					int i;
					while ((i = counter.fetch_sub(1)) >= 0) {
						uint8_t view_tag;
						generate_key_derivation(shares[i].first, txKeySec, i, derivation, view_tag);
						derive_public_key(derivation, i, shares[i].second, eph_public_key);
					}
				}
			}

			hash txKeySec;
			std::atomic<int> counter;
			std::pair<hash, hash>* shares;
		};
		parallel_run(uv_default_loop_checked(), Precalc(m_shares, m_poolBlockTemplate->m_txkeySec));
	}

	m_poolBlockTemplate->m_merkleTreeData = PoolBlock::encode_merkle_tree_data(static_cast<uint32_t>(data.aux_chains.size() + 1), data.aux_nonce);
	m_poolBlockTemplate->m_merkleTreeDataSize = 0;
	writeVarint(m_poolBlockTemplate->m_merkleTreeData, [this](uint8_t) { ++m_poolBlockTemplate->m_merkleTreeDataSize; });

	select_mempool_transactions(mempool);

	const uint64_t base_reward = get_base_reward(data.already_generated_coins);

	uint64_t total_tx_fees = 0;
	uint64_t total_tx_weight = 0;
	for (const TxMempoolData& tx : m_mempoolTxs) {
		total_tx_fees += tx.fee;
		total_tx_weight += tx.weight;
	}

	const uint64_t max_reward = base_reward + total_tx_fees;

	LOGINFO(3, "base  reward = " << log::Gray() << log::XMRAmount(base_reward) << log::NoColor() <<
		", " << log::Gray() << m_mempoolTxs.size() << log::NoColor() <<
		" transactions, fees = " << log::Gray() << log::XMRAmount(total_tx_fees) << log::NoColor() <<
		", weight = " << log::Gray() << total_tx_weight);

	if (!SideChain::split_reward(max_reward, m_shares, m_rewards)) {
		use_old_template();
		return;
	}

	auto get_reward_amounts_weight = [this]() {
		return std::accumulate(m_rewards.begin(), m_rewards.end(), 0ULL,
			[](uint64_t a, uint64_t b)
			{
				writeVarint(b, [&a](uint8_t) { ++a; });
				return a;
			});
	};
	uint64_t max_reward_amounts_weight = get_reward_amounts_weight();

	if (create_miner_tx(data, m_shares, max_reward_amounts_weight, true) < 0) {
		use_old_template();
		return;
	}

	uint64_t miner_tx_weight = m_minerTx.size();

	// Select transactions from the mempool
	uint64_t final_reward, final_fees, final_weight;

	m_mempoolTxsOrder.resize(m_mempoolTxs.size());
	for (size_t i = 0; i < m_mempoolTxs.size(); ++i) {
		m_mempoolTxsOrder[i] = static_cast<int>(i);
	}

	// if a block doesn't get into the penalty zone, just pick all transactions
	if (total_tx_weight + miner_tx_weight <= data.median_weight) {
		final_fees = 0;
		final_weight = miner_tx_weight;

		shuffle_tx_order();

		m_numTransactionHashes = m_mempoolTxsOrder.size();
		m_transactionHashes.assign(HASH_SIZE, 0);
		m_transactionHashesSet.clear();
		m_transactionHashesSet.reserve(m_mempoolTxsOrder.size());
		for (size_t i = 0; i < m_mempoolTxsOrder.size(); ++i) {
			const TxMempoolData& tx = m_mempoolTxs[m_mempoolTxsOrder[i]];
			if (!m_transactionHashesSet.insert(tx.id).second) {
				LOGERR(1, "Added transaction " << tx.id << " twice. Fix the code!");
				continue;
			}
			m_transactionHashes.insert(m_transactionHashes.end(), tx.id.h, tx.id.h + HASH_SIZE);
			final_fees += tx.fee;
			final_weight += tx.weight;
		}

		final_reward = base_reward + final_fees;
	}
	else {
		// Picking all transactions will result in the base reward penalty
		// Use a heuristic algorithm to pick transactions and get the maximum possible reward
		// Testing has shown that this algorithm is very close to the optimal selection
		// Usually no more than 0.5 micronero away from the optimal discrete knapsack solution
		// Sometimes it even finds the optimal solution

		// Sort all transactions by fee per byte (highest to lowest)
		std::sort(m_mempoolTxsOrder.begin(), m_mempoolTxsOrder.end(), [this](int a, int b) { return m_mempoolTxs[a] < m_mempoolTxs[b]; });

		final_reward = base_reward;
		final_fees = 0;
		final_weight = miner_tx_weight;

		m_mempoolTxsOrder2.clear();
		for (int i = 0; i < static_cast<int>(m_mempoolTxsOrder.size()); ++i) {
			const TxMempoolData& tx = m_mempoolTxs[m_mempoolTxsOrder[i]];

			int k = -1;

			const uint64_t reward = get_block_reward(base_reward, data.median_weight, final_fees + tx.fee, final_weight + tx.weight);
			if (reward > final_reward) {
				// If simply adding this transaction increases the reward, remember it
				final_reward = reward;
				k = i;
			}

			// Try replacing other transactions when we are above the limit
			if (final_weight + tx.weight > data.median_weight) {
				// Don't check more than 100 transactions deep because they have higher and higher fee/byte
				const int n = static_cast<int>(m_mempoolTxsOrder2.size());
				for (int j = n - 1, j1 = std::max<int>(0, n - 100); j >= j1; --j) {
					const TxMempoolData& prev_tx = m_mempoolTxs[m_mempoolTxsOrder2[j]];
					const uint64_t reward2 = get_block_reward(base_reward, data.median_weight, final_fees + tx.fee - prev_tx.fee, final_weight + tx.weight - prev_tx.weight);
					if (reward2 > final_reward) {
						// If replacing some other transaction increases the reward even more, remember it
						// And keep trying to replace other transactions
						final_reward = reward2;
						k = j;
					}
				}
			}

			if (k == i) {
				// Simply adding this tx improves the reward
				m_mempoolTxsOrder2.push_back(m_mempoolTxsOrder[i]);
				final_fees += tx.fee;
				final_weight += tx.weight;
			}
			else if (k >= 0) {
				// Replacing another tx with this tx improves the reward
				const TxMempoolData& prev_tx = m_mempoolTxs[m_mempoolTxsOrder2[k]];
				m_mempoolTxsOrder2[k] = m_mempoolTxsOrder[i];
				final_fees += tx.fee - prev_tx.fee;
				final_weight += tx.weight - prev_tx.weight;
			}
		}
		m_mempoolTxsOrder = m_mempoolTxsOrder2;

		final_fees = 0;
		final_weight = miner_tx_weight;

		shuffle_tx_order();

		m_numTransactionHashes = m_mempoolTxsOrder.size();
		m_transactionHashes.assign(HASH_SIZE, 0);
		m_transactionHashesSet.clear();
		m_transactionHashesSet.reserve(m_mempoolTxsOrder.size());
		for (size_t i = 0; i < m_mempoolTxsOrder.size(); ++i) {
			const TxMempoolData& tx = m_mempoolTxs[m_mempoolTxsOrder[i]];
			if (!m_transactionHashesSet.insert(tx.id).second) {
				LOGERR(1, "Added transaction " << tx.id << " twice. Fix the code!");
				continue;
			}
			m_transactionHashes.insert(m_transactionHashes.end(), tx.id.h, tx.id.h + HASH_SIZE);
			final_fees += tx.fee;
			final_weight += tx.weight;
		}

		final_reward = get_block_reward(base_reward, data.median_weight, final_fees, final_weight);

		if (final_reward < base_reward) {
			LOGERR(1, "final_reward < base_reward, this should never happen. Fix the code!");
		}

#if TEST_MEMPOOL_PICKING_ALGORITHM
		LOGINFO(3, "final_reward = " << log::XMRAmount(final_reward) << ", transactions = " << m_numTransactionHashes << ", final_weight = " << final_weight);

		uint64_t final_reward2;
		fill_optimal_knapsack(data, base_reward, miner_tx_weight, final_reward2, final_fees, final_weight);
		LOGINFO(3, "best_reward  = " << log::XMRAmount(final_reward2) << ", transactions = " << m_numTransactionHashes << ", final_weight = " << final_weight);
		if (final_reward2 < final_reward) {
			LOGERR(1, "fill_optimal_knapsack has a bug, found solution is not optimal. Fix it!");
		}
		LOGINFO(3, "difference   = " << static_cast<int64_t>(final_reward2 - final_reward));
		final_reward = final_reward2;
		{
			uint64_t fee_check = 0;
			uint64_t weight_check = miner_tx_weight;
			for (int i : m_mempoolTxsOrder) {
				const TxMempoolData& tx = m_mempoolTxs[i];
				fee_check += tx.fee;
				weight_check += tx.weight;
			}
			const uint64_t reward_check = get_block_reward(base_reward, data.median_weight, final_fees, final_weight);
			if ((reward_check != final_reward) || (fee_check != final_fees) || (weight_check != final_weight)) {
				LOGERR(1, "fill_optimal_knapsack has a bug, expected " << final_reward << ", got " << reward_check << " reward. Fix it!");
			}
		}
#endif
	}

	if (!SideChain::split_reward(final_reward, m_shares, m_rewards)) {
		use_old_template();
		return;
	}

	m_finalReward = final_reward;

	const int create_miner_tx_result = create_miner_tx(data, m_shares, max_reward_amounts_weight, false);
	if (create_miner_tx_result < 0) {
		if (create_miner_tx_result == -3) {
			// Too many extra bytes were added, refine max_reward_amounts_weight and miner_tx_weight
			LOGINFO(4, "Readjusting miner_tx to reduce extra nonce size");

			// The difference between max possible reward and the actual reward can't reduce the size of output amount varints by more than 1 byte each
			// So block weight will be >= current weight - number of outputs
			const uint64_t w = (final_weight > m_rewards.size()) ? (final_weight - m_rewards.size()) : 0;

			// Block reward will be <= r due to how block size penalty works
			const uint64_t r = get_block_reward(base_reward, data.median_weight, final_fees, w);

			if (!SideChain::split_reward(r, m_shares, m_rewards)) {
				use_old_template();
				return;
			}

			max_reward_amounts_weight = get_reward_amounts_weight();

			if (create_miner_tx(data, m_shares, max_reward_amounts_weight, true) < 0) {
				use_old_template();
				return;
			}

			final_weight -= miner_tx_weight;
			final_weight += m_minerTx.size();
			miner_tx_weight = m_minerTx.size();

			final_reward = get_block_reward(base_reward, data.median_weight, final_fees, final_weight);

			if (!SideChain::split_reward(final_reward, m_shares, m_rewards)) {
				use_old_template();
				return;
			}

			if (create_miner_tx(data, m_shares, max_reward_amounts_weight, false) < 0) {
				use_old_template();
				return;
			}

			LOGINFO(4, "New extra nonce size = " << m_poolBlockTemplate->m_extraNonceSize);
		}
		else {
			use_old_template();
			return;
		}
	}

	if (m_minerTx.size() != miner_tx_weight) {
		LOGERR(1, "miner tx size changed after adjusting reward");
		use_old_template();
		return;
	}

	m_blockTemplateBlob = m_blockHeader;
	m_extraNonceOffsetInTemplate += m_blockHeader.size();
	m_minerTxOffsetInTemplate = m_blockHeader.size();
	m_minerTxSize = m_minerTx.size();
	m_blockTemplateBlob.insert(m_blockTemplateBlob.end(), m_minerTx.begin(), m_minerTx.end());
	writeVarint(m_numTransactionHashes, m_blockTemplateBlob);

	// Miner tx hash is skipped here because it's not a part of block template
	m_blockTemplateBlob.insert(m_blockTemplateBlob.end(), m_transactionHashes.begin() + HASH_SIZE, m_transactionHashes.end());

	m_poolBlockTemplate->m_transactions.clear();
	m_poolBlockTemplate->m_transactions.resize(1);
	m_poolBlockTemplate->m_transactions.reserve(m_mempoolTxsOrder.size() + 1);
	for (size_t i = 0, n = m_mempoolTxsOrder.size(); i < n;  ++i) {
		m_poolBlockTemplate->m_transactions.push_back(m_mempoolTxs[m_mempoolTxsOrder[i]].id);
	}

	m_poolBlockTemplate->m_minerWallet = *miner_wallet;

	// Layout: [software id, version, random number, sidechain extra_nonce]
	uint32_t* sidechain_extra = m_poolBlockTemplate->m_sidechainExtraBuf;
	sidechain_extra[0] = static_cast<uint32_t>(SoftwareID::P2Pool);
#ifdef P2POOL_SIDECHAIN_EXTRA_1
	sidechain_extra[1] = P2POOL_SIDECHAIN_EXTRA_1;
#else
	sidechain_extra[1] = P2POOL_VERSION;
#endif
	sidechain_extra[2] = static_cast<uint32_t>(m_rng() >> 32);
	sidechain_extra[3] = 0;

	m_poolBlockTemplate->m_nonce = 0;
	m_poolBlockTemplate->m_extraNonce = 0;
	m_poolBlockTemplate->m_sidechainId = {};
	m_poolBlockTemplate->m_merkleRoot = {};

	m_poolBlockTemplate->m_auxChains = data.aux_chains;
	m_poolBlockTemplate->m_auxNonce = data.aux_nonce;

	m_poolBlockTemplate->m_mergeMiningExtra.clear();
	
	for (const AuxChainData& c : data.aux_chains) {
		std::vector<uint8_t> v;
		v.reserve(HASH_SIZE + 16);

		v.assign(c.data.h, c.data.h + HASH_SIZE);

		writeVarint(c.difficulty.lo, v);
		writeVarint(c.difficulty.hi, v);

		m_poolBlockTemplate->m_mergeMiningExtra.emplace(c.unique_id, std::move(v));
	}

	init_merge_mining_merkle_proof();

	const std::vector<uint8_t> sidechain_data = m_poolBlockTemplate->serialize_sidechain_data();
	const std::vector<uint8_t>& consensus_id = m_sidechain->consensus_id();

	m_sidechainHashBlob = m_poolBlockTemplate->serialize_mainchain_data();
	m_sidechainHashBlob.insert(m_sidechainHashBlob.end(), sidechain_data.begin(), sidechain_data.end());
	m_sidechainHashBlob.insert(m_sidechainHashBlob.end(), consensus_id.begin(), consensus_id.end());

	{
		m_sidechainHashKeccakState = {};

		const size_t extra_nonce_offset = m_sidechainHashBlob.size() - HASH_SIZE - EXTRA_NONCE_SIZE;
		if (extra_nonce_offset >= KeccakParams::HASH_DATA_AREA) {
			// Sidechain data is big enough to cache keccak state up to extra_nonce
			m_sidechainHashInputLength = (extra_nonce_offset / KeccakParams::HASH_DATA_AREA) * KeccakParams::HASH_DATA_AREA;

			const uint8_t* in = m_sidechainHashBlob.data();
			int inlen = static_cast<int>(m_sidechainHashInputLength);

			keccak_step(in, inlen, m_sidechainHashKeccakState);
		}
		else {
			m_sidechainHashInputLength = 0;
		}
	}

	m_fullDataBlob = m_blockTemplateBlob;
	m_fullDataBlob.insert(m_fullDataBlob.end(), sidechain_data.begin(), sidechain_data.end());
	LOGINFO(6, "blob size = " << m_fullDataBlob.size());

	m_poolBlockTemplate->m_sidechainId = calc_sidechain_hash(0);
	{
		const uint32_t n_aux_chains = static_cast<uint32_t>(m_poolBlockTemplate->m_auxChains.size() + 1);
		const uint32_t aux_slot = get_aux_slot(m_sidechain->consensus_hash(), m_poolBlockTemplate->m_auxNonce, n_aux_chains);
		m_poolBlockTemplate->m_merkleRoot = get_root_from_proof(m_poolBlockTemplate->m_sidechainId, m_poolBlockTemplate->m_merkleProof, aux_slot, n_aux_chains);
	}

	if (pool_block_debug()) {
		const size_t merkle_root_offset = m_extraNonceOffsetInTemplate + m_poolBlockTemplate->m_extraNonceSize + 2 + m_poolBlockTemplate->m_merkleTreeDataSize;

		memcpy(m_blockTemplateBlob.data() + merkle_root_offset, m_poolBlockTemplate->m_merkleRoot.h, HASH_SIZE);
		memcpy(m_fullDataBlob.data() + merkle_root_offset, m_poolBlockTemplate->m_merkleRoot.h, HASH_SIZE);
		memcpy(m_minerTx.data() + merkle_root_offset - m_minerTxOffsetInTemplate, m_poolBlockTemplate->m_merkleRoot.h, HASH_SIZE);

		const std::vector<uint8_t> mainchain_data = m_poolBlockTemplate->serialize_mainchain_data();
		if (mainchain_data != m_blockTemplateBlob) {
			LOGERR(1, "serialize_mainchain_data() has a bug, fix it! ");
			LOGERR(1, "mainchain_data.size()      = " << mainchain_data.size());
			LOGERR(1, "m_blockTemplateBlob.size() = " << m_blockTemplateBlob.size());
			for (size_t i = 0, n = std::min(mainchain_data.size(), m_blockTemplateBlob.size()); i < n; ++i) {
				if (mainchain_data[i] != m_blockTemplateBlob[i]) {
					LOGERR(1, "mainchain_data is different at offset " << i);
					break;
				}
			}
		}
		PoolBlock check;
		const int result = check.deserialize(m_fullDataBlob.data(), m_fullDataBlob.size(), *m_sidechain, nullptr, false);
		if (result != 0) {
			LOGERR(1, "pool block blob generation and/or parsing is broken, error " << result);
		}
	}

	m_minerTxKeccakState = {};

	const size_t extra_nonce_offset = m_extraNonceOffsetInTemplate - m_minerTxOffsetInTemplate;
	if (extra_nonce_offset >= KeccakParams::HASH_DATA_AREA) {
		// Miner transaction is big enough to cache keccak state up to extra_nonce
		m_minerTxKeccakStateInputLength = (extra_nonce_offset / KeccakParams::HASH_DATA_AREA) * KeccakParams::HASH_DATA_AREA;

		const uint8_t* in = m_blockTemplateBlob.data() + m_minerTxOffsetInTemplate;
		int inlen = static_cast<int>(m_minerTxKeccakStateInputLength);

		keccak_step(in, inlen, m_minerTxKeccakState);
	}
	else {
		m_minerTxKeccakStateInputLength = 0;
	}

	const hash minerTx_hash = calc_miner_tx_hash(0);

	memcpy(m_transactionHashes.data(), minerTx_hash.h, HASH_SIZE);

	calc_merkle_tree_main_branch();

	LOGINFO(3, "final reward = " << log::Gray() << log::XMRAmount(final_reward) << log::NoColor() <<
		", weight = " << log::Gray() << final_weight << log::NoColor() <<
		", outputs = " << log::Gray() << m_poolBlockTemplate->m_outputs.size() << log::NoColor() <<
		", " << log::Gray() << m_numTransactionHashes << log::NoColor() <<
		" of " << log::Gray() << m_mempoolTxs.size() << log::NoColor() << " transactions included");

	m_minerTx.clear();
	m_blockHeader.clear();
	m_minerTxExtra.clear();
	m_transactionHashes.clear();
	m_transactionHashesSet.clear();
	m_rewards.clear();
	m_mempoolTxs.clear();
	m_mempoolTxsOrder.clear();
	m_mempoolTxsOrder2.clear();
}

#if TEST_MEMPOOL_PICKING_ALGORITHM
void BlockTemplate::fill_optimal_knapsack(const MinerData& data, uint64_t base_reward, uint64_t miner_tx_weight, uint64_t& best_reward, uint64_t& final_fees, uint64_t& final_weight)
{
	// Find the maximum possible fee for every weight value and remember which tx leads to this fee/weight
	// Run time is O(N*W) where N is the number of transactions and W is the maximum block weight
	// 
	// Actual run time is 0.02-0.05 seconds on real full blocks
	// It's too slow and uses too much memory to be practical

	constexpr uint64_t FEE_COEFF = 1000;

	const uint64_t n = m_mempoolTxs.size();
	const uint64_t max_weight = data.median_weight + (data.median_weight / 8) - miner_tx_weight;

	m_knapsack.resize((n + 1) * max_weight);
	memset(m_knapsack.data(), 0, max_weight * sizeof(uint32_t));

	for (size_t i = 1; i <= n; ++i) {
		const TxMempoolData& tx = m_mempoolTxs[i - 1];
		const uint32_t tx_fee = static_cast<uint32_t>(tx.fee / FEE_COEFF);
		const uint64_t tx_weight = tx.weight;

		uint32_t* row = m_knapsack.data() + i * max_weight;
		const uint32_t* prev_row = row - max_weight;

		row[0] = 0;
		memcpy(row + 1, prev_row + 1, (tx_weight - 1) * sizeof(uint32_t));

#define INNER_LOOP(k) { \
	const uint32_t fee_when_used = prev_row[w + k - tx_weight] + tx_fee; \
	const uint32_t fee_when_not_used = prev_row[w + k]; \
	row[w + k] = (fee_when_used > fee_when_not_used) ? fee_when_used : fee_when_not_used; \
}

		for (size_t w = tx_weight, max_w = max_weight - 3; w < max_w; w += 4) {
			INNER_LOOP(0);
			INNER_LOOP(1);
			INNER_LOOP(2);
			INNER_LOOP(3);
		}

#undef INNER_LOOP
	}

	// Now that we know which fee we can get for each weight, just find the maximum possible block reward
	best_reward = base_reward;
	uint64_t best_weight = 0;
	for (uint64_t w = 0, max_w = max_weight - 3; w < max_w; ++w) {
		const uint64_t fee = m_knapsack[n * max_weight + w] * FEE_COEFF;
		if (fee) {
			const uint64_t cur_reward = get_block_reward(base_reward, data.median_weight, fee, w + miner_tx_weight);
			if (cur_reward > best_reward) {
				best_reward = cur_reward;
				best_weight = w;
			}
		}
	}

	m_numTransactionHashes = 0;

	final_fees = 0;
	final_weight = miner_tx_weight;

	m_mempoolTxsOrder.clear();
	m_transactionHashes.assign(HASH_SIZE, 0);
	for (int i = static_cast<int>(n); (i > 0) && (best_weight > 0); --i) {
		if (m_knapsack[i * max_weight + best_weight] > m_knapsack[(i - 1) * max_weight + best_weight]) {
			m_mempoolTxsOrder.push_back(i - 1);
			const TxMempoolData& tx = m_mempoolTxs[i - 1];
			m_transactionHashes.insert(m_transactionHashes.end(), tx.id.h, tx.id.h + HASH_SIZE);
			++m_numTransactionHashes;
			best_weight -= tx.weight;
			final_fees += tx.fee;
			final_weight += tx.weight;
		}
	}

	m_knapsack.clear();
}
#endif

void BlockTemplate::select_mempool_transactions(const Mempool& mempool)
{
	// Only choose transactions that were received 5 or more seconds ago, or high fee (>= 0.006 XMR) transactions
	m_mempoolTxs.clear();

	const uint64_t cur_time = seconds_since_epoch();
	size_t total_mempool_transactions = 0;

	mempool.iterate([this, cur_time, &total_mempool_transactions](const hash&, const TxMempoolData& tx) {
		++total_mempool_transactions;

		if ((cur_time > tx.time_received + 5) || (tx.fee >= HIGH_FEE_VALUE)) {
			m_mempoolTxs.emplace_back(tx);
		}
	});

	// Safeguard for busy mempool moments
	// If the block template gets too big, nodes won't be able to send and receive it because of p2p packet size limit
	// Calculate how many transactions we can take

	PoolBlock* b = m_poolBlockTemplate;
	b->m_transactions.clear();
	b->m_transactions.resize(1);
	b->m_outputs.clear();

	// Block template size without coinbase outputs and transactions (minus 2 bytes for output and tx count dummy varints)
	size_t k = b->serialize_mainchain_data().size() + b->serialize_sidechain_data().size() - 2;

	// Add output and tx count real varints
	writeVarint(m_shares.size(), [&k](uint8_t) { ++k; });
	writeVarint(m_mempoolTxs.size(), [&k](uint8_t) { ++k; });

	// Add a rough upper bound estimation of outputs' size. All outputs have <= 5 bytes for each output's reward (< 0.034359738368 XMR per output)
	k += m_shares.size() * (5 /* reward */ + 1 /* tx_type */ + HASH_SIZE /* stealth address */ + 1 /* viewtag */);

	// >= 0.034359738368 XMR is required for a 6 byte varint, add 1 byte per each potential 6-byte varint
	{
		uint64_t r = BASE_BLOCK_REWARD;
		for (const auto& tx : m_mempoolTxs) {
			r += tx.fee;
		}
		k += r / 34359738368ULL;
	}

	const size_t max_transactions = (MAX_BLOCK_SIZE > k) ? ((MAX_BLOCK_SIZE - k) / HASH_SIZE) : 0;
	LOGINFO(6, max_transactions << " transactions can be taken with current block size limit");

	if (max_transactions == 0) {
		m_mempoolTxs.clear();
	}
	else if (m_mempoolTxs.size() > max_transactions) {
		std::nth_element(m_mempoolTxs.begin(), m_mempoolTxs.begin() + max_transactions, m_mempoolTxs.end());
		m_mempoolTxs.resize(max_transactions);
	}

	LOGINFO(4, "mempool has " << total_mempool_transactions << " transactions, taking " << m_mempoolTxs.size() << " transactions from it");
}

int BlockTemplate::create_miner_tx(const MinerData& data, const std::vector<MinerShare>& shares, uint64_t max_reward_amounts_weight, bool dry_run)
{
	// Miner transaction (coinbase)
	m_minerTx.clear();

	const size_t num_outputs = shares.size();
	m_minerTx.reserve(num_outputs * 39 + 55);

	// tx version
	m_minerTx.push_back(TX_VERSION);

	// Unlock time
	writeVarint(data.height + MINER_REWARD_UNLOCK_TIME, m_minerTx);

	// Number of inputs
	m_minerTx.push_back(1);

	// Input type (txin_gen)
	m_minerTx.push_back(TXIN_GEN);

	// txin_gen height
	writeVarint(data.height, m_minerTx);
	m_poolBlockTemplate->m_txinGenHeight = data.height;

	// Number of outputs (1 output per miner)
	writeVarint(num_outputs, m_minerTx);

	m_poolBlockTemplate->m_outputs.clear();
	m_poolBlockTemplate->m_outputs.reserve(num_outputs);

	const uint8_t tx_type = m_poolBlockTemplate->get_tx_type();

	uint64_t reward_amounts_weight = 0;
	for (size_t i = 0; i < num_outputs; ++i) {
		writeVarint(m_rewards[i], [this, &reward_amounts_weight](uint8_t b)
			{
				m_minerTx.push_back(b);
				++reward_amounts_weight;
			});
		m_minerTx.push_back(tx_type);

		uint8_t view_tag = 0;

		if (dry_run) {
			m_minerTx.insert(m_minerTx.end(), HASH_SIZE, 0);
		}
		else {
			hash eph_public_key;
			if (!shares[i].m_wallet->get_eph_public_key(m_poolBlockTemplate->m_txkeySec, i, eph_public_key, view_tag)) {
				LOGERR(1, "get_eph_public_key failed at index " << i);
			}
			m_minerTx.insert(m_minerTx.end(), eph_public_key.h, eph_public_key.h + HASH_SIZE);
			m_poolBlockTemplate->m_outputs.emplace_back(m_rewards[i], eph_public_key, view_tag);
		}

		if (tx_type == TXOUT_TO_TAGGED_KEY) {
			m_minerTx.emplace_back(view_tag);
		}
	}

	if (dry_run) {
		if (reward_amounts_weight != max_reward_amounts_weight) {
			LOGERR(1, "create_miner_tx: incorrect miner rewards during the dry run (" << reward_amounts_weight << " != " <<  max_reward_amounts_weight << ")");
			return -1;
		}
	}
	else if (reward_amounts_weight > max_reward_amounts_weight) {
		LOGERR(1, "create_miner_tx: incorrect miner rewards during the real run (" << reward_amounts_weight << " > " << max_reward_amounts_weight << ")");
		return -2;
	}

	// TX_EXTRA begin
	m_minerTxExtra.clear();

	m_minerTxExtra.push_back(TX_EXTRA_TAG_PUBKEY);
	m_minerTxExtra.insert(m_minerTxExtra.end(), m_poolBlockTemplate->m_txkeyPub.h, m_poolBlockTemplate->m_txkeyPub.h + HASH_SIZE);

	m_minerTxExtra.push_back(TX_EXTRA_NONCE);

	const uint64_t corrected_extra_nonce_size = EXTRA_NONCE_SIZE + max_reward_amounts_weight - reward_amounts_weight;
	if (corrected_extra_nonce_size > EXTRA_NONCE_SIZE) {
		if (corrected_extra_nonce_size > EXTRA_NONCE_MAX_SIZE) {
			LOGWARN(5, "create_miner_tx: corrected_extra_nonce_size (" << corrected_extra_nonce_size << ") is too large");
			return -3;
		}
		LOGINFO(4, "increased EXTRA_NONCE from " << EXTRA_NONCE_SIZE << " to " << corrected_extra_nonce_size << " bytes to maintain miner tx weight");
	}
	writeVarint(corrected_extra_nonce_size, m_minerTxExtra);
	
	uint64_t extraNonceOffsetInMinerTx = m_minerTxExtra.size();
	m_minerTxExtra.insert(m_minerTxExtra.end(), corrected_extra_nonce_size, 0);

	m_poolBlockTemplate->m_extraNonceSize = corrected_extra_nonce_size;

	m_minerTxExtra.push_back(TX_EXTRA_MERGE_MINING_TAG);

	m_minerTxExtra.push_back(static_cast<uint8_t>(m_poolBlockTemplate->m_merkleTreeDataSize + HASH_SIZE));
	writeVarint(m_poolBlockTemplate->m_merkleTreeData, m_minerTxExtra);
	m_minerTxExtra.insert(m_minerTxExtra.end(), HASH_SIZE, 0);
	// TX_EXTRA end

	writeVarint(m_minerTxExtra.size(), m_minerTx);
	extraNonceOffsetInMinerTx += m_minerTx.size();
	m_extraNonceOffsetInTemplate = extraNonceOffsetInMinerTx;
	m_minerTx.insert(m_minerTx.end(), m_minerTxExtra.begin(), m_minerTxExtra.end());

	m_minerTxExtra.clear();

	// vin_rct_type
	// Not a part of transaction hash data
	m_minerTx.push_back(0);

	return 1;
}

hash BlockTemplate::calc_sidechain_hash(uint32_t sidechain_extra_nonce) const
{
	// Calculate side-chain hash (all block template bytes + all side-chain bytes + consensus ID, replacing NONCE, EXTRA_NONCE and HASH itself with 0's)
	const size_t size = m_sidechainHashBlob.size();
	const size_t N = m_sidechainHashInputLength;

	const size_t sidechain_extra_nonce_offset = size - HASH_SIZE - EXTRA_NONCE_SIZE;
	const uint8_t sidechain_extra_nonce_buf[EXTRA_NONCE_SIZE] = {
		static_cast<uint8_t>(sidechain_extra_nonce >> 0),
		static_cast<uint8_t>(sidechain_extra_nonce >> 8),
		static_cast<uint8_t>(sidechain_extra_nonce >> 16),
		static_cast<uint8_t>(sidechain_extra_nonce >> 24)
	};

	hash result;
	uint8_t buf[288];

	const bool b = N && (N <= sidechain_extra_nonce_offset) && (N < size) && (size - N <= sizeof(buf));

	// Slow path: O(N)
	if (!b || pool_block_debug()) {
		keccak_custom([this, sidechain_extra_nonce_offset, &sidechain_extra_nonce_buf](int offset) -> uint8_t {
			const uint32_t k = static_cast<uint32_t>(offset - sidechain_extra_nonce_offset);
			if (k < EXTRA_NONCE_SIZE) {
				return sidechain_extra_nonce_buf[k];
			}
			return m_sidechainHashBlob[offset];
		}, static_cast<int>(size), result.h, HASH_SIZE);
	}

	// Fast path: O(1)
	if (b) {
		const int inlen = static_cast<int>(size - N);

		memcpy(buf, m_sidechainHashBlob.data() + N, size - N);
		memcpy(buf + sidechain_extra_nonce_offset - N, sidechain_extra_nonce_buf, EXTRA_NONCE_SIZE);

		std::array<uint64_t, 25> st = m_sidechainHashKeccakState;
		keccak_finish(buf, inlen, st);

		if (pool_block_debug() && (memcmp(st.data(), result.h, HASH_SIZE) != 0)) {
			LOGERR(1, "calc_sidechain_hash fast path is broken. Fix the code!");
		}

		memcpy(result.h, st.data(), HASH_SIZE);
	}

	return result;
}

hash BlockTemplate::calc_miner_tx_hash(uint32_t extra_nonce) const
{
	// Calculate 3 partial hashes
	uint8_t hashes[HASH_SIZE * 3];

	const uint8_t* data = m_blockTemplateBlob.data() + m_minerTxOffsetInTemplate;

	const size_t extra_nonce_offset = m_extraNonceOffsetInTemplate - m_minerTxOffsetInTemplate;
	const uint8_t extra_nonce_buf[EXTRA_NONCE_SIZE] = {
		static_cast<uint8_t>(extra_nonce >> 0),
		static_cast<uint8_t>(extra_nonce >> 8),
		static_cast<uint8_t>(extra_nonce >> 16),
		static_cast<uint8_t>(extra_nonce >> 24)
	};

	// Calculate sidechain id and merge mining root hash with this extra_nonce
	hash merge_mining_root;
	{
		const hash sidechain_id = calc_sidechain_hash(extra_nonce);
		const uint32_t n_aux_chains = static_cast<uint32_t>(m_poolBlockTemplate->m_auxChains.size() + 1);
		const uint32_t aux_slot = get_aux_slot(m_sidechain->consensus_hash(), m_poolBlockTemplate->m_auxNonce, n_aux_chains);
		merge_mining_root = get_root_from_proof(sidechain_id, m_poolBlockTemplate->m_merkleProof, aux_slot, n_aux_chains);
	}

	const size_t merkle_root_offset = extra_nonce_offset + m_poolBlockTemplate->m_extraNonceSize + 2 + m_poolBlockTemplate->m_merkleTreeDataSize;

	// 1. Prefix (everything except vin_rct_type byte in the end)
	// Apply extra_nonce in-place because we can't write to the block template here
	const size_t tx_size = m_minerTxSize - 1;

	hash full_hash;
	uint8_t tx_buf[288];

	const size_t N = m_minerTxKeccakStateInputLength;
	const bool b = N && (N <= extra_nonce_offset) && (N < tx_size) && (tx_size - N <= sizeof(tx_buf));

	// Slow path: O(N)
	if (!b || pool_block_debug())
	{
		keccak_custom([data, extra_nonce_offset, &extra_nonce_buf, merkle_root_offset, &merge_mining_root](int offset) {
			uint32_t k = static_cast<uint32_t>(offset - static_cast<int>(extra_nonce_offset));
			if (k < EXTRA_NONCE_SIZE) {
				return extra_nonce_buf[k];
			}

			k = static_cast<uint32_t>(offset - static_cast<int>(merkle_root_offset));
			if (k < HASH_SIZE) {
				return merge_mining_root.h[k];
			}

			return data[offset];
		}, static_cast<int>(tx_size), full_hash.h, HASH_SIZE);
		memcpy(hashes, full_hash.h, HASH_SIZE);
	}

	// Fast path: O(1)
	if (b) {
		const int inlen = static_cast<int>(tx_size - N);

		memcpy(tx_buf, data + N, inlen);
		memcpy(tx_buf + extra_nonce_offset - N, extra_nonce_buf, EXTRA_NONCE_SIZE);
		memcpy(tx_buf + merkle_root_offset - N, merge_mining_root.h, HASH_SIZE);

		std::array<uint64_t, 25> st = m_minerTxKeccakState;
		keccak_finish(tx_buf, inlen, st);

		if (pool_block_debug() && (memcmp(st.data(), full_hash.h, HASH_SIZE) != 0)) {
			LOGERR(1, "calc_miner_tx_hash fast path is broken. Fix the code!");
		}

		memcpy(hashes, st.data(), HASH_SIZE);
	}

	// 2. Base RCT, single 0 byte in miner tx
	static constexpr uint8_t known_second_hash[HASH_SIZE] = {
		188,54,120,158,122,30,40,20,54,70,66,41,130,143,129,125,102,18,247,180,119,214,101,145,255,150,169,224,100,188,201,138
	};
	memcpy(hashes + HASH_SIZE, known_second_hash, HASH_SIZE);

	// 3. Prunable RCT, empty in miner tx
	memset(hashes + HASH_SIZE * 2, 0, HASH_SIZE);

	// Calculate miner transaction hash
	hash result;
	keccak(hashes, sizeof(hashes), result.h);

	return result;
}

void BlockTemplate::calc_merkle_tree_main_branch()
{
	m_merkleTreeMainBranch.clear();

	const uint64_t count = m_numTransactionHashes + 1;
	if (count == 1) {
		return;
	}

	const uint8_t* h = m_transactionHashes.data();

	if (count == 2) {
		m_merkleTreeMainBranch.insert(m_merkleTreeMainBranch.end(), h + HASH_SIZE, h + HASH_SIZE * 2);
	}
	else {
		size_t i, j, cnt;

		for (i = 0, cnt = 1; cnt <= count; ++i, cnt <<= 1) {}

		cnt >>= 1;

		std::vector<uint8_t> ints(cnt * HASH_SIZE);
		memcpy(ints.data(), h, (cnt * 2 - count) * HASH_SIZE);

		hash tmp;

		for (i = cnt * 2 - count, j = cnt * 2 - count; j < cnt; i += 2, ++j) {
			if (i == 0) {
				m_merkleTreeMainBranch.insert(m_merkleTreeMainBranch.end(), h + HASH_SIZE, h + HASH_SIZE * 2);
			}
			keccak(h + i * HASH_SIZE, HASH_SIZE * 2, tmp.h);
			memcpy(ints.data() + j * HASH_SIZE, tmp.h, HASH_SIZE);
		}

		while (cnt > 2) {
			cnt >>= 1;
			for (i = 0, j = 0; j < cnt; i += 2, ++j) {
				if (i == 0) {
					m_merkleTreeMainBranch.insert(m_merkleTreeMainBranch.end(), ints.data() + HASH_SIZE, ints.data() + HASH_SIZE * 2);
				}
				keccak(ints.data() + i * HASH_SIZE, HASH_SIZE * 2, tmp.h);
				memcpy(ints.data() + j * HASH_SIZE, tmp.h, HASH_SIZE);
			}
		}

		m_merkleTreeMainBranch.insert(m_merkleTreeMainBranch.end(), ints.data() + HASH_SIZE, ints.data() + HASH_SIZE * 2);
	}
}

bool BlockTemplate::get_difficulties(const uint32_t template_id, uint64_t& height, uint64_t& sidechain_height, difficulty_type& mainchain_difficulty, difficulty_type& aux_diff, difficulty_type& sidechain_difficulty) const
{
	ReadLock lock(m_lock);

	if (template_id == m_templateId) {
		height = m_height;
		sidechain_height = m_poolBlockTemplate->m_sidechainHeight;
		mainchain_difficulty = m_difficulty;
		aux_diff = m_auxDifficulty;
		sidechain_difficulty = m_poolBlockTemplate->m_difficulty;
		return true;
	}

	const BlockTemplate* old = m_oldTemplates[template_id % array_size(&BlockTemplate::m_oldTemplates)];

	if (old && (template_id == old->m_templateId)) {
		return old->get_difficulties(template_id, height, sidechain_height, mainchain_difficulty, aux_diff, sidechain_difficulty);
	}

	return false;
}

uint32_t BlockTemplate::get_hashing_blob(const uint32_t template_id, uint32_t extra_nonce, uint8_t (&blob)[128], uint64_t& height, difficulty_type& difficulty, difficulty_type& aux_diff, difficulty_type& sidechain_difficulty, hash& seed_hash, size_t& nonce_offset) const
{
	ReadLock lock(m_lock);

	if (template_id == m_templateId) {
		height = m_height;
		difficulty = m_difficulty;
		aux_diff = m_auxDifficulty;
		sidechain_difficulty = m_poolBlockTemplate->m_difficulty;
		seed_hash = m_seedHash;
		nonce_offset = m_nonceOffset;

		return get_hashing_blob_nolock(extra_nonce, blob);
	}

	const BlockTemplate* old = m_oldTemplates[template_id % array_size(&BlockTemplate::m_oldTemplates)];

	if (old && (template_id == old->m_templateId)) {
		return old->get_hashing_blob(template_id, extra_nonce, blob, height, difficulty, aux_diff, sidechain_difficulty, seed_hash, nonce_offset);
	}

	return 0;
}

uint32_t BlockTemplate::get_hashing_blob(uint32_t extra_nonce, uint8_t (&blob)[128], uint64_t& height, uint64_t& sidechain_height, difficulty_type& difficulty, difficulty_type& aux_diff, difficulty_type& sidechain_difficulty, hash& seed_hash, size_t& nonce_offset, uint32_t& template_id) const
{
	ReadLock lock(m_lock);

	height = m_height;
	sidechain_height = m_poolBlockTemplate->m_sidechainHeight;
	difficulty = m_difficulty;
	aux_diff = m_auxDifficulty;
	sidechain_difficulty = m_poolBlockTemplate->m_difficulty;
	seed_hash = m_seedHash;
	nonce_offset = m_nonceOffset;
	template_id = m_templateId;

	return get_hashing_blob_nolock(extra_nonce, blob);
}

uint32_t BlockTemplate::get_hashing_blob_nolock(uint32_t extra_nonce, uint8_t* blob) const
{
	uint8_t* p = blob;

	// Block header
	memcpy(p, m_blockTemplateBlob.data(), m_blockHeaderSize);
	p += m_blockHeaderSize;

	// Merkle tree hash
	hash root_hash = calc_miner_tx_hash(extra_nonce);

	for (size_t i = 0; i < m_merkleTreeMainBranch.size(); i += HASH_SIZE) {
		uint8_t h[HASH_SIZE * 2];

		memcpy(h, root_hash.h, HASH_SIZE);
		memcpy(h + HASH_SIZE, m_merkleTreeMainBranch.data() + i, HASH_SIZE);

		keccak(h, HASH_SIZE * 2, root_hash.h);
	}

	memcpy(p, root_hash.h, HASH_SIZE);
	p += HASH_SIZE;

	// Total number of transactions in this block (including the miner tx)
	writeVarint(m_numTransactionHashes + 1, [&p](uint8_t b) { *(p++) = b; });

	return static_cast<uint32_t>(p - blob);
}

uint32_t BlockTemplate::get_hashing_blobs(uint32_t extra_nonce_start, uint32_t count, std::vector<uint8_t>& blobs, uint64_t& height, difficulty_type& difficulty, difficulty_type& aux_diff, difficulty_type& sidechain_difficulty, hash& seed_hash, size_t& nonce_offset, uint32_t& template_id) const
{
	blobs.clear();

	const size_t required_capacity = static_cast<size_t>(count) * 80;
	if (blobs.capacity() < required_capacity) {
		blobs.reserve(required_capacity * 2);
	}

	ReadLock lock(m_lock);

	height = m_height;
	difficulty = m_difficulty;
	aux_diff = m_auxDifficulty;
	sidechain_difficulty = m_poolBlockTemplate->m_difficulty;
	seed_hash = m_seedHash;
	nonce_offset = m_nonceOffset;
	template_id = m_templateId;

	constexpr size_t MIN_BLOB_SIZE = 76;
	constexpr size_t MAX_BLOB_SIZE = 128;

	blobs.resize(MAX_BLOB_SIZE);
	const uint32_t blob_size = get_hashing_blob_nolock(extra_nonce_start, blobs.data());

	if (blob_size > MAX_BLOB_SIZE) {
		LOGERR(1, "internal error: get_hashing_blob_nolock returned too large blob size " << blob_size << ", expected <= " << MAX_BLOB_SIZE);
		PANIC_STOP();
	}
	else if (blob_size < MIN_BLOB_SIZE) {
		LOGERR(1, "internal error: get_hashing_blob_nolock returned too little blob size " << blob_size << ", expected >= " << MIN_BLOB_SIZE);
	}

	blobs.resize(static_cast<size_t>(blob_size) * count);

	if (count > 1) {
		uint8_t* blobs_data = blobs.data();

		std::atomic<uint32_t> counter = 1;

		parallel_run(uv_default_loop_checked(), [this, blob_size, extra_nonce_start, count, &counter, blobs_data]() {
			for (;;) {
				const uint32_t i = counter.fetch_add(1);
				if (i >= count) {
					return;
				}

				const uint32_t n = get_hashing_blob_nolock(extra_nonce_start + i, blobs_data + static_cast<size_t>(i) * blob_size);
				if (n != blob_size) {
					LOGERR(1, "internal error: get_hashing_blob_nolock returned different blob size " << n << ", expected " << blob_size);
				}
			}
		}, true);
	}

	return blob_size;
}

std::vector<AuxChainData> BlockTemplate::get_aux_chains(const uint32_t template_id) const
{
	ReadLock lock(m_lock);

	if (template_id != m_templateId) {
		const BlockTemplate* old = m_oldTemplates[template_id % array_size(&BlockTemplate::m_oldTemplates)];
		if (old && (template_id == old->m_templateId)) {
			return old->get_aux_chains(template_id);
		}

		return {};
	}

	return m_poolBlockTemplate->m_auxChains;
}

bool BlockTemplate::get_aux_proof(const uint32_t template_id, uint32_t extra_nonce, const hash& h, std::vector<hash>& proof, uint32_t& path) const
{
	ReadLock lock(m_lock);

	if (template_id != m_templateId) {
		const BlockTemplate* old = m_oldTemplates[template_id % array_size(&BlockTemplate::m_oldTemplates)];
		if (old && (template_id == old->m_templateId)) {
			return old->get_aux_proof(template_id, extra_nonce, h, proof, path);
		}

		return false;
	}

	bool found = false;

	const hash sidechain_id = calc_sidechain_hash(extra_nonce);
	const uint32_t n_aux_chains = static_cast<uint32_t>(m_poolBlockTemplate->m_auxChains.size() + 1);

	std::vector<hash> hashes(n_aux_chains);

	for (const AuxChainData& aux_data : m_poolBlockTemplate->m_auxChains) {
		const uint32_t aux_slot = get_aux_slot(aux_data.unique_id, m_poolBlockTemplate->m_auxNonce, n_aux_chains);
		hashes[aux_slot] = aux_data.data;

		if (aux_data.data == h) {
			found = true;
		}
	}

	const uint32_t aux_slot = get_aux_slot(m_sidechain->consensus_hash(), m_poolBlockTemplate->m_auxNonce, n_aux_chains);
	hashes[aux_slot] = sidechain_id;

	if (sidechain_id == h) {
		found = true;
	}

	if (!found) {
		return false;
	}

	std::vector<std::vector<hash>> tree;
	merkle_hash_full_tree(hashes, tree);

	return get_merkle_proof(tree, h, proof, path);
}

std::vector<uint8_t> BlockTemplate::get_block_template_blob(uint32_t template_id, uint32_t sidechain_extra_nonce, size_t& nonce_offset, size_t& extra_nonce_offset, size_t& merkle_root_offset, hash& merge_mining_root, const BlockTemplate** pThis) const
{
	ReadLock lock(m_lock);

	if (template_id != m_templateId) {
		const BlockTemplate* old = m_oldTemplates[template_id % array_size(&BlockTemplate::m_oldTemplates)];
		if (old && (template_id == old->m_templateId)) {
			return old->get_block_template_blob(template_id, sidechain_extra_nonce, nonce_offset, extra_nonce_offset, merkle_root_offset, merge_mining_root, pThis);
		}

		nonce_offset = 0;
		extra_nonce_offset = 0;
		merkle_root_offset = 0;
		merge_mining_root = {};
		return std::vector<uint8_t>();
	}

	nonce_offset = m_nonceOffset;
	extra_nonce_offset = m_extraNonceOffsetInTemplate;

	const hash sidechain_id = calc_sidechain_hash(sidechain_extra_nonce);
	const uint32_t n_aux_chains = static_cast<uint32_t>(m_poolBlockTemplate->m_auxChains.size() + 1);
	const uint32_t aux_slot = get_aux_slot(m_sidechain->consensus_hash(), m_poolBlockTemplate->m_auxNonce, n_aux_chains);
	merge_mining_root = get_root_from_proof(sidechain_id, m_poolBlockTemplate->m_merkleProof, aux_slot, n_aux_chains);

	merkle_root_offset = m_extraNonceOffsetInTemplate + m_poolBlockTemplate->m_extraNonceSize + 2 + m_poolBlockTemplate->m_merkleTreeDataSize;

	*pThis = this;

	return m_blockTemplateBlob;
}

bool BlockTemplate::submit_sidechain_block(uint32_t template_id, uint32_t nonce, uint32_t extra_nonce)
{
	const uint64_t received_timestamp = microseconds_since_epoch();

	WriteLock lock(m_lock);

	if (template_id == m_templateId) {
		m_poolBlockTemplate->m_receivedTimestamp = received_timestamp;

		m_poolBlockTemplate->m_nonce = nonce;
		m_poolBlockTemplate->m_extraNonce = extra_nonce;
		m_poolBlockTemplate->m_sidechainId = calc_sidechain_hash(extra_nonce);
		m_poolBlockTemplate->m_sidechainExtraBuf[3] = extra_nonce;

		const uint32_t n_aux_chains = static_cast<uint32_t>(m_poolBlockTemplate->m_auxChains.size() + 1);
		const uint32_t aux_slot = get_aux_slot(m_sidechain->consensus_hash(), m_poolBlockTemplate->m_auxNonce, n_aux_chains);

		m_poolBlockTemplate->m_merkleRoot = get_root_from_proof(m_poolBlockTemplate->m_sidechainId, m_poolBlockTemplate->m_merkleProof, aux_slot, n_aux_chains);

		if (pool_block_debug()) {
			std::vector<uint8_t> buf = m_poolBlockTemplate->serialize_mainchain_data();
			const std::vector<uint8_t> sidechain_data = m_poolBlockTemplate->serialize_sidechain_data();

			memcpy(buf.data() + m_nonceOffset, &nonce, NONCE_SIZE);
			memcpy(buf.data() + m_extraNonceOffsetInTemplate, &extra_nonce, EXTRA_NONCE_SIZE);

			buf.insert(buf.end(), sidechain_data.begin(), sidechain_data.end());

			PoolBlock check;
			const int result = check.deserialize(buf.data(), buf.size(), *m_sidechain, nullptr, false);
			if (result != 0) {
				LOGERR(1, "pool block blob generation and/or parsing is broken, error " << result);
			}

			if (m_hasher) {
				hash pow_hash;
				if (!check.get_pow_hash(m_hasher, check.m_txinGenHeight, m_seedHash, pow_hash)) {
					LOGERR(1, "PoW check failed for the sidechain block. Fix it! ");
				}
				else if (!check.m_difficulty.check_pow(pow_hash)) {
					LOGERR(1, "Sidechain block has wrong PoW. Fix it! ");
				}
			}
		}

		m_poolBlockTemplate->m_verified = true;
		if (!m_sidechain->incoming_block_seen(*m_poolBlockTemplate)) {
			m_poolBlockTemplate->m_wantBroadcast = true;
			const bool result = m_sidechain->add_block(*m_poolBlockTemplate);
			if (!result) {
				LOGWARN(3, "failed to submit a share: add_block failed for template id " << template_id);
			}
			return result;
		}

		const PoolBlock* b = m_poolBlockTemplate;
		LOGWARN(3, "failed to submit a share: template id " << template_id << ", block " << b->m_sidechainId << ", nonce = " << b->m_nonce << ", extra_nonce = " << b->m_extraNonce << " was already added before");
		return false;
	}

	BlockTemplate* old = m_oldTemplates[template_id % array_size(&BlockTemplate::m_oldTemplates)];

	if (old && (template_id == old->m_templateId)) {
		return old->submit_sidechain_block(template_id, nonce, extra_nonce);
	}

	LOGWARN(3, "failed to submit a share: template id " << template_id << " is too old/out of range, current template id is " << m_templateId);
	return false;
}

void BlockTemplate::init_merge_mining_merkle_proof()
{
	const uint32_t n_aux_chains = static_cast<uint32_t>(m_poolBlockTemplate->m_auxChains.size() + 1);

	m_poolBlockTemplate->m_merkleProof.clear();
	m_auxDifficulty = diff_max;

	if (n_aux_chains == 1) {
		return;
	}

	std::vector<hash> hashes(n_aux_chains);
	std::vector<bool> used(n_aux_chains);

	for (const AuxChainData& aux_data : m_poolBlockTemplate->m_auxChains) {
		const uint32_t aux_slot = get_aux_slot(aux_data.unique_id, m_poolBlockTemplate->m_auxNonce, n_aux_chains);
		hashes[aux_slot] = aux_data.data;
		used[aux_slot] = true;

		if (aux_data.difficulty < m_auxDifficulty) {
			m_auxDifficulty = aux_data.difficulty;
		}
	}

	const uint32_t aux_slot = get_aux_slot(m_sidechain->consensus_hash(), m_poolBlockTemplate->m_auxNonce, n_aux_chains);
	hashes[aux_slot] = m_poolBlockTemplate->m_sidechainId;
	used[aux_slot] = true;

	for (bool b : used) {
		if (!b) {
			LOGERR(1, "aux nonce is invalid. Fix the code!");
			break;
		}
	}

	std::vector<std::vector<hash>> tree;
	merkle_hash_full_tree(hashes, tree);

	get_merkle_proof(tree, m_poolBlockTemplate->m_sidechainId, m_poolBlockTemplate->m_merkleProof, m_poolBlockTemplate->m_merkleProofPath);
}

} // namespace p2pool
