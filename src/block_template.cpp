/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2022 SChernykh <https://github.com/SChernykh>
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
#include <zmq.hpp>
#include <ctime>
#include <numeric>

static constexpr char log_category_prefix[] = "BlockTemplate ";

namespace p2pool {

BlockTemplate::BlockTemplate(p2pool* pool)
	: m_pool(pool)
	, m_templateId(0)
	, m_blockHeaderSize(0)
	, m_minerTxOffsetInTemplate(0)
	, m_minerTxSize(0)
	, m_nonceOffset(0)
	, m_extraNonceOffsetInTemplate(0)
	, m_numTransactionHashes(0)
	, m_prevId{}
	, m_height(0)
	, m_difficulty{}
	, m_seedHash{}
	, m_timestamp(0)
	, m_txkeyPub{}
	, m_txkeySec{}
	, m_poolBlockTemplate(new PoolBlock())
	, m_finalReward(0)
{
	uv_rwlock_init_checked(&m_lock);

	m_blockHeader.reserve(64);
	m_minerTx.reserve(49152);
	m_minerTxExtra.reserve(64);
	m_transactionHashes.reserve(8192);
	m_rewards.reserve(100);
	m_blockTemplateBlob.reserve(65536);
	m_merkleTreeMainBranch.reserve(HASH_SIZE * 10);
	m_mempoolTxs.reserve(1024);
	m_mempoolTxsOrder.reserve(1024);
	m_shares.reserve(m_pool->side_chain().chain_window_size() * 2);

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

	m_pool = b.m_pool;
	m_templateId = b.m_templateId;
	m_blockTemplateBlob = b.m_blockTemplateBlob;
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
	m_seedHash = b.m_seedHash;
	m_timestamp = b.m_timestamp;
	m_txkeyPub = b.m_txkeyPub;
	m_txkeySec = b.m_txkeySec;
	*m_poolBlockTemplate = *b.m_poolBlockTemplate;
	m_finalReward = b.m_finalReward;

	m_minerTx.clear();
	m_blockHeader.clear();
	m_minerTxExtra.clear();
	m_transactionHashes.clear();
	m_rewards.clear();
	m_mempoolTxs.clear();
	m_mempoolTxsOrder.clear();
	m_shares.clear();

#if TEST_MEMPOOL_PICKING_ALGORITHM
	m_knapsack.clear();
#endif

	return *this;
}

static FORCEINLINE uint64_t get_base_reward(uint64_t already_generated_coins)
{
	const uint64_t result = ~already_generated_coins >> 19;

	constexpr uint64_t min_reward = 600000000000ULL;
	return (result < min_reward) ? min_reward : result;
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

void BlockTemplate::update(const MinerData& data, const Mempool& mempool, Wallet* miner_wallet)
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

	// When block template generation fails for any reason
	auto use_old_template = [this]() {
		const uint32_t id = m_templateId - 1;
		LOGWARN(4, "using old block template with ID = " << id);
		*this = *m_oldTemplates[id % array_size(&BlockTemplate::m_oldTemplates)];
	};

	get_tx_keys(m_txkeyPub, m_txkeySec, miner_wallet->spend_public_key(), data.prev_id);

	m_height = data.height;
	m_difficulty = data.difficulty;
	m_seedHash = data.seed_hash;

	// Only choose transactions that were received 10 or more seconds ago
	size_t total_mempool_transactions;
	{
		m_mempoolTxs.clear();

		ReadLock mempool_lock(mempool.m_lock);

		total_mempool_transactions = mempool.m_transactions.size();

		const uint64_t cur_time = seconds_since_epoch();

		for (auto& it : mempool.m_transactions) {
			if (cur_time >= it.second.time_received + 10) {
				m_mempoolTxs.emplace_back(it.second);
			}
		}
	}

	// Safeguard for busy mempool moments
	// If the block template gets too big, nodes won't be able to send and receive it because of p2p packet size limit
	// Select 1000 transactions with the highest fee per byte
	if (m_mempoolTxs.size() > 1000) {
		std::nth_element(m_mempoolTxs.begin(), m_mempoolTxs.begin() + 1000, m_mempoolTxs.end(),
			[](const TxMempoolData& tx_a, const TxMempoolData& tx_b)
			{
				return tx_a.fee * tx_b.weight > tx_b.fee * tx_a.weight;
			});
		m_mempoolTxs.resize(1000);
	}

	LOGINFO(4, "mempool has " << total_mempool_transactions << " transactions, taking " << m_mempoolTxs.size() << " transactions from it");

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

	m_blockHeaderSize = m_blockHeader.size();

	m_pool->side_chain().fill_sidechain_data(*m_poolBlockTemplate, miner_wallet, m_txkeySec, m_shares);
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
		m_numTransactionHashes = 0;

		final_fees = 0;
		final_weight = miner_tx_weight;

		m_transactionHashes.assign(HASH_SIZE, 0);
		for (const TxMempoolData& tx : m_mempoolTxs) {
			m_transactionHashes.insert(m_transactionHashes.end(), tx.id.h, tx.id.h + HASH_SIZE);
			++m_numTransactionHashes;

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
		std::sort(m_mempoolTxsOrder.begin(), m_mempoolTxsOrder.end(),
			[this](int a, int b)
			{
				const TxMempoolData& tx_a = m_mempoolTxs[a];
				const TxMempoolData& tx_b = m_mempoolTxs[b];
				return tx_a.fee * tx_b.weight > tx_b.fee * tx_a.weight;
			});

		final_reward = base_reward;
		final_fees = 0;
		final_weight = miner_tx_weight;

		for (int i = 0; i < static_cast<int>(m_mempoolTxsOrder.size());) {
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
				for (int j = 0; j < i; ++j) {
					const TxMempoolData& prev_tx = m_mempoolTxs[m_mempoolTxsOrder[j]];
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
				final_fees += tx.fee;
				final_weight += tx.weight;
				++i;
				continue;
			}

			if (k >= 0) {
				// Replacing another tx with this tx improves the reward
				const TxMempoolData& prev_tx = m_mempoolTxs[m_mempoolTxsOrder[k]];
				final_fees += tx.fee - prev_tx.fee;
				final_weight += tx.weight - prev_tx.weight;
			}

			m_mempoolTxsOrder.erase(m_mempoolTxsOrder.begin() + ((k >= 0) ? k : i));
		}

		final_fees = 0;
		final_weight = miner_tx_weight;

		m_numTransactionHashes = m_mempoolTxsOrder.size();
		m_transactionHashes.assign(HASH_SIZE, 0);
		for (size_t i = 0; i < m_mempoolTxsOrder.size(); ++i) {
			const TxMempoolData& tx = m_mempoolTxs[m_mempoolTxsOrder[i]];
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

	m_poolBlockTemplate->serialize_sidechain_data();
	m_poolBlockTemplate->m_sidechainId = calc_sidechain_hash();
	const int sidechain_hash_offset = static_cast<int>(m_extraNonceOffsetInTemplate + m_poolBlockTemplate->m_extraNonceSize) + 2;

	memcpy(m_blockTemplateBlob.data() + sidechain_hash_offset, m_poolBlockTemplate->m_sidechainId.h, HASH_SIZE);
	memcpy(m_minerTx.data() + sidechain_hash_offset - m_minerTxOffsetInTemplate, m_poolBlockTemplate->m_sidechainId.h, HASH_SIZE);

#if POOL_BLOCK_DEBUG
	const std::vector<uint8_t> mainchain_data = m_poolBlockTemplate->serialize_mainchain_data();

	if (mainchain_data != m_blockTemplateBlob) {
		LOGERR(1, "serialize_mainchain_data() has a bug, fix it! ");
		LOGERR(1, "m_poolBlockTemplate->m_mainChainData.size() = " << mainchain_data.size());
		LOGERR(1, "m_blockTemplateBlob.size()         = " << m_blockTemplateBlob.size());
		for (size_t i = 0, n = std::min(mainchain_data.size(), m_blockTemplateBlob.size()); i < n; ++i) {
			if (mainchain_data[i] != m_blockTemplateBlob[i]) {
				LOGERR(1, "m_poolBlockTemplate->m_mainChainData is different at offset " << i);
				break;
			}
		}
	}

	{
		std::vector<uint8_t> buf = m_blockTemplateBlob;
		buf.insert(buf.end(), m_poolBlockTemplate->m_sideChainData.begin(), m_poolBlockTemplate->m_sideChainData.end());

		PoolBlock check;
		const int result = check.deserialize(buf.data(), buf.size(), m_pool->side_chain(), nullptr);
		if (result != 0) {
			LOGERR(1, "pool block blob generation and/or parsing is broken, error " << result);
		}
		else {
			LOGINFO(6, "blob size = " << buf.size());
		}
	}
#endif

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
	m_rewards.clear();
	m_mempoolTxs.clear();
	m_mempoolTxsOrder.clear();
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
	const uint64_t max_weight = data.median_weight + (data.median_weight / 32) - miner_tx_weight;

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
			if (!shares[i].m_wallet->get_eph_public_key(m_txkeySec, i, eph_public_key, view_tag)) {
				LOGERR(1, "get_eph_public_key failed at index " << i);
			}
			m_minerTx.insert(m_minerTx.end(), eph_public_key.h, eph_public_key.h + HASH_SIZE);
			m_poolBlockTemplate->m_outputs.emplace_back(m_rewards[i], eph_public_key, tx_type, view_tag);
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

	m_poolBlockTemplate->m_txkeyPub = m_txkeyPub;
	m_poolBlockTemplate->m_txkeySec = m_txkeySec;

	// TX_EXTRA begin
	m_minerTxExtra.clear();

	m_minerTxExtra.push_back(TX_EXTRA_TAG_PUBKEY);
	m_minerTxExtra.insert(m_minerTxExtra.end(), m_txkeyPub.h, m_txkeyPub.h + HASH_SIZE);

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
	writeVarint(HASH_SIZE, m_minerTxExtra);
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

hash BlockTemplate::calc_sidechain_hash() const
{
	// Calculate side-chain hash (all block template bytes + all side-chain bytes + consensus ID, replacing NONCE, EXTRA_NONCE and HASH itself with 0's)
	hash sidechain_hash;
	const int sidechain_hash_offset = static_cast<int>(m_extraNonceOffsetInTemplate + m_poolBlockTemplate->m_extraNonceSize) + 2;
	const int blob_size = static_cast<int>(m_blockTemplateBlob.size());

	const std::vector<uint8_t>& consensus_id = m_pool->side_chain().consensus_id();

	keccak_custom([this, sidechain_hash_offset, blob_size, consensus_id](int offset) -> uint8_t {
			uint32_t k = static_cast<uint32_t>(offset - static_cast<int>(m_nonceOffset));
			if (k < NONCE_SIZE) {
				return 0;
			}

			k = static_cast<uint32_t>(offset - static_cast<int>(m_extraNonceOffsetInTemplate));
			if (k < EXTRA_NONCE_SIZE) {
				return 0;
			}

			k = static_cast<uint32_t>(offset - sidechain_hash_offset);
			if (k < HASH_SIZE) {
				return 0;
			}

			if (offset < blob_size) {
				return m_blockTemplateBlob[offset];
			}

			const int side_chain_data_offsset = offset - blob_size;
			const int side_chain_data_size = static_cast<int>(m_poolBlockTemplate->m_sideChainData.size());
			if (side_chain_data_offsset < side_chain_data_size) {
				return m_poolBlockTemplate->m_sideChainData[side_chain_data_offsset];
			}

			const int consensus_id_offset = side_chain_data_offsset - side_chain_data_size;
			return consensus_id[consensus_id_offset];
		},
		static_cast<int>(m_blockTemplateBlob.size() + m_poolBlockTemplate->m_sideChainData.size() + consensus_id.size()), sidechain_hash.h, HASH_SIZE);

	return sidechain_hash;
}

hash BlockTemplate::calc_miner_tx_hash(uint32_t extra_nonce) const
{
	// Calculate 3 partial hashes
	uint8_t hashes[HASH_SIZE * 3];

	const uint8_t* data = m_blockTemplateBlob.data() + m_minerTxOffsetInTemplate;

	const int extra_nonce_offset = static_cast<int>(m_extraNonceOffsetInTemplate - m_minerTxOffsetInTemplate);
	const uint8_t extra_nonce_buf[EXTRA_NONCE_SIZE] = {
		static_cast<uint8_t>(extra_nonce >> 0),
		static_cast<uint8_t>(extra_nonce >> 8),
		static_cast<uint8_t>(extra_nonce >> 16),
		static_cast<uint8_t>(extra_nonce >> 24)
	};

	// 1. Prefix (everything except vin_rct_type byte in the end)
	// Apply extra_nonce in-place because we can't write to the block template here
	keccak_custom([data, extra_nonce_offset, &extra_nonce_buf](int offset)
		{
			const uint32_t k = static_cast<uint32_t>(offset - extra_nonce_offset);
			if (k < EXTRA_NONCE_SIZE) {
				return extra_nonce_buf[k];
			}
			return data[offset];
		},
		static_cast<int>(m_minerTxSize) - 1, hashes, HASH_SIZE);

	// 2. Base RCT, single 0 byte in miner tx
	static constexpr uint8_t known_second_hash[HASH_SIZE] = {
		188,54,120,158,122,30,40,20,54,70,66,41,130,143,129,125,102,18,247,180,119,214,101,145,255,150,169,224,100,188,201,138
	};
	memcpy(hashes + HASH_SIZE, known_second_hash, HASH_SIZE);

	// 3. Prunable RCT, empty in miner tx
	memset(hashes + HASH_SIZE * 2, 0, HASH_SIZE);

	// Calculate miner transaction hash
	hash result;
	keccak(hashes, sizeof(hashes), result.h, HASH_SIZE);

	return result;
}

void BlockTemplate::calc_merkle_tree_main_branch()
{
	m_merkleTreeMainBranch.clear();

	const uint64_t count = m_numTransactionHashes + 1;
	const uint8_t* h = m_transactionHashes.data();

	hash root_hash;

	if (count == 1) {
		memcpy(root_hash.h, h, HASH_SIZE);
	}
	else if (count == 2) {
		m_merkleTreeMainBranch.insert(m_merkleTreeMainBranch.end(), h + HASH_SIZE, h + HASH_SIZE * 2);
		keccak(h, HASH_SIZE * 2, root_hash.h, HASH_SIZE);
	}
	else {
		size_t i, j, cnt;

		for (i = 0, cnt = 1; cnt <= count; ++i, cnt <<= 1) {}

		cnt >>= 1;

		std::vector<uint8_t> ints(cnt * HASH_SIZE);
		memcpy(ints.data(), h, (cnt * 2 - count) * HASH_SIZE);

		for (i = cnt * 2 - count, j = cnt * 2 - count; j < cnt; i += 2, ++j) {
			if (i == 0) {
				m_merkleTreeMainBranch.insert(m_merkleTreeMainBranch.end(), h + HASH_SIZE, h + HASH_SIZE * 2);
			}
			keccak(h + i * HASH_SIZE, HASH_SIZE * 2, ints.data() + j * HASH_SIZE, HASH_SIZE);
		}

		while (cnt > 2) {
			cnt >>= 1;
			for (i = 0, j = 0; j < cnt; i += 2, ++j) {
				if (i == 0) {
					m_merkleTreeMainBranch.insert(m_merkleTreeMainBranch.end(), ints.data() + HASH_SIZE, ints.data() + HASH_SIZE * 2);
				}
				keccak(ints.data() + i * HASH_SIZE, HASH_SIZE * 2, ints.data() + j * HASH_SIZE, HASH_SIZE);
			}
		}

		m_merkleTreeMainBranch.insert(m_merkleTreeMainBranch.end(), ints.data() + HASH_SIZE, ints.data() + HASH_SIZE * 2);
		keccak(ints.data(), HASH_SIZE * 2, root_hash.h, HASH_SIZE);
	}
}

bool BlockTemplate::get_difficulties(const uint32_t template_id, uint64_t& height, difficulty_type& mainchain_difficulty, difficulty_type& sidechain_difficulty) const
{
	ReadLock lock(m_lock);

	if (template_id == m_templateId) {
		height = m_height;
		mainchain_difficulty = m_difficulty;
		sidechain_difficulty = m_poolBlockTemplate->m_difficulty;
		return true;
	}

	const BlockTemplate* old = m_oldTemplates[template_id % array_size(&BlockTemplate::m_oldTemplates)];

	if (old && (template_id == old->m_templateId)) {
		return old->get_difficulties(template_id, height, mainchain_difficulty, sidechain_difficulty);
	}

	return false;
}

uint32_t BlockTemplate::get_hashing_blob(const uint32_t template_id, uint32_t extra_nonce, uint8_t (&blob)[128], uint64_t& height, difficulty_type& difficulty, difficulty_type& sidechain_difficulty, hash& seed_hash, size_t& nonce_offset) const
{
	ReadLock lock(m_lock);

	if (template_id == m_templateId) {
		height = m_height;
		difficulty = m_difficulty;
		sidechain_difficulty = m_poolBlockTemplate->m_difficulty;
		seed_hash = m_seedHash;
		nonce_offset = m_nonceOffset;

		return get_hashing_blob_nolock(extra_nonce, blob);
	}

	const BlockTemplate* old = m_oldTemplates[template_id % array_size(&BlockTemplate::m_oldTemplates)];

	if (old && (template_id == old->m_templateId)) {
		return old->get_hashing_blob(template_id, extra_nonce, blob, height, difficulty, sidechain_difficulty, seed_hash, nonce_offset);
	}

	return 0;
}

uint32_t BlockTemplate::get_hashing_blob(uint32_t extra_nonce, uint8_t (&blob)[128], uint64_t& height, difficulty_type& difficulty, difficulty_type& sidechain_difficulty, hash& seed_hash, size_t& nonce_offset, uint32_t& template_id) const
{
	ReadLock lock(m_lock);

	height = m_height;
	difficulty = m_difficulty;
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

		keccak(h, HASH_SIZE * 2, root_hash.h, HASH_SIZE);
	}

	memcpy(p, root_hash.h, HASH_SIZE);
	p += HASH_SIZE;

	// Total number of transactions in this block (including the miner tx)
	writeVarint(m_numTransactionHashes + 1, [&p](uint8_t b) { *(p++) = b; });

	return static_cast<uint32_t>(p - blob);
}

uint32_t BlockTemplate::get_hashing_blobs(uint32_t extra_nonce_start, uint32_t count, std::vector<uint8_t>& blobs, uint64_t& height, difficulty_type& difficulty, difficulty_type& sidechain_difficulty, hash& seed_hash, size_t& nonce_offset, uint32_t& template_id) const
{
	blobs.clear();

	const size_t required_capacity = static_cast<size_t>(count) * 80;
	if (blobs.capacity() < required_capacity) {
		blobs.reserve(required_capacity * 2);
	}

	uint32_t blob_size = 0;

	ReadLock lock(m_lock);

	height = m_height;
	difficulty = m_difficulty;
	sidechain_difficulty = m_poolBlockTemplate->m_difficulty;
	seed_hash = m_seedHash;
	nonce_offset = m_nonceOffset;
	template_id = m_templateId;

	for (uint32_t i = 0; i < count; ++i) {
		uint8_t blob[128];
		uint32_t n = get_hashing_blob_nolock(extra_nonce_start + i, blob);

		if (n > sizeof(blob)) {
			LOGERR(1, "internal error: get_hashing_blob_nolock returned too large blob size " << n << ", expected <= " << sizeof(blob));
			n = sizeof(blob);
		}
		else if (n < 76) {
			LOGERR(1, "internal error: get_hashing_blob_nolock returned too little blob size " << n << ", expected >= 76");
		}

		if (blob_size == 0) {
			blob_size = n;
		}
		else if (n != blob_size) {
			LOGERR(1, "internal error: get_hashing_blob_nolock returned different blob size " << n << ", expected " << blob_size);
		}
		blobs.insert(blobs.end(), blob, blob + blob_size);
	}

	return blob_size;
}

std::vector<uint8_t> BlockTemplate::get_block_template_blob(uint32_t template_id, size_t& nonce_offset, size_t& extra_nonce_offset) const
{
	ReadLock lock(m_lock);

	if (template_id != m_templateId) {
		const BlockTemplate* old = m_oldTemplates[template_id % array_size(&BlockTemplate::m_oldTemplates)];
		if (old && (template_id == old->m_templateId)) {
			return old->get_block_template_blob(template_id, nonce_offset, extra_nonce_offset);
		}

		nonce_offset = 0;
		extra_nonce_offset = 0;
		return std::vector<uint8_t>();
	}

	nonce_offset = m_nonceOffset;
	extra_nonce_offset = m_extraNonceOffsetInTemplate;
	return m_blockTemplateBlob;
}

void BlockTemplate::submit_sidechain_block(uint32_t template_id, uint32_t nonce, uint32_t extra_nonce)
{
	WriteLock lock(m_lock);

	if (template_id == m_templateId) {
		m_poolBlockTemplate->m_nonce = nonce;
		m_poolBlockTemplate->m_extraNonce = extra_nonce;

		SideChain& side_chain = m_pool->side_chain();

#if POOL_BLOCK_DEBUG
		{
			std::vector<uint8_t> buf = m_poolBlockTemplate->serialize_mainchain_data();

			memcpy(buf.data() + m_nonceOffset, &nonce, NONCE_SIZE);
			memcpy(buf.data() + m_extraNonceOffsetInTemplate, &extra_nonce, EXTRA_NONCE_SIZE);

			buf.insert(buf.end(), m_poolBlockTemplate->m_sideChainData.begin(), m_poolBlockTemplate->m_sideChainData.end());

			PoolBlock check;
			const int result = check.deserialize(buf.data(), buf.size(), side_chain, nullptr);
			if (result != 0) {
				LOGERR(1, "pool block blob generation and/or parsing is broken, error " << result);
			}

			hash pow_hash;
			if (!check.get_pow_hash(m_pool->hasher(), check.m_txinGenHeight, m_seedHash, pow_hash)) {
				LOGERR(1, "PoW check failed for the sidechain block. Fix it! ");
			}
			else if (!check.m_difficulty.check_pow(pow_hash)) {
				LOGERR(1, "Sidechain block has wrong PoW. Fix it! ");
			}
		}
#endif

		m_poolBlockTemplate->m_verified = true;
		if (!side_chain.block_seen(*m_poolBlockTemplate)) {
			m_poolBlockTemplate->m_wantBroadcast = true;
			side_chain.add_block(*m_poolBlockTemplate);
		}
		return;
	}

	BlockTemplate* old = m_oldTemplates[template_id % array_size(&BlockTemplate::m_oldTemplates)];

	if (old && (template_id == old->m_templateId)) {
		old->submit_sidechain_block(template_id, nonce, extra_nonce);
		return;
	}
}

} // namespace p2pool
