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
#include "wallet.h"

#ifdef _DEBUG
#define POOL_BLOCK_DEBUG 1
#else
#define POOL_BLOCK_DEBUG 0
#endif

namespace p2pool {

class RandomX_Hasher_Base;
class SideChain;

/*
* --------------------------------------------------
* |                   POOL BLOCK                   |
* |------------------------------------------------|
* |    Monero block template     | Side-chain data |
* |------------------------------|-----------------|
* |xxxNONCExxxEXTRA_NONCExHASHxxx|xxxxxxxxxxxxxxxxx|
* --------------------------------------------------
*
* HASH comes in TX_EXTRA_MERGE_MINING_TAG directly after EXTRA_NONCE
* HASH is calculated from all pool block's bytes and consensus ID (NONCE, EXTRA_NONCE and HASH itself are replaced with 0's when calculating HASH)
* Pool block's PoW hash is calculated from the Monero block template part using Monero's consensus rules
*/

struct DifficultyData
{
	FORCEINLINE DifficultyData(uint64_t t, const difficulty_type& d) : m_timestamp(t), m_cumulativeDifficulty(d) {}

	uint64_t m_timestamp;
	difficulty_type m_cumulativeDifficulty;
};

struct PoolBlock
{
	PoolBlock();
	~PoolBlock();

	PoolBlock(const PoolBlock& b);
	PoolBlock& operator=(const PoolBlock& b);

	mutable uv_mutex_t m_lock;

	// Monero block template
	std::vector<uint8_t> m_mainChainData;
	size_t m_mainChainHeaderSize;
	size_t m_mainChainMinerTxSize;
	int m_mainChainOutputsOffset;
	int m_mainChainOutputsBlobSize;

	uint8_t m_majorVersion;
	uint8_t m_minorVersion;
	uint64_t m_timestamp;
	hash m_prevId;
	uint32_t m_nonce;

	// Miner transaction
	uint64_t m_txinGenHeight;

	struct TxOutput
	{
		FORCEINLINE TxOutput() : m_reward(0), m_ephPublicKey(), m_txType(0), m_viewTag(0) {}
		FORCEINLINE TxOutput(uint64_t r, const hash& k, uint8_t tx_type, uint8_t view_tag) : m_reward(r), m_ephPublicKey(k), m_txType(tx_type), m_viewTag(view_tag) {}

		uint64_t m_reward;
		hash m_ephPublicKey;
		uint8_t m_txType;
		uint8_t m_viewTag;
	};

	std::vector<TxOutput> m_outputs;

	hash m_txkeyPub;
	uint64_t m_extraNonceSize;
	uint32_t m_extraNonce;

	// All block transaction hashes including the miner transaction hash at index 0
	std::vector<hash> m_transactions;

	// Side-chain data
	std::vector<uint8_t> m_sideChainData;

	// Miner's wallet
	Wallet m_minerWallet{ nullptr };

	// Transaction secret key
	// Required to check that pub keys in the miner transaction pay out to correct miner wallet addresses
	hash m_txkeySec;

	// Side-chain parent and uncle blocks
	hash m_parent;
	std::vector<hash> m_uncles;

	// Blockchain data
	uint64_t m_sidechainHeight;
	difficulty_type m_difficulty;
	difficulty_type m_cumulativeDifficulty;

	// HASH (see diagram in the comment above)
	hash m_sidechainId;

	// Just temporary stuff, not a part of the block
	std::vector<uint8_t> m_tmpTxExtra;

	uint64_t m_depth;

	bool m_verified;
	bool m_invalid;

	mutable bool m_broadcasted;
	mutable bool m_wantBroadcast;

	uint64_t m_localTimestamp;

	void serialize_mainchain_data(uint32_t nonce, uint32_t extra_nonce, const hash& sidechain_hash);
	void serialize_sidechain_data();

	int deserialize(const uint8_t* data, size_t size, const SideChain& sidechain);
	void reset_offchain_data();

	bool get_pow_hash(RandomX_Hasher_Base* hasher, uint64_t height, const hash& seed_hash, hash& pow_hash);

	uint64_t get_payout(const Wallet& w) const;

	// Both tx types are allowed by Monero consensus during v15 because it needs to process pre-fork mempool transactions,
	// but P2Pool can switch to using only TXOUT_TO_TAGGED_KEY for miner payouts starting from v15
	FORCEINLINE uint8_t get_tx_type() const { return (m_majorVersion < HARDFORK_VIEW_TAGS_VERSION) ? TXOUT_TO_KEY : TXOUT_TO_TAGGED_KEY; }
};

} // namespace p2pool
