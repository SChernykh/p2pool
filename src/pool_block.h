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
#include "wallet.h"

#ifdef _DEBUG
#define POOL_BLOCK_DEBUG 1
#else
#define POOL_BLOCK_DEBUG 0
#endif

namespace p2pool {

static FORCEINLINE constexpr int pool_block_debug() { return POOL_BLOCK_DEBUG; }

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

	PoolBlock(const PoolBlock& b);
	PoolBlock& operator=(const PoolBlock& b);

#if POOL_BLOCK_DEBUG
	std::vector<uint8_t> m_mainChainDataDebug;
	std::vector<uint8_t> m_sideChainDataDebug;
#endif

	// Monero block template
	uint8_t m_majorVersion;
	uint8_t m_minorVersion;
	uint64_t m_timestamp;
	hash m_prevId;
	uint32_t m_nonce;

	// Miner transaction
	uint64_t m_txinGenHeight;

	struct TxOutput
	{
		FORCEINLINE TxOutput() : m_ephPublicKey(), m_reward(0), m_viewTag(0) {}
		FORCEINLINE TxOutput(uint64_t r, const hash& k, uint8_t view_tag) : m_ephPublicKey(k), m_reward(r), m_viewTag(view_tag) {}

		hash m_ephPublicKey;
		uint64_t m_reward : 56;
		uint64_t m_viewTag : 8;
	};

	static_assert(sizeof(TxOutput) == sizeof(hash) + sizeof(uint64_t), "TxOutput bit packing didn't work with this compiler, fix the code!");

	std::vector<TxOutput> m_outputs;

	hash m_txkeyPub;
	uint64_t m_extraNonceSize;
	uint32_t m_extraNonce;

	// All block transaction hashes including the miner transaction hash at index 0
	std::vector<hash> m_transactions;

	// Miner's wallet
	Wallet m_minerWallet{ nullptr };

	// Transaction secret key
	// Required to check that pub keys in the miner transaction pay out to correct miner wallet addresses
	hash m_txkeySecSeed;
	hash m_txkeySec;

	// Side-chain parent and uncle blocks
	hash m_parent;
	std::vector<hash> m_uncles;

	// Blockchain data
	uint64_t m_sidechainHeight;
	difficulty_type m_difficulty;
	difficulty_type m_cumulativeDifficulty;

	// Arbitrary extra data
	uint32_t m_sidechainExtraBuf[4];

	// HASH (see diagram in the comment above)
	hash m_sidechainId;

	// Just temporary stuff, not a part of the block
	uint64_t m_depth;

	bool m_verified;
	bool m_invalid;

	mutable bool m_broadcasted;
	mutable bool m_wantBroadcast;

	bool m_precalculated;

	uint64_t m_localTimestamp;
	uint64_t m_receivedTimestamp;

	std::vector<uint8_t> serialize_mainchain_data(size_t* header_size = nullptr, size_t* miner_tx_size = nullptr, int* outputs_offset = nullptr, int* outputs_blob_size = nullptr, const uint32_t* nonce = nullptr, const uint32_t* extra_nonce = nullptr) const;
	std::vector<uint8_t> serialize_sidechain_data() const;

	int deserialize(const uint8_t* data, size_t size, const SideChain& sidechain, uv_loop_t* loop, bool compact);
	void reset_offchain_data();

	bool get_pow_hash(RandomX_Hasher_Base* hasher, uint64_t height, const hash& seed_hash, hash& pow_hash);

	uint64_t get_payout(const Wallet& w) const;

	// Both tx types are allowed by Monero consensus during v15 because it needs to process pre-fork mempool transactions,
	// but P2Pool can switch to using only TXOUT_TO_TAGGED_KEY for miner payouts starting from v15
	FORCEINLINE uint8_t get_tx_type() const { return (m_majorVersion < HARDFORK_VIEW_TAGS_VERSION) ? TXOUT_TO_KEY : TXOUT_TO_TAGGED_KEY; }

	typedef std::array<uint8_t, HASH_SIZE + NONCE_SIZE + EXTRA_NONCE_SIZE> full_id;

	FORCEINLINE full_id get_full_id() const
	{
		full_id key;
		uint8_t* p = key.data();
		memcpy(p, m_sidechainId.h, HASH_SIZE);
		memcpy(p + HASH_SIZE, &m_nonce, NONCE_SIZE);
		memcpy(p + HASH_SIZE + NONCE_SIZE, &m_extraNonce, EXTRA_NONCE_SIZE);
		return key;
	}

	hash calculate_tx_key_seed() const;
};

} // namespace p2pool
