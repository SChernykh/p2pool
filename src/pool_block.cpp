/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021 SChernykh <https://github.com/SChernykh>
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
#include "pool_block.h"
#include "keccak.h"
#include "side_chain.h"
#include "pow_hash.h"

static constexpr char log_category_prefix[] = "PoolBlock ";

#include "pool_block_parser.inl"

namespace p2pool {

PoolBlock::PoolBlock()
	: m_mainChainHeaderSize(0)
	, m_mainChainMinerTxSize(0)
	, m_mainChainOutputsOffset(0)
	, m_mainChainOutputsBlobSize(0)
	, m_majorVersion(0)
	, m_minorVersion(0)
	, m_timestamp(0)
	, m_prevId{}
	, m_nonce(0)
	, m_txinGenHeight(0)
	, m_txkeyPub{}
	, m_extraNonceSize(0)
	, m_extraNonce(0)
	, m_txkeySec{}
	, m_parent{}
	, m_sidechainHeight(0)
	, m_difficulty{}
	, m_cumulativeDifficulty{}
	, m_sidechainId{}
	, m_depth(0)
	, m_verified(false)
	, m_invalid(false)
	, m_broadcasted(false)
	, m_wantBroadcast(false)
{
	uv_mutex_init_checked(&m_lock);

	m_mainChainData.reserve(48 * 1024);
	m_outputs.reserve(2048);
	m_transactions.reserve(256);
	m_tmpInts.reserve(m_transactions.capacity() * HASH_SIZE);
	m_sideChainData.reserve(512);
	m_uncles.reserve(8);
	m_tmpTxExtra.reserve(80);
}

PoolBlock::PoolBlock(const PoolBlock& b)
{
	uv_mutex_init_checked(&m_lock);
	operator=(b);
}

PoolBlock& PoolBlock::operator=(const PoolBlock& b)
{
	if (this == &b) {
		return *this;
	}

	const int lock_result = uv_mutex_trylock(&b.m_lock);
	if (lock_result) {
		LOGERR(1, "operator= uv_mutex_trylock failed. Fix the code!");
	}

	m_mainChainData = b.m_mainChainData;
	m_mainChainHeaderSize = b.m_mainChainHeaderSize;
	m_mainChainMinerTxSize = b.m_mainChainMinerTxSize;
	m_mainChainOutputsOffset = b.m_mainChainOutputsOffset;
	m_mainChainOutputsBlobSize = b.m_mainChainOutputsBlobSize;
	m_majorVersion = b.m_majorVersion;
	m_minorVersion = b.m_minorVersion;
	m_timestamp = b.m_timestamp;
	m_prevId = b.m_prevId;
	m_nonce = b.m_nonce;
	m_txinGenHeight = b.m_txinGenHeight;
	m_outputs = b.m_outputs;
	m_txkeyPub = b.m_txkeyPub;
	m_extraNonceSize = b.m_extraNonceSize;
	m_extraNonce = b.m_extraNonce;
	m_transactions = b.m_transactions;
	m_sideChainData = b.m_sideChainData;
	m_minerWallet = b.m_minerWallet;
	m_txkeySec = b.m_txkeySec;
	m_parent = b.m_parent;
	m_uncles = b.m_uncles;
	m_sidechainHeight = b.m_sidechainHeight;
	m_difficulty = b.m_difficulty;
	m_cumulativeDifficulty = b.m_cumulativeDifficulty;
	m_sidechainId = b.m_sidechainId;
	m_tmpTxExtra = b.m_tmpTxExtra;
	m_tmpInts = b.m_tmpInts;
	m_depth = b.m_depth;
	m_verified = b.m_verified;
	m_invalid = b.m_invalid;
	m_broadcasted = b.m_broadcasted;
	m_wantBroadcast = b.m_wantBroadcast;

	if (lock_result == 0) {
		uv_mutex_unlock(&b.m_lock);
	}

	return *this;
}

PoolBlock::~PoolBlock()
{
	uv_mutex_destroy(&m_lock);
}

void PoolBlock::serialize_mainchain_data(uint32_t nonce, uint32_t extra_nonce, const hash& sidechain_hash)
{
	MutexLock lock(m_lock);

	m_mainChainData.clear();

	// Header
	m_mainChainData.push_back(m_majorVersion);
	m_mainChainData.push_back(m_minorVersion);
	writeVarint(m_timestamp, m_mainChainData);
	m_mainChainData.insert(m_mainChainData.end(), m_prevId.h, m_prevId.h + HASH_SIZE);
	m_mainChainData.insert(m_mainChainData.end(), reinterpret_cast<uint8_t*>(&nonce), reinterpret_cast<uint8_t*>(&nonce) + NONCE_SIZE);

	m_mainChainHeaderSize = m_mainChainData.size();

	// Miner tx
	m_mainChainData.push_back(TX_VERSION);
	writeVarint(m_txinGenHeight + MINER_REWARD_UNLOCK_TIME, m_mainChainData);
	m_mainChainData.push_back(1);
	m_mainChainData.push_back(TXIN_GEN);
	writeVarint(m_txinGenHeight, m_mainChainData);

	m_mainChainOutputsOffset = static_cast<int>(m_mainChainData.size());

	writeVarint(m_outputs.size(), m_mainChainData);

	for (TxOutput& output : m_outputs) {
		writeVarint(output.m_reward, m_mainChainData);
		m_mainChainData.push_back(TXOUT_TO_KEY);
		m_mainChainData.insert(m_mainChainData.end(), output.m_ephPublicKey.h, output.m_ephPublicKey.h + HASH_SIZE);
	}

	m_mainChainOutputsBlobSize = static_cast<int>(m_mainChainData.size()) - m_mainChainOutputsOffset;

	m_tmpTxExtra.clear();

	m_tmpTxExtra.push_back(TX_EXTRA_TAG_PUBKEY);
	m_tmpTxExtra.insert(m_tmpTxExtra.end(), m_txkeyPub.h, m_txkeyPub.h + HASH_SIZE);

	m_tmpTxExtra.push_back(TX_EXTRA_NONCE);
	writeVarint(m_extraNonceSize, m_tmpTxExtra);

	m_extraNonce = extra_nonce;
	m_tmpTxExtra.insert(m_tmpTxExtra.end(), reinterpret_cast<uint8_t*>(&m_extraNonce), reinterpret_cast<uint8_t*>(&m_extraNonce) + EXTRA_NONCE_SIZE);
	if (m_extraNonceSize > EXTRA_NONCE_SIZE) {
		m_tmpTxExtra.insert(m_tmpTxExtra.end(), m_extraNonceSize - EXTRA_NONCE_SIZE, 0);
	}

	m_tmpTxExtra.push_back(TX_EXTRA_MERGE_MINING_TAG);
	writeVarint(HASH_SIZE, m_tmpTxExtra);
	m_tmpTxExtra.insert(m_tmpTxExtra.end(), sidechain_hash.h, sidechain_hash.h + HASH_SIZE);

	writeVarint(m_tmpTxExtra.size(), m_mainChainData);
	m_mainChainData.insert(m_mainChainData.end(), m_tmpTxExtra.begin(), m_tmpTxExtra.end());

	m_tmpTxExtra.clear();

	m_mainChainData.push_back(0);

	m_mainChainMinerTxSize = m_mainChainData.size() - m_mainChainHeaderSize;

	writeVarint(m_transactions.size() - 1, m_mainChainData);
	const uint8_t* data = reinterpret_cast<const uint8_t*>(m_transactions.data());
	m_mainChainData.insert(m_mainChainData.end(), data + HASH_SIZE, data + m_transactions.size() * HASH_SIZE);
}

void PoolBlock::serialize_sidechain_data()
{
	MutexLock lock(m_lock);

	m_sideChainData.clear();
	m_sideChainData.reserve((m_uncles.size() + 4) * HASH_SIZE + 11);

	const hash& spend = m_minerWallet.spend_public_key();
	const hash& view = m_minerWallet.view_public_key();

	m_sideChainData.insert(m_sideChainData.end(), spend.h, spend.h + HASH_SIZE);
	m_sideChainData.insert(m_sideChainData.end(), view.h, view.h + HASH_SIZE);
	m_sideChainData.insert(m_sideChainData.end(), m_txkeySec.h, m_txkeySec.h + HASH_SIZE);
	m_sideChainData.insert(m_sideChainData.end(), m_parent.h, m_parent.h + HASH_SIZE);

	writeVarint(m_uncles.size(), m_sideChainData);

	for (const hash& id : m_uncles) {
		m_sideChainData.insert(m_sideChainData.end(), id.h, id.h + HASH_SIZE);
	}

	writeVarint(m_sidechainHeight, m_sideChainData);

	writeVarint(m_difficulty.lo, m_sideChainData);
	writeVarint(m_difficulty.hi, m_sideChainData);

	writeVarint(m_cumulativeDifficulty.lo, m_sideChainData);
	writeVarint(m_cumulativeDifficulty.hi, m_sideChainData);
}

bool PoolBlock::get_pow_hash(RandomX_Hasher* hasher, const hash& seed_hash, hash& pow_hash)
{
	alignas(8) uint8_t hashes[HASH_SIZE * 3];

	uint64_t* second_hash = reinterpret_cast<uint64_t*>(hashes + HASH_SIZE);
	second_hash[0] = 0x14281e7a9e7836bcull;
	second_hash[1] = 0x7d818f8229424636ull;
	second_hash[2] = 0x9165d677b4f71266ull;
	second_hash[3] = 0x8ac9bc64e0a996ffull;

	memset(hashes + HASH_SIZE * 2, 0, HASH_SIZE);

	uint64_t count;

	uint8_t blob[128];
	size_t blob_size = 0;

	{
		MutexLock lock(m_lock);

		if (!m_mainChainHeaderSize || !m_mainChainMinerTxSize || (m_mainChainData.size() < m_mainChainHeaderSize + m_mainChainMinerTxSize)) {
			LOGERR(1, "tried to calculate PoW of uninitialized block");
			return false;
		}

		blob_size = m_mainChainHeaderSize;
		memcpy(blob, m_mainChainData.data(), blob_size);

		uint8_t* miner_tx = m_mainChainData.data() + m_mainChainHeaderSize;
		keccak(miner_tx, static_cast<int>(m_mainChainMinerTxSize) - 1, reinterpret_cast<uint8_t*>(hashes), HASH_SIZE);

		count = m_transactions.size();
		uint8_t* h = reinterpret_cast<uint8_t*>(m_transactions.data());

		keccak(reinterpret_cast<uint8_t*>(hashes), HASH_SIZE * 3, h, HASH_SIZE);

		if (count == 1) {
			memcpy(blob + blob_size, h, HASH_SIZE);
		}
		else if (count == 2) {
			keccak(h, HASH_SIZE * 2, blob + blob_size, HASH_SIZE);
		}
		else {
			size_t i, j, cnt;

			for (i = 0, cnt = 1; cnt <= count; ++i, cnt <<= 1) {}

			cnt >>= 1;

			m_tmpInts.resize(cnt * HASH_SIZE);
			memcpy(m_tmpInts.data(), h, (cnt * 2 - count) * HASH_SIZE);

			for (i = cnt * 2 - count, j = cnt * 2 - count; j < cnt; i += 2, ++j) {
				keccak(h + i * HASH_SIZE, HASH_SIZE * 2, m_tmpInts.data() + j * HASH_SIZE, HASH_SIZE);
			}

			while (cnt > 2) {
				cnt >>= 1;
				for (i = 0, j = 0; j < cnt; i += 2, ++j) {
					keccak(m_tmpInts.data() + i * HASH_SIZE, HASH_SIZE * 2, m_tmpInts.data() + j * HASH_SIZE, HASH_SIZE);
				}
			}

			keccak(m_tmpInts.data(), HASH_SIZE * 2, blob + blob_size, HASH_SIZE);
		}
	}
	blob_size += HASH_SIZE;

	writeVarint(count, [&blob, &blob_size](uint8_t b) { blob[blob_size++] = b; });

	return hasher->calculate(blob, blob_size, seed_hash, pow_hash);
}

} // namespace p2pool
