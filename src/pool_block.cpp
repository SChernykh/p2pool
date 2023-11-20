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
#include "pool_block.h"
#include "keccak.h"
#include "side_chain.h"
#include "pow_hash.h"
#include "crypto.h"
#include "merkle.h"

LOG_CATEGORY(PoolBlock)

#include "pool_block_parser.inl"

namespace p2pool {

PoolBlock::PoolBlock()
	: m_majorVersion(0)
	, m_minorVersion(0)
	, m_timestamp(0)
	, m_prevId{}
	, m_nonce(0)
	, m_txinGenHeight(0)
	, m_txkeyPub{}
	, m_extraNonceSize(0)
	, m_extraNonce(0)
	, m_merkleTreeDataSize(1)
	, m_merkleTreeData(0)
	, m_merkleRoot{}
	, m_txkeySecSeed{}
	, m_txkeySec{}
	, m_parent{}
	, m_sidechainHeight(0)
	, m_difficulty{}
	, m_cumulativeDifficulty{}
	, m_sidechainExtraBuf{}
	, m_sidechainId{}
	, m_depth(0)
	, m_verified(false)
	, m_invalid(false)
	, m_broadcasted(false)
	, m_wantBroadcast(false)
	, m_precalculated(false)
	, m_localTimestamp(seconds_since_epoch())
	, m_receivedTimestamp(0)
	, m_auxNonce(0)
{
}

PoolBlock::PoolBlock(const PoolBlock& b)
{
	operator=(b);
}

// cppcheck-suppress operatorEqVarError
PoolBlock& PoolBlock::operator=(const PoolBlock& b)
{
	if (this == &b) {
		return *this;
	}

#if POOL_BLOCK_DEBUG
	m_mainChainDataDebug = b.m_mainChainDataDebug;
	m_sideChainDataDebug = b.m_sideChainDataDebug;
#endif

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
	m_merkleTreeDataSize = b.m_merkleTreeDataSize;
	m_merkleTreeData = b.m_merkleTreeData;
	m_merkleRoot = b.m_merkleRoot;
	m_transactions = b.m_transactions;
	m_minerWallet = b.m_minerWallet;
	m_txkeySecSeed = b.m_txkeySecSeed;
	m_txkeySec = b.m_txkeySec;
	m_parent = b.m_parent;
	m_uncles = b.m_uncles;
	m_sidechainHeight = b.m_sidechainHeight;
	m_difficulty = b.m_difficulty;
	m_cumulativeDifficulty = b.m_cumulativeDifficulty;
	m_merkleTree = b.m_merkleTree;
	m_merkleProof = b.m_merkleProof;
	memcpy(m_sidechainExtraBuf, b.m_sidechainExtraBuf, sizeof(m_sidechainExtraBuf));
	m_sidechainId = b.m_sidechainId;
	m_depth = b.m_depth;
	m_verified = b.m_verified;
	m_invalid = b.m_invalid;
	m_broadcasted = b.m_broadcasted;
	m_wantBroadcast = b.m_wantBroadcast;
	m_precalculated = b.m_precalculated;

	m_localTimestamp = seconds_since_epoch();
	m_receivedTimestamp = b.m_receivedTimestamp;

	m_auxChains = b.m_auxChains;
	m_auxNonce = b.m_auxNonce;

	return *this;
}

std::vector<uint8_t> PoolBlock::serialize_mainchain_data(size_t* header_size, size_t* miner_tx_size, int* outputs_offset, int* outputs_blob_size, const uint32_t* nonce, const uint32_t* extra_nonce) const
{
	std::vector<uint8_t> data;
	data.reserve(128 + m_outputs.size() * 39 + m_transactions.size() * HASH_SIZE);

	// Header
	data.push_back(m_majorVersion);
	data.push_back(m_minorVersion);
	writeVarint(m_timestamp, data);
	data.insert(data.end(), m_prevId.h, m_prevId.h + HASH_SIZE);

	if (!nonce) {
		nonce = &m_nonce;
	}
	data.insert(data.end(), reinterpret_cast<const uint8_t*>(nonce), reinterpret_cast<const uint8_t*>(nonce) + NONCE_SIZE);

	const size_t header_size0 = data.size();
	if (header_size) {
		*header_size = header_size0;
	}

	// Miner tx
	data.push_back(TX_VERSION);
	writeVarint(m_txinGenHeight + MINER_REWARD_UNLOCK_TIME, data);
	data.push_back(1);
	data.push_back(TXIN_GEN);
	writeVarint(m_txinGenHeight, data);

	const int outputs_offset0 = static_cast<int>(data.size());
	if (outputs_offset) {
		*outputs_offset = outputs_offset0;
	}

	writeVarint(m_outputs.size(), data);

	const uint8_t tx_type = get_tx_type();

	for (const TxOutput& output : m_outputs) {
		writeVarint(output.m_reward, data);
		data.push_back(tx_type);
		data.insert(data.end(), output.m_ephPublicKey.h, output.m_ephPublicKey.h + HASH_SIZE);

		if (tx_type == TXOUT_TO_TAGGED_KEY) {
			data.push_back(static_cast<uint8_t>(output.m_viewTag));
		}
	}

	if (outputs_blob_size) {
		*outputs_blob_size = static_cast<int>(data.size()) - outputs_offset0;
	}

	uint8_t tx_extra[128];
	uint8_t* p = tx_extra;

	*(p++) = TX_EXTRA_TAG_PUBKEY;
	memcpy(p, m_txkeyPub.h, HASH_SIZE);
	p += HASH_SIZE;

	uint64_t extra_nonce_size = m_extraNonceSize;
	if (extra_nonce_size > EXTRA_NONCE_MAX_SIZE) {
		LOGERR(1, "extra nonce size is too large (" << extra_nonce_size << "), fix the code!");
		extra_nonce_size = EXTRA_NONCE_MAX_SIZE;
	}

	*(p++) = TX_EXTRA_NONCE;
	*(p++) = static_cast<uint8_t>(extra_nonce_size);

	if (!extra_nonce) {
		extra_nonce = &m_extraNonce;
	}
	memcpy(p, extra_nonce, EXTRA_NONCE_SIZE);
	p += EXTRA_NONCE_SIZE;
	if (extra_nonce_size > EXTRA_NONCE_SIZE) {
		memset(p, 0, extra_nonce_size - EXTRA_NONCE_SIZE);
		p += extra_nonce_size - EXTRA_NONCE_SIZE;
	}

	*(p++) = TX_EXTRA_MERGE_MINING_TAG;
	*(p++) = static_cast<uint8_t>(m_merkleTreeDataSize + HASH_SIZE);
	writeVarint(m_merkleTreeData, [&p](const uint8_t b) { *(p++) = b; });
	memcpy(p, m_merkleRoot.h, HASH_SIZE);
	p += HASH_SIZE;

	writeVarint(static_cast<size_t>(p - tx_extra), data);
	data.insert(data.end(), tx_extra, p);

	data.push_back(0);

	if (miner_tx_size) {
		*miner_tx_size = data.size() - header_size0;
	}

	writeVarint(m_transactions.size() - 1, data);
	const uint8_t* t = reinterpret_cast<const uint8_t*>(m_transactions.data());
	data.insert(data.end(), t + HASH_SIZE, t + m_transactions.size() * HASH_SIZE);

#if POOL_BLOCK_DEBUG
	if ((nonce == &m_nonce) && (extra_nonce == &m_extraNonce) && !m_mainChainDataDebug.empty() && (data != m_mainChainDataDebug)) {
		LOGERR(1, "serialize_mainchain_data() has a bug, fix it!");
		PANIC_STOP();
	}
#endif

	return data;
}

std::vector<uint8_t> PoolBlock::serialize_sidechain_data() const
{
	std::vector<uint8_t> data;

	data.reserve((m_uncles.size() + 4) * HASH_SIZE + 36);

	const hash& spend = m_minerWallet.spend_public_key();
	const hash& view = m_minerWallet.view_public_key();

	data.insert(data.end(), spend.h, spend.h + HASH_SIZE);
	data.insert(data.end(), view.h, view.h + HASH_SIZE);
	data.insert(data.end(), m_txkeySecSeed.h, m_txkeySecSeed.h + HASH_SIZE);
	data.insert(data.end(), m_parent.h, m_parent.h + HASH_SIZE);

	writeVarint(m_uncles.size(), data);

	for (const hash& id : m_uncles) {
		data.insert(data.end(), id.h, id.h + HASH_SIZE);
	}

	writeVarint(m_sidechainHeight, data);

	writeVarint(m_difficulty.lo, data);
	writeVarint(m_difficulty.hi, data);

	writeVarint(m_cumulativeDifficulty.lo, data);
	writeVarint(m_cumulativeDifficulty.hi, data);

	const uint8_t n = static_cast<uint8_t>(m_merkleProof.size());
	data.push_back(n);

	for (uint8_t i = 0; i < n; ++i) {
		const hash& h = m_merkleProof[i];
		data.insert(data.end(), h.h, h.h + HASH_SIZE);
	}

	const uint8_t* p = reinterpret_cast<const uint8_t*>(m_sidechainExtraBuf);
	data.insert(data.end(), p, p + sizeof(m_sidechainExtraBuf));

#if POOL_BLOCK_DEBUG
	if (!m_sideChainDataDebug.empty() && (data != m_sideChainDataDebug)) {
		LOGERR(1, "serialize_sidechain_data() has a bug, fix it!");
		PANIC_STOP();
	}
#endif

	return data;
}

void PoolBlock::reset_offchain_data()
{
	// Defaults for off-chain variables
	m_depth = 0;

	m_verified = false;
	m_invalid = false;

	m_broadcasted = false;
	m_wantBroadcast = false;

	m_precalculated = false;

	m_localTimestamp = seconds_since_epoch();
	m_receivedTimestamp = 0;

	m_auxChains.clear();
	m_auxChains.shrink_to_fit();

	m_auxNonce = 0;

	m_merkleTree.clear();
	m_merkleTree.shrink_to_fit();
}

bool PoolBlock::get_pow_hash(RandomX_Hasher_Base* hasher, uint64_t height, const hash& seed_hash, hash& pow_hash, bool force_light_mode)
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
		size_t header_size, miner_tx_size;
		const std::vector<uint8_t> mainchain_data = serialize_mainchain_data(&header_size, &miner_tx_size, nullptr, nullptr, nullptr, nullptr);

		if (!header_size || !miner_tx_size || (mainchain_data.size() < header_size + miner_tx_size)) {
			LOGERR(1, "tried to calculate PoW of uninitialized block");
			return false;
		}

		blob_size = header_size;
		memcpy(blob, mainchain_data.data(), blob_size);

		const uint8_t* miner_tx = mainchain_data.data() + header_size;
		hash tmp;
		keccak(miner_tx, static_cast<int>(miner_tx_size) - 1, tmp.h);
		memcpy(hashes, tmp.h, HASH_SIZE);

		count = m_transactions.size();
		uint8_t* h = reinterpret_cast<uint8_t*>(m_transactions.data());

		keccak(reinterpret_cast<uint8_t*>(hashes), HASH_SIZE * 3, tmp.h);
		memcpy(h, tmp.h, HASH_SIZE);

		merkle_hash(m_transactions, tmp);
		memcpy(blob + blob_size, tmp.h, HASH_SIZE);
	}
	blob_size += HASH_SIZE;

	writeVarint(count, [&blob, &blob_size](uint8_t b) { blob[blob_size++] = b; });

	return hasher->calculate(blob, blob_size, height, seed_hash, pow_hash, force_light_mode);
}

uint64_t PoolBlock::get_payout(const Wallet& w) const
{
	const uint8_t tx_type = get_tx_type();

	for (size_t i = 0, n = m_outputs.size(); i < n; ++i) {
		const TxOutput& out = m_outputs[i];
		hash eph_public_key;

		if (tx_type == TXOUT_TO_TAGGED_KEY) {
			uint8_t view_tag;
			const uint8_t expected_view_tag = out.m_viewTag;
			if (w.get_eph_public_key(m_txkeySec, i, eph_public_key, view_tag, &expected_view_tag) && (eph_public_key == out.m_ephPublicKey)) {
				return out.m_reward;
			}
		}
		else {
			uint8_t view_tag;
			if (w.get_eph_public_key(m_txkeySec, i, eph_public_key, view_tag) && (eph_public_key == out.m_ephPublicKey)) {
				return out.m_reward;
			}
		}
	}

	return 0;
}

hash PoolBlock::calculate_tx_key_seed() const
{
	const char domain[] = "tx_key_seed";
	const uint32_t zero = 0;

	const std::vector<uint8_t> mainchain_data = serialize_mainchain_data(nullptr, nullptr, nullptr, nullptr, &zero, &zero);
	const std::vector<uint8_t> sidechain_data = serialize_sidechain_data();

	hash result;
	keccak_custom([&domain, &mainchain_data, &sidechain_data](int offset) -> uint8_t {
		size_t k = offset;

		if (k < sizeof(domain)) return domain[k];
		k -= sizeof(domain);

		if (k < mainchain_data.size()) return mainchain_data[k];
		k -= mainchain_data.size();

		return sidechain_data[k];
	}, static_cast<int>(sizeof(domain) + mainchain_data.size() + sidechain_data.size()), result.h, HASH_SIZE);

	return result;
}

} // namespace p2pool
