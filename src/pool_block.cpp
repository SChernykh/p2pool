/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2026 SChernykh <https://github.com/SChernykh>
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

ReadWriteLock* PoolBlock::s_precalculatedSharesLock = nullptr;
uint64_t PoolBlock::s_coinbaseUnlockWindow = 20;

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
	, m_merkleProof{}
	, m_mergeMiningExtra{}
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
	m_ephPublicKeys = b.m_ephPublicKeys;
	m_outputAmounts = b.m_outputAmounts;
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
	m_merkleProof = b.m_merkleProof;
	m_mergeMiningExtra = b.m_mergeMiningExtra;
	memcpy(m_sidechainExtraBuf, b.m_sidechainExtraBuf, sizeof(m_sidechainExtraBuf));
	m_sidechainId = b.m_sidechainId;
	m_depth = b.m_depth;
	m_verified = b.m_verified;
	m_invalid = b.m_invalid;
	m_broadcasted = b.m_broadcasted;
	m_wantBroadcast = b.m_wantBroadcast;
	m_precalculated = b.m_precalculated;
	{
		WriteLock lock(*s_precalculatedSharesLock);
		m_precalculatedShares = b.m_precalculatedShares;
	}

	m_localTimestamp = seconds_since_epoch();
	m_receivedTimestamp = b.m_receivedTimestamp;

	m_auxChains = b.m_auxChains;
	m_auxNonce = b.m_auxNonce;

	m_hashingBlob = b.m_hashingBlob;

	m_powHash = b.m_powHash;
	m_seed = b.m_seed;

	m_cachedNextDifficulty = b.m_cachedNextDifficulty;

	return *this;
}

// ---------------------------------------------------------------------------
//  Kryptokrona (XKR) block serialization helpers
//
//  XKR blocks (major_version >= 2) are a nested ForkNote structure, unlike
//  Monero's flat block. See docs/kryptokrona_block_format.md for the full,
//  byte-validated layout. These file-local helpers are shared by
//  serialize_mainchain_data() (the submit blob) and get_pow_hash() (the PoW
//  input), which must build identical coinbases.
// ---------------------------------------------------------------------------
namespace {

// coinbase.unlock_time = height + this. The authoritative value comes from the
// daemon (get_miner_data), since kryptokrona addresses don't encode a network.
static FORCEINLINE uint64_t xkr_coinbase_unlock_window()
{
	return PoolBlock::s_coinbaseUnlockWindow;
}

// The REAL coinbase (the multi-output PPLNS payout). CryptoNote format:
// version 1, TXOUT_TO_KEY outputs (no view tag), no RingCT byte. The p2pool
// sidechain merkle root is appended to the extra_nonce so it's the last 32
// bytes of `extra` (where handle_chain_main reads it back).
static void xkr_serialize_real_coinbase(const PoolBlock& b, uint32_t extra_nonce, std::vector<uint8_t>& out)
{
	writeVarint(static_cast<uint64_t>(coin::COINBASE_TX_VERSION), out);
	writeVarint(b.m_txinGenHeight + xkr_coinbase_unlock_window(), out);
	out.push_back(1);          // vin count
	out.push_back(TXIN_GEN);   // 0xff
	writeVarint(b.m_txinGenHeight, out);

	writeVarint(b.m_outputAmounts.size(), out);
	for (size_t i = 0, n = b.m_outputAmounts.size(); i < n; ++i) {
		writeVarint(b.m_outputAmounts[i].m_reward, out);
		out.push_back(coin::TXOUT_TO_KEY);     // 0x02, no view tag
		const hash k = b.m_ephPublicKeys[i];
		out.insert(out.end(), k.h, k.h + HASH_SIZE);
	}

	// extra = [PUBKEY, txkeyPub][NONCE, size, extra_nonce(4) ++ sidechain_root(32)]
	std::vector<uint8_t> extra;
	extra.push_back(TX_EXTRA_TAG_PUBKEY);
	extra.insert(extra.end(), b.m_txkeyPub.h, b.m_txkeyPub.h + HASH_SIZE);
	extra.push_back(TX_EXTRA_NONCE);
	writeVarint(static_cast<uint64_t>(EXTRA_NONCE_SIZE + HASH_SIZE), extra);
	extra.insert(extra.end(), reinterpret_cast<const uint8_t*>(&extra_nonce), reinterpret_cast<const uint8_t*>(&extra_nonce) + EXTRA_NONCE_SIZE);
	extra.insert(extra.end(), b.m_merkleRoot.h, b.m_merkleRoot.h + HASH_SIZE);

	writeVarint(extra.size(), out);
	out.insert(out.end(), extra.begin(), extra.end());
	// No RingCT type byte (CryptoNote coinbase ends here).
}

// aux hash = keccak(getBlockHashingBinaryArray) — must equal the parent
// coinbase merge-mining tag merkleRoot (checkProofOfWorkV2).
static hash xkr_aux_header_hash(const PoolBlock& b, const std::vector<uint8_t>& real_coinbase)
{
	hash coinbase_hash;
	keccak(real_coinbase.data(), static_cast<int>(real_coinbase.size()), coinbase_hash.h);

	std::vector<hash> tx_hashes;
	tx_hashes.reserve(b.m_transactions.size());
	tx_hashes.push_back(coinbase_hash);
	for (size_t i = 1, n = b.m_transactions.size(); i < n; ++i) {
		tx_hashes.emplace_back(b.m_transactions[i]);
	}

	root_hash tree_hash;
	merkle_hash(tx_hashes, tree_hash);

	std::vector<uint8_t> bha;
	writeVarint(static_cast<uint64_t>(b.m_majorVersion), bha);
	writeVarint(static_cast<uint64_t>(b.m_minorVersion), bha);
	bha.insert(bha.end(), b.m_prevId.h, b.m_prevId.h + HASH_SIZE);
	bha.insert(bha.end(), tree_hash.h, tree_hash.h + HASH_SIZE);
	writeVarint(static_cast<uint64_t>(b.m_transactions.size()), bha); // transactionHashes.size() + 1

	// The daemon's getAuxiliaryBlockHeaderHash is getObjectHash(blockHashingArray),
	// i.e. cn_fast_hash of the array serialized as an object = keccak of
	// varint(length) ++ array (NOT keccak of the array directly).
	std::vector<uint8_t> obj;
	writeVarint(bha.size(), obj);
	obj.insert(obj.end(), bha.begin(), bha.end());

	hash aux;
	keccak(obj.data(), static_cast<int>(obj.size()), aux.h);
	return aux;
}

// The (self-referential) parent coinbase: version/unlock/vin/vout all 0, extra
// holds only the merge-mining tag [0x03, size=33, depth=0, aux_hash(32)].
static void xkr_serialize_parent_coinbase(const hash& aux_hash, std::vector<uint8_t>& out)
{
	out.push_back(0); // version
	out.push_back(0); // unlock_time
	out.push_back(0); // vin count
	out.push_back(0); // vout count

	std::vector<uint8_t> mm;
	writeVarint(static_cast<uint64_t>(coin::PARENT_MM_TAG_DEPTH), mm);
	mm.insert(mm.end(), aux_hash.h, aux_hash.h + HASH_SIZE);

	std::vector<uint8_t> extra;
	extra.push_back(TX_EXTRA_MERGE_MINING_TAG); // 0x03
	writeVarint(mm.size(), extra);              // 33
	extra.insert(extra.end(), mm.begin(), mm.end());

	writeVarint(extra.size(), out);             // 35
	out.insert(out.end(), extra.begin(), extra.end());
}

// The parent-block hashing blob fed to CryptoNight-Turtle for the PoW hash.
static void xkr_serialize_pow_blob(const PoolBlock& b, uint32_t nonce, const hash& parent_coinbase_hash, std::vector<uint8_t>& out)
{
	writeVarint(static_cast<uint64_t>(0), out); // parent major (0, see format doc)
	writeVarint(static_cast<uint64_t>(0), out); // parent minor
	writeVarint(b.m_timestamp, out);
	out.insert(out.end(), HASH_SIZE, 0);        // parent prev hash (zero)
	out.insert(out.end(), reinterpret_cast<const uint8_t*>(&nonce), reinterpret_cast<const uint8_t*>(&nonce) + NONCE_SIZE);
	out.insert(out.end(), parent_coinbase_hash.h, parent_coinbase_hash.h + HASH_SIZE); // merkleRoot
	writeVarint(static_cast<uint64_t>(1), out); // numberOfTransactions (parent has 1)
}

} // namespace

std::vector<uint8_t> PoolBlock::serialize_mainchain_data(int* nonce_offset, int* aux_hash_offset, int* extra_nonce_offset, int* mm_root_offset, const uint32_t* nonce, const uint32_t* extra_nonce) const
{
	if (m_transactions.empty()) {
		LOGERR(1, "Trying to serialize an uninitialized block, fix the code!");
		return {};
	}

	const uint32_t nonce_val = nonce ? *nonce : m_nonce;
	const uint32_t extra_nonce_val = extra_nonce ? *extra_nonce : m_extraNonce;

	// Build the real (PPLNS) coinbase, then the aux hash and the parent
	// coinbase that commits to it.
	std::vector<uint8_t> real_coinbase;
	xkr_serialize_real_coinbase(*this, extra_nonce_val, real_coinbase);

	const hash aux_hash = xkr_aux_header_hash(*this, real_coinbase);

	std::vector<uint8_t> parent_coinbase;
	xkr_serialize_parent_coinbase(aux_hash, parent_coinbase);

	std::vector<uint8_t> data;
	data.reserve(std::min<size_t>(128 + m_outputAmounts.size() * 38 + m_transactions.size() * HASH_SIZE, 131072));

	// Outer block header (v>=2): major, minor, prevHash only.
	writeVarint(static_cast<uint64_t>(m_majorVersion), data);
	writeVarint(static_cast<uint64_t>(m_minorVersion), data);
	data.insert(data.end(), m_prevId.h, m_prevId.h + HASH_SIZE);

	// Parent block header.
	writeVarint(static_cast<uint64_t>(0), data); // parent major (0)
	writeVarint(static_cast<uint64_t>(0), data); // parent minor
	writeVarint(m_timestamp, data);
	data.insert(data.end(), HASH_SIZE, 0);       // parent prev hash (zero)
	const int nonce_off = static_cast<int>(data.size());
	data.insert(data.end(), reinterpret_cast<const uint8_t*>(&nonce_val), reinterpret_cast<const uint8_t*>(&nonce_val) + NONCE_SIZE);
	writeVarint(static_cast<uint64_t>(1), data); // parent txCount
	// baseTransactionBranch: tree_depth(1) == 0 -> nothing

	// Parent coinbase ends with the 32-byte aux hash.
	const int parent_cb_off = static_cast<int>(data.size());
	data.insert(data.end(), parent_coinbase.begin(), parent_coinbase.end());
	const int aux_hash_off = parent_cb_off + static_cast<int>(parent_coinbase.size()) - static_cast<int>(HASH_SIZE);
	// blockchainBranch: depth 0 -> nothing

	// Real coinbase extra ends with [extra_nonce(4)][sidechain_root(32)].
	const int real_cb_off = static_cast<int>(data.size());
	data.insert(data.end(), real_coinbase.begin(), real_coinbase.end());
	const int mm_root_off = real_cb_off + static_cast<int>(real_coinbase.size()) - static_cast<int>(HASH_SIZE);
	const int extra_nonce_off = mm_root_off - static_cast<int>(EXTRA_NONCE_SIZE);

	// Non-coinbase transaction hashes.
	writeVarint(m_transactions.size() - 1, data);
	for (size_t i = 1, n = m_transactions.size(); i < n; ++i) {
		const hash h = m_transactions[i];
		data.insert(data.end(), h.h, h.h + HASH_SIZE);
	}

	if (nonce_offset) { *nonce_offset = nonce_off; }
	if (aux_hash_offset) { *aux_hash_offset = aux_hash_off; }
	if (extra_nonce_offset) { *extra_nonce_offset = extra_nonce_off; }
	if (mm_root_offset) { *mm_root_offset = mm_root_off; }

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

	writeVarint(m_mergeMiningExtra.size(), data);

	for (const auto& mm_extra_data : m_mergeMiningExtra) {
		data.insert(data.end(), mm_extra_data.first.h, mm_extra_data.first.h + HASH_SIZE);

		writeVarint(mm_extra_data.second.size(), data);
		data.insert(data.end(), mm_extra_data.second.begin(), mm_extra_data.second.end());
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
	{
		WriteLock lock(*s_precalculatedSharesLock);
		m_precalculatedShares.clear();
		m_precalculatedShares.shrink_to_fit();
	}

	m_localTimestamp = seconds_since_epoch();
	m_receivedTimestamp = 0;

	m_auxChains.clear();
	m_auxChains.shrink_to_fit();

	m_auxNonce = 0;

	m_hashingBlob.clear();
	m_hashingBlob.shrink_to_fit();

	m_powHash = {};
	m_seed = {};

	m_cachedNextDifficulty = {};
}

bool PoolBlock::get_pow_hash(RandomX_Hasher_Base* hasher, uint64_t height, const hash& seed_hash, hash& pow_hash, bool force_light_mode, size_t lane)
{
	if (m_transactions.empty()) {
		LOGERR(1, "Trying to calculate PoW hash of an uninitialized block, fix the code!");
		return false;
	}

	// Kryptokrona (XKR) PoW: CryptoNight-Turtle over the parent-block hashing
	// blob. build_pow_blob() also records the real coinbase hash at
	// m_transactions[0]. See docs/kryptokrona_block_format.md.
	uint8_t blob[HASHING_BLOB_MAX_SIZE];
	size_t nonce_offset;
	const size_t blob_size = build_pow_blob(m_extraNonce, m_nonce, blob, nonce_offset);

	// cppcheck-suppress danglingLifetime
	m_hashingBlob.assign(blob, blob + blob_size);

	return hasher->calculate(blob, blob_size, height, seed_hash, pow_hash, force_light_mode, lane);
}

size_t PoolBlock::build_pow_blob(uint32_t extra_nonce, uint32_t nonce, uint8_t* blob, size_t& nonce_offset) const
{
	std::vector<uint8_t> real_coinbase;
	xkr_serialize_real_coinbase(*this, extra_nonce, real_coinbase);

	// Record the real coinbase hash at index 0 of m_transactions (used elsewhere).
	hash coinbase_hash;
	keccak(real_coinbase.data(), static_cast<int>(real_coinbase.size()), coinbase_hash.h);
	const_cast<PoolBlock*>(this)->m_transactions[0] = static_cast<indexed_hash>(coinbase_hash);

	const hash aux_hash = xkr_aux_header_hash(*this, real_coinbase);

	std::vector<uint8_t> parent_coinbase;
	xkr_serialize_parent_coinbase(aux_hash, parent_coinbase);

	hash parent_coinbase_hash;
	keccak(parent_coinbase.data(), static_cast<int>(parent_coinbase.size()), parent_coinbase_hash.h);

	std::vector<uint8_t> pow_blob;
	xkr_serialize_pow_blob(*this, nonce, parent_coinbase_hash, pow_blob);

	// nonce sits after: pb.major(1) + pb.minor(1) + varint(timestamp) + pb.prev(32)
	size_t timestamp_len = 1;
	for (uint64_t t = m_timestamp; t >= 0x80; t >>= 7) { ++timestamp_len; }
	nonce_offset = 2 + timestamp_len + HASH_SIZE;

	memcpy(blob, pow_blob.data(), pow_blob.size());
	return pow_blob.size();
}

uint64_t PoolBlock::get_payout(const Wallet& w) const
{
	for (size_t i = 0, n = m_outputAmounts.size(); i < n; ++i) {
		const TxOutput& out = m_outputAmounts[i];

		hash eph_public_key;

		uint8_t view_tag;
		const uint8_t expected_view_tag = out.m_viewTag;
		if (w.get_eph_public_key(m_txkeySec, i, eph_public_key, view_tag, &expected_view_tag) && (m_ephPublicKeys[i] == eph_public_key)) {
			return out.m_reward;
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
