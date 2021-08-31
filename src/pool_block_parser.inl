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

#pragma once

namespace p2pool {

// Parse an arbitrary binary blob into the pool block
// Since data here can come from external and possibly malicious sources, check everything
// Only the syntax (i.e. the serialized block binary format) and the keccak hash are checked here
// Semantics must also be checked elsewhere before accepting the block (PoW, reward split between miners, difficulty calculation and so on)
int PoolBlock::deserialize(const uint8_t* data, size_t size, SideChain& sidechain)
{
	try {
		// Sanity check
		if (!data || (size > 128 * 1024)) {
			return __LINE__;
		}

		const uint8_t* const data_begin = data;
		const uint8_t* const data_end = data + size;

		auto read_byte = [&data, data_end](uint8_t& b) -> bool
		{
			if (data < data_end) {
				b = *(data++);
				return true;
			}
			return false;
		};

#define READ_BYTE(x) do { if (!read_byte(x)) return __LINE__; } while (0)
#define EXPECT_BYTE(value) do { uint8_t tmp; READ_BYTE(tmp); if (tmp != (value)) return __LINE__; } while (0)

		auto read_varint = [&data, data_end](auto& b) -> bool
		{
			uint64_t result = 0;
			int k = 0;

			while (data < data_end) {
				if (k >= static_cast<int>(sizeof(b)) * 8) {
					return false;
				}

				const uint64_t cur_byte = *(data++);
				result |= (cur_byte & 0x7F) << k;
				k += 7;

				if ((cur_byte & 0x80) == 0) {
					b = result;
					return true;
				}
			}
			return false;
		};

#define READ_VARINT(x) do { if (!read_varint(x)) return __LINE__; } while(0)

		auto read_buf = [&data, data_end](void* buf, size_t size) -> bool
		{
			if (static_cast<size_t>(data_end - data) < size) {
				return false;
			}

			memcpy(buf, data, size);
			data += size;
			return true;
		};

#define READ_BUF(buf, size) do { if (!read_buf((buf), (size))) return __LINE__; } while(0)

		MutexLock lock(m_lock);

		READ_BYTE(m_majorVersion);
		if (m_majorVersion > HARDFORK_SUPPORTED_VERSION) return __LINE__;

		READ_BYTE(m_minorVersion);
		if (m_minorVersion < m_majorVersion) return __LINE__;

		READ_VARINT(m_timestamp);
		READ_BUF(m_prevId.h, HASH_SIZE);

		const int nonce_offset = static_cast<int>(data - data_begin);
		READ_BUF(&m_nonce, NONCE_SIZE);

		m_mainChainHeaderSize = data - data_begin;

		EXPECT_BYTE(TX_VERSION);

		uint64_t unlock_height;
		READ_VARINT(unlock_height);

		EXPECT_BYTE(1);
		EXPECT_BYTE(TXIN_GEN);

		READ_VARINT(m_txinGenHeight);
		if (unlock_height != m_txinGenHeight + MINER_REWARD_UNLOCK_TIME) return __LINE__;

		std::vector<uint8_t> outputs_blob;
		m_mainChainOutputsOffset = static_cast<int>(data - data_begin);

		uint64_t num_outputs;
		READ_VARINT(num_outputs);

		uint64_t total_reward = 0;

		if (num_outputs > 0) {
			// Outputs are in the buffer, just read them
			// Each output is at least 34 bytes, exit early if there's not enough data left
			// 1 byte for reward, 1 byte for TXOUT_TO_KEY, 32 bytes for eph_pub_key
			constexpr uint64_t MIN_OUTPUT_SIZE = 34;

			if (num_outputs > std::numeric_limits<uint64_t>::max() / MIN_OUTPUT_SIZE) return __LINE__;
			if (static_cast<uint64_t>(data_end - data) < num_outputs * MIN_OUTPUT_SIZE) return __LINE__;

			m_outputs.clear();
			m_outputs.reserve(num_outputs);

			for (uint64_t i = 0; i < num_outputs; ++i) {
				TxOutput t;

				READ_VARINT(t.m_reward);
				total_reward += t.m_reward;

				EXPECT_BYTE(TXOUT_TO_KEY);
				READ_BUF(t.m_ephPublicKey.h, HASH_SIZE);

				m_outputs.emplace_back(std::move(t));
			}

			m_mainChainOutputsBlobSize = static_cast<int>(data - data_begin) - m_mainChainOutputsOffset;
			outputs_blob.assign(data_begin + m_mainChainOutputsOffset, data);
		}
		else {
			// Outputs are not in the buffer and must be calculated from sidechain data
			// We only have total reward and outputs blob size here
			READ_VARINT(total_reward);

			uint64_t tmp;
			READ_VARINT(tmp);

			// Sanity check
			if ((tmp == 0) || (tmp > 128 * 1024)) {
				return __LINE__;
			}

			m_mainChainOutputsBlobSize = static_cast<int>(tmp);
		}

		// Technically some p2pool node could keep stuffing block with transactions until reward is less than 0.6 XMR
		// But default transaction picking algorithm never does that. It's better to just ban such nodes
		if (total_reward < 600000000000ULL) {
			return __LINE__;
		}

		const int outputs_actual_blob_size = static_cast<int>(data - data_begin) - m_mainChainOutputsOffset;

		if (m_mainChainOutputsBlobSize < outputs_actual_blob_size) {
			return __LINE__;
		}

		const int outputs_blob_size_diff = m_mainChainOutputsBlobSize - outputs_actual_blob_size;

		uint64_t tx_extra_size;
		READ_VARINT(tx_extra_size);

		const uint8_t* tx_extra_begin = data;

		EXPECT_BYTE(TX_EXTRA_TAG_PUBKEY);
		READ_BUF(m_txkeyPub.h, HASH_SIZE);

		EXPECT_BYTE(TX_EXTRA_NONCE);
		READ_VARINT(m_extraNonceSize);

		// Sanity check
		if ((m_extraNonceSize < EXTRA_NONCE_SIZE) || (m_extraNonceSize > EXTRA_NONCE_SIZE + 10)) return __LINE__;

		const int extra_nonce_offset = static_cast<int>((data - data_begin) + outputs_blob_size_diff);
		READ_BUF(&m_extraNonce, EXTRA_NONCE_SIZE);
		for (uint64_t i = EXTRA_NONCE_SIZE; i < m_extraNonceSize; ++i) {
			EXPECT_BYTE(0);
		}

		EXPECT_BYTE(TX_EXTRA_MERGE_MINING_TAG);
		EXPECT_BYTE(HASH_SIZE);

		const int sidechain_hash_offset = static_cast<int>((data - data_begin) + outputs_blob_size_diff);
		READ_BUF(m_sidechainId.h, HASH_SIZE);

		if (static_cast<uint64_t>(data - tx_extra_begin) != tx_extra_size) return __LINE__;

		EXPECT_BYTE(0);

		m_mainChainMinerTxSize = (data - data_begin) + outputs_blob_size_diff - m_mainChainHeaderSize;

		uint64_t num_transactions;
		READ_VARINT(num_transactions);

		if (num_transactions > std::numeric_limits<uint64_t>::max() / HASH_SIZE) return __LINE__;
		if (static_cast<uint64_t>(data_end - data) < num_transactions * HASH_SIZE) return __LINE__;

		m_transactions.resize(1);
		m_transactions.reserve(num_transactions + 1);

		for (uint64_t i = 0; i < num_transactions; ++i) {
			hash id;
			READ_BUF(id.h, HASH_SIZE);
			m_transactions.emplace_back(std::move(id));
		}

		m_mainChainData.reserve((data - data_begin) + outputs_blob_size_diff);
		m_mainChainData.assign(data_begin, data_begin + m_mainChainOutputsOffset);
		m_mainChainData.insert(m_mainChainData.end(), m_mainChainOutputsBlobSize, 0);
		m_mainChainData.insert(m_mainChainData.end(), data_begin + m_mainChainOutputsOffset + outputs_actual_blob_size, data);

		const uint8_t* sidechain_data_begin = data;

		hash spend_pub_key;
		hash view_pub_key;
		READ_BUF(spend_pub_key.h, HASH_SIZE);
		READ_BUF(view_pub_key.h, HASH_SIZE);
		if (!m_minerWallet.assign(spend_pub_key, view_pub_key, sidechain.network_type())) {
			return __LINE__;
		}

		READ_BUF(m_txkeySec.h, HASH_SIZE);

		if (!check_keys(m_txkeyPub, m_txkeySec)) {
			return __LINE__;
		}

		READ_BUF(m_parent.h, HASH_SIZE);

		uint64_t num_uncles;
		READ_VARINT(num_uncles);

		if (num_uncles > std::numeric_limits<uint64_t>::max() / HASH_SIZE) return __LINE__;
		if (static_cast<uint64_t>(data_end - data) < num_uncles * HASH_SIZE) return __LINE__;

		m_uncles.clear();
		m_uncles.reserve(num_uncles);

		for (uint64_t i = 0; i < num_uncles; ++i) {
			hash id;
			READ_BUF(id.h, HASH_SIZE);
			m_uncles.emplace_back(std::move(id));
		}

		READ_VARINT(m_sidechainHeight);

		READ_VARINT(m_difficulty.lo);
		READ_VARINT(m_difficulty.hi);

		READ_VARINT(m_cumulativeDifficulty.lo);
		READ_VARINT(m_cumulativeDifficulty.hi);

#undef READ_BYTE
#undef EXPECT_BYTE
#undef READ_VARINT
#undef READ_BUF

		if (data != data_end) {
			return __LINE__;
		}

		if ((num_outputs == 0) && !sidechain.get_outputs_blob(this, total_reward, outputs_blob)) {
			return __LINE__;
		}

		if (static_cast<int>(outputs_blob.size()) != m_mainChainOutputsBlobSize) {
			return __LINE__;
		}

		memcpy(m_mainChainData.data() + m_mainChainOutputsOffset, outputs_blob.data(), m_mainChainOutputsBlobSize);

		hash check;
		const std::vector<uint8_t>& consensus_id = sidechain.consensus_id();
		keccak_custom(
			[this, nonce_offset, extra_nonce_offset, sidechain_hash_offset, data_begin, data_end, &consensus_id, &outputs_blob, outputs_blob_size_diff](int offset) -> uint8_t
			{
				uint32_t k = static_cast<uint32_t>(offset - nonce_offset);
				if (k < NONCE_SIZE) {
					return 0;
				}

				k = static_cast<uint32_t>(offset - extra_nonce_offset);
				if (k < EXTRA_NONCE_SIZE) {
					return 0;
				}

				k = static_cast<uint32_t>(offset - sidechain_hash_offset);
				if (k < HASH_SIZE) {
					return 0;
				}

				const int data_size = static_cast<int>((data_end - data_begin) + outputs_blob_size_diff);
				if (offset < data_size) {
					if (offset < m_mainChainOutputsOffset) {
						return data_begin[offset];
					}
					else if (offset < m_mainChainOutputsOffset + m_mainChainOutputsBlobSize) {
						const int tmp = offset - m_mainChainOutputsOffset;
						return outputs_blob[tmp];
					}
					else {
						return data_begin[offset - outputs_blob_size_diff];
					}
				}
				offset -= data_size;

				return consensus_id[offset];
			},
			static_cast<int>(size + outputs_blob_size_diff + consensus_id.size()), check.h, HASH_SIZE);

		if (check != m_sidechainId) {
			return __LINE__;
		}

		m_sideChainData.assign(sidechain_data_begin, data_end);
	}
	catch (std::exception& e) {
		const char* msg = e.what();
		LOGERR(0, "Exception in PoolBlock::deserialize(): " << (msg ? msg : "unknown exception"));
		return __LINE__;
	}

	// Defaults for off-chain variables
	m_tmpTxExtra.clear();
	m_tmpInts.clear();

	m_depth = 0;

	m_verified = false;
	m_invalid = false;

	m_broadcasted = false;
	m_wantBroadcast = false;

	m_localTimestamp = time(nullptr);

	return 0;
}

} // namespace p2pool
