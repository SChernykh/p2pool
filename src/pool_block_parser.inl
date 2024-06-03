/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2024 SChernykh <https://github.com/SChernykh>
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
int PoolBlock::deserialize(const uint8_t* data, size_t size, const SideChain& sidechain, uv_loop_t* loop, bool compact)
{
	try {
		// Sanity check
		if (!data || (size > MAX_BLOCK_SIZE)) {
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

#define READ_VARINT(x) do { data = readVarint(data, data_end, x); if (!data) return __LINE__; } while(0)

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

		if (!merge_mining_enabled()) {
			READ_BYTE(m_majorVersion);
			READ_BYTE(m_minorVersion);
		}
		else {
			READ_VARINT(m_majorVersion);
			READ_VARINT(m_minorVersion);
		}

		if (m_majorVersion > HARDFORK_SUPPORTED_VERSION) return __LINE__;
		if (m_minorVersion < m_majorVersion) return __LINE__;

		READ_VARINT(m_timestamp);
		READ_BUF(m_prevId.h, HASH_SIZE);

		const int nonce_offset = static_cast<int>(data - data_begin);
		READ_BUF(&m_nonce, NONCE_SIZE);

		EXPECT_BYTE(TX_VERSION);

		uint64_t unlock_height;
		READ_VARINT(unlock_height);

		EXPECT_BYTE(1);
		EXPECT_BYTE(TXIN_GEN);

		READ_VARINT(m_txinGenHeight);
		if (m_majorVersion != sidechain.network_major_version(m_txinGenHeight)) return __LINE__;
		if (unlock_height != m_txinGenHeight + MINER_REWARD_UNLOCK_TIME) return __LINE__;

		std::vector<uint8_t> outputs_blob;
		const int outputs_offset = static_cast<int>(data - data_begin);

		uint64_t num_outputs;
		READ_VARINT(num_outputs);

		uint64_t total_reward = 0;
		int outputs_blob_size;

		if (num_outputs > 0) {
			// Outputs are in the buffer, just read them
			// Each output is at least 34 bytes, exit early if there's not enough data left
			// 1 byte for reward, 1 byte for tx_type, 32 bytes for eph_pub_key
			constexpr uint64_t MIN_OUTPUT_SIZE = 34;

			if (num_outputs > std::numeric_limits<uint64_t>::max() / MIN_OUTPUT_SIZE) return __LINE__;
			if (static_cast<uint64_t>(data_end - data) < num_outputs * MIN_OUTPUT_SIZE) return __LINE__;

			m_outputs.resize(num_outputs);
			m_outputs.shrink_to_fit();

			const uint8_t expected_tx_type = get_tx_type();

			for (uint64_t i = 0; i < num_outputs; ++i) {
				TxOutput& t = m_outputs[i];

				uint64_t reward;
				READ_VARINT(reward);
				t.m_reward = reward;
				total_reward += reward;

				EXPECT_BYTE(expected_tx_type);

				READ_BUF(t.m_ephPublicKey.h, HASH_SIZE);

				if (expected_tx_type == TXOUT_TO_TAGGED_KEY) {
					uint8_t view_tag;
					READ_BYTE(view_tag);
					t.m_viewTag = view_tag;
				}
			}

			outputs_blob_size = static_cast<int>(data - data_begin) - outputs_offset;
			outputs_blob.assign(data_begin + outputs_offset, data);

			m_sidechainId.clear();
		}
		else {
			// Outputs are not in the buffer and must be calculated from sidechain data
			// We only have total reward and outputs blob size here
			READ_VARINT(total_reward);

			uint64_t tmp;
			READ_VARINT(tmp);

			// Sanity check
			if ((tmp == 0) || (tmp > MAX_BLOCK_SIZE)) {
				return __LINE__;
			}

			outputs_blob_size = static_cast<int>(tmp);

			// Required by sidechain.get_outputs_blob() to speed up repeated broadcasts from different peers
			if (merge_mining_enabled()) {
				READ_BUF(m_sidechainId.h, HASH_SIZE);
			}
		}

		// Technically some p2pool node could keep stuffing block with transactions until reward is less than 0.6 XMR
		// But default transaction picking algorithm never does that. It's better to just ban such nodes
		if (total_reward < BASE_BLOCK_REWARD) {
			return __LINE__;
		}

		const int outputs_actual_blob_size = static_cast<int>(data - data_begin) - outputs_offset;
		if (outputs_blob_size < outputs_actual_blob_size) {
			return __LINE__;
		}

		const int outputs_blob_size_diff = outputs_blob_size - outputs_actual_blob_size;

		uint64_t tx_extra_size;
		READ_VARINT(tx_extra_size);

		const uint8_t* tx_extra_begin = data;

		EXPECT_BYTE(TX_EXTRA_TAG_PUBKEY);
		READ_BUF(m_txkeyPub.h, HASH_SIZE);

		EXPECT_BYTE(TX_EXTRA_NONCE);
		READ_VARINT(m_extraNonceSize);

		// Sanity check
		if ((m_extraNonceSize < EXTRA_NONCE_SIZE) || (m_extraNonceSize > EXTRA_NONCE_MAX_SIZE)) return __LINE__;

		const int extra_nonce_offset = static_cast<int>((data - data_begin) + outputs_blob_size_diff);
		READ_BUF(&m_extraNonce, EXTRA_NONCE_SIZE);
		for (uint64_t i = EXTRA_NONCE_SIZE; i < m_extraNonceSize; ++i) {
			EXPECT_BYTE(0);
		}

		EXPECT_BYTE(TX_EXTRA_MERGE_MINING_TAG);

		int mm_root_hash_offset;
		uint32_t mm_n_aux_chains, mm_nonce;

		if (!merge_mining_enabled()) {
			EXPECT_BYTE(HASH_SIZE);

			mm_root_hash_offset = static_cast<int>((data - data_begin) + outputs_blob_size_diff);
			READ_BUF(m_sidechainId.h, HASH_SIZE);

			mm_n_aux_chains = 1;
			mm_nonce = 0;

			m_merkleRoot = static_cast<root_hash&>(m_sidechainId);
			m_merkleTreeDataSize = 0;
		}
		else {
			uint64_t mm_field_size;
			READ_VARINT(mm_field_size);

			const uint8_t* const mm_field_begin = data;

			READ_VARINT(m_merkleTreeData);

			m_merkleTreeDataSize = static_cast<uint32_t>(data - mm_field_begin);

			decode_merkle_tree_data(mm_n_aux_chains, mm_nonce);

			mm_root_hash_offset = static_cast<int>((data - data_begin) + outputs_blob_size_diff);
			READ_BUF(m_merkleRoot.h, HASH_SIZE);

			if (static_cast<uint64_t>(data - mm_field_begin) != mm_field_size) {
				return __LINE__;
			}
		}

		if (static_cast<uint64_t>(data - tx_extra_begin) != tx_extra_size) return __LINE__;

		EXPECT_BYTE(0);

		uint64_t num_transactions;
		READ_VARINT(num_transactions);

		const int transactions_offset = static_cast<int>(data - data_begin);

		std::vector<uint64_t> parent_indices;
		if (compact) {
			if (static_cast<uint64_t>(data_end - data) < num_transactions) return __LINE__;

			m_transactions.resize(1);
			parent_indices.resize(1);

			// limit reserved memory size because we can't check "num_transactions" properly here
			const uint64_t k = std::min<uint64_t>(num_transactions + 1, 256);
			m_transactions.reserve(k);
			parent_indices.reserve(k);

			for (uint64_t i = 0; i < num_transactions; ++i) {
				uint64_t parent_index;
				READ_VARINT(parent_index);

				hash id;
				if (parent_index == 0) {
					READ_BUF(id.h, HASH_SIZE);
				}

				m_transactions.emplace_back(id);
				parent_indices.emplace_back(parent_index);
			}
		}
		else {
			if (num_transactions > std::numeric_limits<uint64_t>::max() / HASH_SIZE) return __LINE__;
			if (static_cast<uint64_t>(data_end - data) < num_transactions * HASH_SIZE) return __LINE__;

			m_transactions.resize(1);
			m_transactions.reserve(num_transactions + 1);

			for (uint64_t i = 0; i < num_transactions; ++i) {
				hash id;
				READ_BUF(id.h, HASH_SIZE);
				m_transactions.emplace_back(id);
			}
		}

		const int transactions_actual_blob_size = static_cast<int>(data - data_begin) - transactions_offset;
		const int transactions_blob_size = static_cast<int>(num_transactions) * HASH_SIZE;
		const int transactions_blob_size_diff = transactions_blob_size - transactions_actual_blob_size;

		m_transactions.shrink_to_fit();

#if POOL_BLOCK_DEBUG
		m_mainChainDataDebug.reserve((data - data_begin) + outputs_blob_size_diff + transactions_blob_size_diff);
		m_mainChainDataDebug.assign(data_begin, data_begin + outputs_offset);
		m_mainChainDataDebug.insert(m_mainChainDataDebug.end(), outputs_blob_size, 0);
		m_mainChainDataDebug.insert(m_mainChainDataDebug.end(), data_begin + outputs_offset + outputs_actual_blob_size, data_begin + transactions_offset);
		m_mainChainDataDebug.insert(m_mainChainDataDebug.end(), transactions_blob_size, 0);
		m_mainChainDataDebug.insert(m_mainChainDataDebug.end(), data_begin + transactions_offset + transactions_actual_blob_size, data);

		const uint8_t* sidechain_data_begin = data;
#endif

		hash spend_pub_key;
		hash view_pub_key;
		READ_BUF(spend_pub_key.h, HASH_SIZE);
		READ_BUF(view_pub_key.h, HASH_SIZE);
		if (!m_minerWallet.assign(spend_pub_key, view_pub_key, sidechain.network_type())) {
			return __LINE__;
		}

		READ_BUF(m_txkeySecSeed.h, HASH_SIZE);

		hash pub;
		get_tx_keys(pub, m_txkeySec, m_txkeySecSeed, m_prevId);
		if (pub != m_txkeyPub) {
			return __LINE__;
		}

		if (!check_keys(m_txkeyPub, m_txkeySec)) {
			return __LINE__;
		}

		READ_BUF(m_parent.h, HASH_SIZE);

		if (compact) {
			const PoolBlock* parent = sidechain.find_block(m_parent);
			if (!parent) {
				return __LINE__;
			}

			for (uint64_t i = 1, n = m_transactions.size(); i < n; ++i) {
				const uint64_t parent_index = parent_indices[i];
				if (parent_index) {
					if (parent_index >= parent->m_transactions.size()) {
						return __LINE__;
					}
					m_transactions[i] = parent->m_transactions[parent_index];
				}
			}
		}

		uint64_t num_uncles;
		READ_VARINT(num_uncles);

		if (num_uncles > std::numeric_limits<uint64_t>::max() / HASH_SIZE) return __LINE__;
		if (static_cast<uint64_t>(data_end - data) < num_uncles * HASH_SIZE) return __LINE__;

		m_uncles.clear();
		m_uncles.reserve(num_uncles);

		for (uint64_t i = 0; i < num_uncles; ++i) {
			hash id;
			READ_BUF(id.h, HASH_SIZE);
			m_uncles.emplace_back(id);
		}

		READ_VARINT(m_sidechainHeight);

		if (m_sidechainHeight > MAX_SIDECHAIN_HEIGHT) {
			return __LINE__;
		}

		READ_VARINT(m_difficulty.lo);
		READ_VARINT(m_difficulty.hi);

		READ_VARINT(m_cumulativeDifficulty.lo);
		READ_VARINT(m_cumulativeDifficulty.hi);

		if (m_cumulativeDifficulty > MAX_CUMULATIVE_DIFFICULTY) {
			return __LINE__;
		}

		m_merkleProof.clear();

		if (merge_mining_enabled()) {
			uint8_t merkle_proof_size;
			READ_BYTE(merkle_proof_size);

			if (merkle_proof_size > 8) {
				return __LINE__;
			}

			m_merkleProof.reserve(merkle_proof_size);

			for (uint8_t i = 0; i < merkle_proof_size; ++i) {
				hash h;
				READ_BUF(h.h, HASH_SIZE);
				m_merkleProof.emplace_back(h);
			}
		}

		READ_BUF(m_sidechainExtraBuf, sizeof(m_sidechainExtraBuf));

#undef READ_BYTE
#undef EXPECT_BYTE
#undef READ_VARINT
#undef READ_BUF

		if (data != data_end) {
			return __LINE__;
		}

		if ((num_outputs == 0) && !sidechain.get_outputs_blob(this, total_reward, outputs_blob, loop)) {
			return __LINE__;
		}

		if (static_cast<int>(outputs_blob.size()) != outputs_blob_size) {
			return __LINE__;
		}

		const uint8_t* transactions_blob = reinterpret_cast<uint8_t*>(m_transactions.data() + 1);

#if POOL_BLOCK_DEBUG
		memcpy(m_mainChainDataDebug.data() + outputs_offset, outputs_blob.data(), outputs_blob_size);
		memcpy(m_mainChainDataDebug.data() + transactions_offset + outputs_blob_size_diff, transactions_blob, transactions_blob_size);
#endif

		hash check;
		const std::vector<uint8_t>& consensus_id = sidechain.consensus_id();
		const int data_size = static_cast<int>((data_end - data_begin) + outputs_blob_size_diff + transactions_blob_size_diff);

		if (data_size > static_cast<int>(MAX_BLOCK_SIZE)) {
			return __LINE__;
		}

		keccak_custom(
			[nonce_offset, extra_nonce_offset, mm_root_hash_offset, data_begin, data_size, &consensus_id, &outputs_blob, outputs_blob_size_diff, outputs_offset, outputs_blob_size, transactions_blob, transactions_blob_size_diff, transactions_offset, transactions_blob_size](int offset) -> uint8_t
			{
				uint32_t k = static_cast<uint32_t>(offset - nonce_offset);
				if (k < NONCE_SIZE) {
					return 0;
				}

				k = static_cast<uint32_t>(offset - extra_nonce_offset);
				if (k < EXTRA_NONCE_SIZE) {
					return 0;
				}

				k = static_cast<uint32_t>(offset - mm_root_hash_offset);
				if (k < HASH_SIZE) {
					return 0;
				}

				if (offset < data_size) {
					if (offset < outputs_offset) {
						return data_begin[offset];
					}
					else if (offset < outputs_offset + outputs_blob_size) {
						return outputs_blob[offset - outputs_offset];
					}
					else if (offset < transactions_offset + outputs_blob_size_diff) {
						return data_begin[offset - outputs_blob_size_diff];
					}
					else if (offset < transactions_offset + outputs_blob_size_diff + transactions_blob_size) {
						return transactions_blob[offset - (transactions_offset + outputs_blob_size_diff)];
					}
					return data_begin[offset - outputs_blob_size_diff - transactions_blob_size_diff];
				}

				return consensus_id[offset - data_size];
			},
			static_cast<int>(size + outputs_blob_size_diff + transactions_blob_size_diff + consensus_id.size()), check.h, HASH_SIZE);

		if (m_sidechainId.empty()) {
			m_sidechainId = check;
		}
		else if (m_sidechainId != check) {
			return __LINE__;
		}

#if POOL_BLOCK_DEBUG
		m_sideChainDataDebug.assign(sidechain_data_begin, data_end);
#endif

		const uint32_t mm_aux_slot = get_aux_slot(sidechain.consensus_hash(), mm_nonce, mm_n_aux_chains);

		if (!verify_merkle_proof(check, m_merkleProof, mm_aux_slot, mm_n_aux_chains, m_merkleRoot)) {
			return __LINE__;
		}
	}
	catch (std::exception& e) {
		LOGERR(0, "Exception in PoolBlock::deserialize(): " << e.what());
		return __LINE__;
	}

	reset_offchain_data();
	return 0;
}

} // namespace p2pool
