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

#include "common.h"
#include "crypto.h"
#include "block_template.h"
#include "mempool.h"
#include "pool_block.h"
#include "pow_hash.h"
#include "side_chain.h"
#include "p2p_server.h"
#include "keccak.h"
#include "params.h"
#include "gtest/gtest.h"
#include <fstream>
#include <numeric>

namespace p2pool {

static hash H(const char* s)
{
	hash result;
	from_hex(s, strlen(s), result);
	return result;
};

TEST(pool_block, deserialize)
{
	init_crypto_cache();
	{
	PoolBlock b;
	SideChain sidechain(nullptr, NetworkType::Mainnet, "default");

	constexpr uint64_t expected_consensus_id[HASH_SIZE / sizeof(uint64_t)] = {
		0x92680bb5e77eaf22ull,
		0x27446c2c6bda99e3ull,
		0x008e04a9d40451b2ull,
		0x18f90744f09d6eb1ull
	};

	const std::vector<uint8_t>& consensus_id = sidechain.consensus_id();
	ASSERT_EQ(consensus_id.size(), HASH_SIZE);
	ASSERT_EQ(memcmp(consensus_id.data(), expected_consensus_id, HASH_SIZE), 0);

	std::ifstream f("block.dat", std::ios::binary | std::ios::ate);
	ASSERT_EQ(f.good() && f.is_open(), true);

	std::vector<uint8_t> buf(f.tellg());
	f.seekg(0);
	f.read(reinterpret_cast<char*>(buf.data()), buf.size());
	ASSERT_EQ(f.good(), true);

	ASSERT_EQ(b.deserialize(buf.data(), buf.size(), sidechain, false, false), 0);

	{
		const PoolBlock::full_id id = b.get_full_id();

		ASSERT_EQ(memcmp(id.data(), b.m_sidechainId.h, HASH_SIZE), 0);
		ASSERT_EQ(memcmp(id.data() + HASH_SIZE, &b.m_nonce, NONCE_SIZE), 0);
		ASSERT_EQ(memcmp(id.data() + HASH_SIZE + NONCE_SIZE, &b.m_extraNonce, EXTRA_NONCE_SIZE), 0);
	}

	ASSERT_EQ(b.get_payout(Wallet("4B4aCvEcZr6GcusVJfEds2LXixCeJ2dQBaDUCguWmzi5L7PW5tVXfAnE4cn1mQdiNzH6zWcEPMQTiYTsNcX44ryxCJWZKZH")), 17411468548U);
	ASSERT_EQ(b.get_payout(Wallet("43VbH7CQCJqhH1d327TBenCs9hFN3zvcgX5YZdGyJfEE5rabasAtKhyPsKmbYSU9AmMReACZrz9j5U2Ba6WXWoQpVi38AJn")), 1404738424U);
	ASSERT_EQ(b.get_payout(Wallet("46r3PD45TYH9jVf8sEejW9JdK1EgNe6BeYLdGyJTU1MRctoevAHXpzSjBMJhdkLirGXwiWdZejSRZ8MZP72artSD17LprKY")), 1419699645U);
	ASSERT_EQ(b.get_payout(Wallet("44MnN1f3Eto8DZYUWuE5XZNUtE3vcRzt2j6PzqWpPau34e6Cf4fAxt6X2MBmrm6F9YMEiMNjN6W4Shn4pLcfNAja621jwyg")), 0U);

	size_t header_size, miner_tx_size;
	int outputs_offset, outputs_blob_size;
	const std::vector<uint8_t> mainchain_data = b.serialize_mainchain_data(&header_size, &miner_tx_size, &outputs_offset, &outputs_blob_size);
	const std::vector<uint8_t> sidechain_data = b.serialize_sidechain_data();

	ASSERT_EQ(mainchain_data.size(), 1829U);
	ASSERT_EQ(header_size, 43U);
	ASSERT_EQ(miner_tx_size, 1145U);
	ASSERT_EQ(outputs_offset, 54);
	ASSERT_EQ(outputs_blob_size, 1058);

	ASSERT_EQ(b.m_majorVersion, 16U);
	ASSERT_EQ(b.m_minorVersion, 16U);
	ASSERT_EQ(b.m_timestamp, 1728813765U);
	ASSERT_EQ(b.m_nonce, 352454720U);
	ASSERT_EQ(b.m_txinGenHeight, 3258099U);
	ASSERT_EQ(b.m_ephPublicKeys.size(), 27U);
	ASSERT_EQ(b.m_outputAmounts.size(), 27U);
	ASSERT_EQ(b.m_extraNonceSize, 4U);
	ASSERT_EQ(b.m_extraNonce, 2983923783U);
	ASSERT_EQ(b.m_transactions.size(), 20U);
	ASSERT_EQ(b.m_uncles.size(), 0U);
	ASSERT_EQ(b.m_sidechainHeight, 9443384U);
	ASSERT_EQ(b.m_difficulty.lo, 1828732004U);
	ASSERT_EQ(b.m_difficulty.hi, 0U);
	ASSERT_EQ(b.m_cumulativeDifficulty.lo, 15051095864465561ull);
	ASSERT_EQ(b.m_cumulativeDifficulty.hi, 0U);
	ASSERT_EQ(b.m_depth, 0U);
	ASSERT_EQ(b.m_verified, false);
	ASSERT_EQ(b.m_invalid, false);
	ASSERT_EQ(b.m_broadcasted, false);
	ASSERT_EQ(b.m_wantBroadcast, false);

	const hash seed = H("bf513dbe52c22b09e65edae222ec902d6adb75585a0141b81a165f0fb0c9c0bc");

	RandomX_Hasher hasher(nullptr);
	hasher.set_seed(seed);

	hash pow_hash;
	ASSERT_EQ(b.get_pow_hash(&hasher, 0, seed, pow_hash, false, RandomX_Hasher_Base::VM_LANE_P2P), true);

	std::stringstream s;
	s << pow_hash;
	ASSERT_EQ(s.str(), "0906c001cc0900098fe1b62593f8ba52bd1ae2a0806096aa361a9f1702000000");

	ASSERT_EQ(b.m_difficulty.check_pow(pow_hash), true);

	// Test self-assignment
	b = b;

	ASSERT_EQ(b.serialize_mainchain_data(), mainchain_data);
	ASSERT_EQ(b.serialize_sidechain_data(), sidechain_data);
	}
	destroy_crypto_cache();

#ifdef WITH_INDEXED_HASHES
	indexed_hash::cleanup_storage();
#endif
}

namespace {

std::vector<uint8_t> carrot_block_blob(const PoolBlock& b, const PoolBlock* parent, bool pruned, bool compact, bool all_inline = false)
{
	int outputs_offset, outputs_size;

	const auto main = b.serialize_mainchain_data(nullptr, nullptr, &outputs_offset, &outputs_size);
	const auto side = b.serialize_sidechain_data();

	const uint8_t* const end = main.data() + main.size();

	uint64_t extra_size;
	const uint8_t* pubkeys = readVarint(main.data() + outputs_offset + outputs_size, end, extra_size);

	const size_t num_outputs = b.m_carrotOutputs.size();
	size_t pubkeys_size = 1 + num_outputs * HASH_SIZE;

	if (num_outputs > 1) writeVarint(num_outputs, [&pubkeys_size](uint8_t) { ++pubkeys_size; });

	const size_t transactions_offset = main.size() - (1 + HASH_SIZE) - b.m_transactions.size() * HASH_SIZE;

	std::vector<uint8_t> blob;

	if (pruned) {
		blob.assign(main.begin(), main.begin() + outputs_offset);
		blob.push_back(0);

		const uint64_t reward = std::accumulate(b.m_carrotOutputs.begin(), b.m_carrotOutputs.end(), 0ULL, [](uint64_t sum, const auto& output) { return sum + output.amount; });

		writeVarint(reward, blob);
		writeVarint(outputs_size, blob);

		blob.insert(blob.end(), b.m_sidechainId.h, b.m_sidechainId.h + HASH_SIZE);

		blob.insert(blob.end(), main.data() + outputs_offset + outputs_size, pubkeys);
		writeVarint(pubkeys_size, blob);

		blob.insert(blob.end(), pubkeys + pubkeys_size, main.data() + transactions_offset);
	}
	else {
		blob.assign(main.begin(), main.begin() + transactions_offset);
	}

	for (const auto& tx : b.m_transactions) {
		size_t index = 0;

		if (compact) {
			if (parent && !all_inline) {
				const auto it = std::find(parent->m_transactions.begin(), parent->m_transactions.end(), tx);
				if (it != parent->m_transactions.end()) index = 1 + (it - parent->m_transactions.begin());
			}

			writeVarint(index, blob);
		}

		if (!index) {
			const hash h = tx;
			blob.insert(blob.end(), h.h, h.h + HASH_SIZE);
		}
	}

	blob.insert(blob.end(), end - (1 + HASH_SIZE), end);
	blob.insert(blob.end(), side.begin(), side.end());

	return blob;
}

void replace_carrot_varint(std::vector<uint8_t>& blob, size_t offset, uint64_t value)
{
	uint64_t old;
	const uint8_t* end = readVarint(blob.data() + offset, blob.data() + blob.size(), old);
	ASSERT_NE(end, nullptr);

	std::vector<uint8_t> encoded;
	writeVarint(value, encoded);

	blob.erase(blob.begin() + offset, blob.begin() + (end - blob.data()));
	blob.insert(blob.begin() + offset, encoded.begin(), encoded.end());
}

struct CarrotBlockTestHasher : RandomX_Hasher_Base
{
	std::vector<uint8_t> blob;

	bool calculate(const void* data, size_t size, uint64_t, const hash&, hash& result, bool, size_t) override
	{
		const auto* p = static_cast<const uint8_t*>(data);
		blob.assign(p, p + size);

		result = {};
		return true;
	}
};

struct CarrotBlockTestCrypto
{
	CarrotBlockTestCrypto()
	{
		thread_pool_init();
		init_crypto_cache();
	}

	~CarrotBlockTestCrypto()
	{
		thread_pool_destroy();
		destroy_crypto_cache();

#ifdef WITH_INDEXED_HASHES
		indexed_hash::cleanup_storage();
#endif
	}
};

} // namespace

TEST(pool_block, deserialize_carrot)
{
	CarrotBlockTestCrypto crypto;

	SideChain sidechain(nullptr, NetworkType::Testnet, "default");

	sidechain.m_testMainChainDiff = difficulty_type(1000000000000ULL);

	std::ifstream ancestors("block_carrot_ancestors.dat", std::ios::binary);
	ASSERT_TRUE(ancestors.is_open());

	const struct {
		size_t main_size;
		hash sidechain_id;
		hash coinbase_hash;
		const char* hashing_blob;
	} expected[] = {
		{ 4396, H("0400ca792371f8df36594f56f095c6f8c97163352616e5690010aff754827333"), H("335daf62519ed2b14059d222dcbcfd6a0488a6da96d77ac6378f8067be20e615"), "111280cae2d006bdda1c810a375bad19096497a8e2129c9af02cbb6654571c900a1d82abbb3a897856341253d894523d547b80f6b51c3400a1693622607113177ea7c24bd73dd3d1072ffe8301" },
		{ 4487, H("d5b66ed1013ec7e3ce0df8f416de2ad6bd5f5f17a0df0ec9323f56f7dbc4fcb2"), H("7b0f958291e1f85ee9edd84ae3b5db9c46e164b85cf120a26cc1686534cf8363"), "11128acae2d006bdda1c810a375bad19096497a8e2129c9af02cbb6654571c900a1d82abbb3a8979563412dfe6e88cee500ba9bb114f0edce0643830b3899b4327f6f896cd614cd34170598301" },
		{ 4578, H("f92a0343f280eb0ddd0484d7f17c1523094eccf864c5ff2692f087d9966d05c4"), H("e49c34a7754ca556014ad26b3134b53a7e65578d12c6c279927f242b6e5f9468"), "111294cae2d006bdda1c810a375bad19096497a8e2129c9af02cbb6654571c900a1d82abbb3a897a56341277b07c277417c72b117836c106d6752c2959552c3ef7188895921f9cab069a7c8301" },
		{ 4668, H("bb134a644b0f5315c919d17ec40d20acdc2599d5eb15fe40eb388169e1697aba"), H("b112f093f23951de6d2385345d20c4daed75f5c586ff95c30f1e625ddcf22e5b"), "11129ecae2d006bdda1c810a375bad19096497a8e2129c9af02cbb6654571c900a1d82abbb3a897b56341262c026f0a85c93c31f46f4632beb2ef6adc68e525d7ba14ac8a4d99bd33625168301" },
	};

	PoolBlock decoded;

	for (size_t i = 0; i < 4; ++i) {
		SCOPED_TRACE(i);

		std::vector<uint8_t> buf;

		if (i < 3) {
			uint32_t size;
			ancestors.read(reinterpret_cast<char*>(&size), sizeof(size));
			ASSERT_TRUE(ancestors.good());

			ASSERT_GT(size, 0U);
			ASSERT_LE(size, MAX_BLOCK_SIZE);

			buf.resize(size);
			ancestors.read(reinterpret_cast<char*>(buf.data()), buf.size());
			ASSERT_TRUE(ancestors.good());
		}
		else {
			std::ifstream f("block_carrot.dat", std::ios::binary | std::ios::ate);
			ASSERT_TRUE(f.is_open());
			ASSERT_GT(f.tellg(), 0);
			ASSERT_LE(static_cast<uint64_t>(f.tellg()), MAX_BLOCK_SIZE);

			buf.resize(static_cast<size_t>(f.tellg()));
			f.seekg(0);
			f.read(reinterpret_cast<char*>(buf.data()), buf.size());

			ASSERT_TRUE(f.good());
		}

		PoolBlock b;

		ASSERT_EQ(b.deserialize(buf.data(), buf.size(), sidechain, false, false), 0);

		const auto main = b.serialize_mainchain_data();
		const auto side = b.serialize_sidechain_data();
		auto full = main;
		full.insert(full.end(), side.begin(), side.end());

		ASSERT_EQ(full, buf);
		ASSERT_EQ(main.size(), expected[i].main_size);
		ASSERT_EQ(b.m_sidechainId, expected[i].sidechain_id);

		CarrotBlockTestHasher hasher;
		hash pow_hash;

		ASSERT_TRUE(b.get_pow_hash(&hasher, b.m_txinGenHeight, {}, pow_hash, false, RandomX_Hasher_Base::VM_LANE_P2P));
		ASSERT_EQ(b.m_coinbase_tx_hash, expected[i].coinbase_hash);

		std::vector<uint8_t> expected_hashing_blob;

		ASSERT_TRUE(from_hex(expected[i].hashing_blob, strlen(expected[i].hashing_blob), expected_hashing_blob));
		ASSERT_EQ(hasher.blob, expected_hashing_blob);

		ASSERT_EQ(b.m_majorVersion, HARDFORK_VERSION_CARROT);
		ASSERT_EQ(b.m_minorVersion, 18U);
		ASSERT_EQ(b.m_txinGenHeight, 3012000U);
		ASSERT_EQ(b.m_sidechainHeight, i);
		ASSERT_EQ(b.m_timestamp, 1780000000U + i * 10);
		ASSERT_EQ(b.m_nonce, 0x12345678U + i);
		ASSERT_EQ(b.m_extraNonce, 0x9abcdef0U + i);
		ASSERT_EQ(b.m_extraNonceSize, 14U);
		ASSERT_EQ(b.m_carrotOutputs.size(), i + 1);
		ASSERT_TRUE(b.m_ephPublicKeys.empty());
		ASSERT_TRUE(b.m_outputAmounts.empty());
		ASSERT_TRUE(b.m_viewTags.empty());
		ASSERT_EQ(b.m_transactions.size(), 130U);
		ASSERT_EQ(b.m_fcmp_pp_n_tree_layers, 7U);
		ASSERT_EQ(b.m_fcmp_pp_tree_root, H("61b736ce93b62a3d3778ab204da85d3b4cdc07250f5da7e3df2629928134d526"));
		ASSERT_EQ(b.m_mergeMiningExtra.size(), 4U);
		ASSERT_FALSE(b.m_merkleProof.empty());
		ASSERT_EQ(b.m_sidechainExtraBuf[3], 0x99aabbccU + i);

		uint32_t chains, mm_nonce;
		b.decode_merkle_tree_data(chains, mm_nonce);

		ASSERT_EQ(chains, 5U);
		ASSERT_EQ(mm_nonce, 4663U);

		const hash aux_ids[] = { keccak("Carrot fixture chain A"), keccak("Carrot fixture chain B"), keccak("Carrot fixture chain C"), keccak("Carrot fixture chain D") };
		const size_t extra_sizes[] = { 0, 1, 128, 257 };

		for (size_t j = 0; j < 4; ++j) {
			const auto it = b.m_mergeMiningExtra.find(aux_ids[j]);

			ASSERT_NE(it, b.m_mergeMiningExtra.end());
			ASSERT_EQ(it->second.size(), extra_sizes[j]);

			for (size_t k = 0; k < extra_sizes[j]; ++k) {
				ASSERT_EQ(it->second[k], static_cast<uint8_t>(k + j + 1 + i));
			}
		}

		uint64_t reward = 0;
		for (const auto& output : b.m_carrotOutputs) reward += output.amount;
		ASSERT_EQ(reward, BASE_BLOCK_REWARD + 123456789U);

		const PoolBlock* parent = sidechain.find_block(b.m_parent);
		ASSERT_EQ(parent != nullptr, i > 0);
		ASSERT_EQ(sidechain.find_block(b.m_sidechainId), nullptr);

		for (bool cached : {false, true}) {
			SCOPED_TRACE(cached);

			if (cached) {
				ASSERT_TRUE(sidechain.add_block(b));
				const PoolBlock* stored = sidechain.find_block(b.m_sidechainId);
				ASSERT_NE(stored, nullptr);
				ASSERT_TRUE(stored->m_verified);
				ASSERT_FALSE(stored->m_invalid);
			}
			for (bool compact : {false, true}) {
				if (compact && !parent) continue;

				for (bool pruned : {false, true}) {
					for (bool all_inline : {false, true}) {
						if (all_inline && !compact) continue;

						SCOPED_TRACE(testing::Message() << "compact=" << compact << " pruned=" << pruned << " inline=" << all_inline);

						const auto wire = carrot_block_blob(b, parent, pruned, compact, all_inline);
						ASSERT_EQ(decoded.deserialize(wire.data(), wire.size(), sidechain, compact, pruned), 0);
						ASSERT_EQ(decoded.m_sidechainId, b.m_sidechainId);
						ASSERT_EQ(decoded.serialize_mainchain_data(), main);
						ASSERT_EQ(decoded.serialize_sidechain_data(), side);
						ASSERT_EQ(decoded.m_carrotOutputs.size(), b.m_carrotOutputs.size());

						for (size_t j = 0; j < b.m_carrotOutputs.size(); ++j) {
							const auto& x = decoded.m_carrotOutputs[j];
							const auto& y = b.m_carrotOutputs[j];
							ASSERT_EQ(x.amount, y.amount);
							ASSERT_EQ(x.onetime_address, y.onetime_address);
							ASSERT_EQ(x.eph_pub_key, y.eph_pub_key);
							ASSERT_EQ(x.vt, y.vt);
							ASSERT_EQ(x.anchor_enc, y.anchor_enc);
						}

						ASSERT_TRUE(decoded.m_ephPublicKeys.empty());
						ASSERT_TRUE(decoded.m_outputAmounts.empty());
						ASSERT_TRUE(decoded.m_viewTags.empty());
						ASSERT_FALSE(decoded.m_verified);

						if (pruned) {
							ASSERT_NE(decoded.deserialize(wire.data(), wire.size(), sidechain, compact, false), 0);
						}
					}
				}
			}

			int outputs_offset, outputs_size;
			(void)b.serialize_mainchain_data(nullptr, nullptr, &outputs_offset, &outputs_size);

			const auto pruned = carrot_block_blob(b, parent, true, false);

			const uint8_t* const begin = pruned.data();
			const uint8_t* const end = begin + pruned.size();

			uint64_t value;
			const size_t reward_offset = outputs_offset + 1;
			const uint8_t* output_size_ptr = readVarint(begin + reward_offset, end, value);
			ASSERT_NE(output_size_ptr, nullptr);

			const uint8_t* id = readVarint(output_size_ptr, end, value);
			ASSERT_NE(id, nullptr);

			const uint8_t* extra_size_ptr = id + HASH_SIZE;
			const uint8_t* pubkeys_size_ptr = readVarint(extra_size_ptr, end, value);
			ASSERT_NE(pubkeys_size_ptr, nullptr);

			const uint64_t extra_size = value;
			const uint8_t* nonce_tag = readVarint(pubkeys_size_ptr, end, value);
			ASSERT_NE(nonce_tag, nullptr);

			const uint64_t pubkeys_size = value;

			auto bad_varint = [&](size_t offset, uint64_t replacement) {
				auto bad = pruned;
				replace_carrot_varint(bad, offset, replacement);
				EXPECT_NE(decoded.deserialize(bad.data(), bad.size(), sidechain, false, true), 0) << "offset=" << offset << " value=" << replacement;
			};

			bad_varint(reward_offset, reward + 1);

			for (uint64_t n : std::initializer_list<uint64_t>{0ULL, 53ULL, uint64_t(outputs_size - 1), uint64_t(outputs_size + 1), MAX_BLOCK_SIZE + 1, UINT64_MAX}) bad_varint(output_size_ptr - begin, n);
			for (uint64_t n : std::initializer_list<uint64_t>{0ULL, 32ULL, pubkeys_size - 1, pubkeys_size + 1, MAX_BLOCK_SIZE + 1, UINT64_MAX}) bad_varint(pubkeys_size_ptr - begin, n);

			bad_varint(extra_size_ptr - begin, extra_size - 1);
			bad_varint(extra_size_ptr - begin, extra_size + 1);
			bad_varint(extra_size_ptr - begin, extra_size - (pubkeys_size - (nonce_tag - pubkeys_size_ptr)));

			size_t header_size;
			(void)b.serialize_mainchain_data(&header_size);

			auto changed_nonces = pruned;
			changed_nonces[header_size - NONCE_SIZE] ^= 0x80;
			changed_nonces[(nonce_tag - begin) + 2] ^= 0x40;

			ASSERT_EQ(decoded.deserialize(changed_nonces.data(), changed_nonces.size(), sidechain, false, true), 0);
			ASSERT_EQ(decoded.m_sidechainId, b.m_sidechainId);
			ASSERT_EQ(decoded.m_nonce, b.m_nonce ^ 0x80);
			ASSERT_EQ(decoded.m_extraNonce, b.m_extraNonce ^ 0x40);

			const uint32_t nonce = b.m_nonce ^ 0x80;
			const uint32_t extra_nonce = b.m_extraNonce ^ 0x40;

			ASSERT_EQ(decoded.serialize_mainchain_data(), b.serialize_mainchain_data(nullptr, nullptr, nullptr, nullptr, &nonce, &extra_nonce));

			for (size_t offset : {size_t(id - begin), pruned.size() - 1, pruned.size() - side.size() - HASH_SIZE, pruned.size() - side.size() - HASH_SIZE - 2}) {
				auto bad = pruned;
				bad[offset] ^= 1;
				EXPECT_NE(decoded.deserialize(bad.data(), bad.size(), sidechain, false, true), 0) << offset;
			}

			auto bad_count = buf;
			replace_carrot_varint(bad_count, outputs_offset, UINT64_MAX);
			EXPECT_NE(decoded.deserialize(bad_count.data(), bad_count.size(), sidechain, false, false), 0);

			if (i > 0) {
				auto bad_reward = buf;
				replace_carrot_varint(bad_reward, outputs_offset + 1, UINT64_MAX);
				EXPECT_NE(decoded.deserialize(bad_reward.data(), bad_reward.size(), sidechain, false, false), 0);
			}

			if (!cached) {
				for (size_t n = 0; n < pruned.size(); ++n) EXPECT_NE(decoded.deserialize(pruned.data(), n, sidechain, false, true), 0) << n;
			}
		}
	}
	ASSERT_EQ(ancestors.peek(), std::char_traits<char>::eof());
}

TEST(pool_block, verify)
{
	thread_pool_init();
	init_crypto_cache();
	{
	struct STest
	{
		const char* m_poolName;
		const char* m_fileName;
		uint64_t m_txinGenHeight;
		uint64_t m_sidechainHeight;
		uint32_t m_expectedSharesNextBlock;
		bool m_shuffle;
		hash m_templateBlobsHash;
	} tests[6] = {
		{ "default", "sidechain_dump.dat", 3456189, 11704382, 53, false, H("fd6bd6b38ed20a770c7eca6de3715e36453765908ef52a1d4df822d5eb66de5d") },
		{ "default", "sidechain_dump.dat", 3456189, 11704382, 53, true, H("fd6bd6b38ed20a770c7eca6de3715e36453765908ef52a1d4df822d5eb66de5d") },
		{ "mini", "sidechain_dump_mini.dat", 3456189, 11207082, 578, false, H("a0746d4a39a1a72aa48ddacc0c38d44504c77022bff92d937dbf45478cb8e4cb") },
		{ "mini", "sidechain_dump_mini.dat", 3456189, 11207082, 578, true, H("a0746d4a39a1a72aa48ddacc0c38d44504c77022bff92d937dbf45478cb8e4cb") },
		{ "nano", "sidechain_dump_nano.dat", 3456189, 188542, 115, false, H("2b5a6abd276e99a1a8165c42e4ef3b4a7bcb4e79e483fc891e77288f8498a417") },
		{ "nano", "sidechain_dump_nano.dat", 3456189, 188542, 115, true, H("2b5a6abd276e99a1a8165c42e4ef3b4a7bcb4e79e483fc891e77288f8498a417") },
	};

	for (const STest& t : tests)
	{
		SideChain sidechain(nullptr, NetworkType::Mainnet, t.m_poolName);

		// Difficulty of block 3454976
		sidechain.m_testMainChainDiff = difficulty_type(625461936742ULL, 0ULL);

		std::ifstream f(t.m_fileName, std::ios::binary | std::ios::ate);
		ASSERT_EQ(f.good() && f.is_open(), true);

		std::vector<uint8_t> buf(f.tellg());
		f.seekg(0);
		f.read(reinterpret_cast<char*>(buf.data()), buf.size());
		ASSERT_EQ(f.good(), true);

		std::vector<PoolBlock*> blocks;
		for (const uint8_t *p = buf.data(), *e = buf.data() + buf.size(); p < e;) {
			ASSERT_TRUE(p + sizeof(uint32_t) <= e);
			const uint32_t n = *reinterpret_cast<const uint32_t*>(p);
			p += sizeof(uint32_t);

			ASSERT_TRUE(p + n <= e);

			PoolBlock* b = new PoolBlock();
			ASSERT_EQ(b->deserialize(p, n, sidechain, false, false), 0);
			p += n;

			blocks.push_back(b);
		}

		if (t.m_shuffle) {
			std::mt19937_64 rng;

			for (uint64_t i = 0, k, n = blocks.size(); i < n - 1; ++i) {
				umul128(rng(), n - i, &k);
				std::swap(blocks[i], blocks[i + k]);
			}
		}

		for (uint64_t i = 0, n = blocks.size(); i < n; ++i) {
			ASSERT_TRUE(sidechain.add_block(*blocks[i]));
			ASSERT_TRUE(sidechain.find_block(blocks[i]->m_sidechainId) != nullptr);
			delete blocks[i];
		}

		for (auto it = sidechain.blocksById().begin(); it != sidechain.blocksById().end(); ++it) {
			const PoolBlock* b = it->second;
			ASSERT_TRUE(b->m_verified);
			ASSERT_FALSE(b->m_invalid);
		}

		const PoolBlock* tip = sidechain.chainTip();
		ASSERT_TRUE(tip != nullptr);
		ASSERT_TRUE(tip->m_verified);
		ASSERT_FALSE(tip->m_invalid);

		ASSERT_EQ(tip->m_txinGenHeight, t.m_txinGenHeight);
		ASSERT_EQ(tip->m_sidechainHeight, t.m_sidechainHeight);

		{
			BlockTemplate tpl(&sidechain, nullptr);
			auto& r = tpl.rng();
			r.seed(0);

			MinerData data;
			data.major_version = 16;
			data.height = t.m_txinGenHeight;
			data.prev_id = H("f7723462d2f4d9f605601df8de8bd483802d2275f77cbf3a6f61d8f3fc4c47bc");
			data.seed_hash = H("11186f5a8473d8dc7a0d3a0bf25834a07b1dffe8741d53cd543a8708c2e8b2a9");
			data.difficulty = { 656711234691ULL, 0 };
			data.median_weight = 300000;
			data.already_generated_coins = std::numeric_limits<uint64_t>::max();
			data.median_timestamp = (1ULL << 35) - 2;

			Mempool mempool;

			for (uint64_t i = 0; i < 8192; ++i) {
				hash h;
				h.u64()[0] = i;

				TxMempoolData tx;
				tx.id = static_cast<indexed_hash>(h);
				tx.fee = (r() % 1'000'000'000) + 30'000'000;
				tx.weight = (r() % 20'000) + 1'500;
				mempool.add(tx);
			}

			Params params;

			params.m_miningWallet = Wallet("44MnN1f3Eto8DZYUWuE5XZNUtE3vcRzt2j6PzqWpPau34e6Cf4fAxt6X2MBmrm6F9YMEiMNjN6W4Shn4pLcfNAja621jwyg");

			tpl.update(data, mempool, params);

			std::vector<uint8_t> blobs;
			uint64_t height;
			difficulty_type diff, aux_diff, sidechain_diff;
			hash seed_hash;
			size_t nonce_offset;
			uint32_t template_id;
			const uint32_t blob_size = tpl.get_hashing_blobs(0, 1000, blobs, height, diff, aux_diff, sidechain_diff, seed_hash, nonce_offset, template_id);
			ASSERT_EQ(blob_size, 77);

			hash blobs_hash;
			keccak(blobs.data(), static_cast<int>(blobs.size()), blobs_hash.h);
			ASSERT_EQ(blobs_hash, t.m_templateBlobsHash);
		}

		PoolBlock block;
		ASSERT_TRUE(block.m_minerWallet.decode("44MnN1f3Eto8DZYUWuE5XZNUtE3vcRzt2j6PzqWpPau34e6Cf4fAxt6X2MBmrm6F9YMEiMNjN6W4Shn4pLcfNAja621jwyg"));

		std::vector<MinerShare> shares;

		ASSERT_TRUE(sidechain.fill_sidechain_data(block, shares));

		ASSERT_EQ(block.m_sidechainHeight, t.m_sidechainHeight + 1);
		ASSERT_EQ(shares.size(), t.m_expectedSharesNextBlock);

		const PoolBlock* parent = sidechain.find_block(tip->m_parent);
		ASSERT_TRUE(parent != nullptr);

		// Check pruned and compact broadcast blobs

		auto tip_full_blob = tip->serialize_mainchain_data();
		auto v2 = tip->serialize_sidechain_data();
		tip_full_blob.insert(tip_full_blob.end(), v2.begin(), v2.end());

		P2PServer::Broadcast broadcast(*tip, parent);

		{
			PoolBlock block2;
			ASSERT_EQ(block2.deserialize(broadcast.pruned_blob.data(), broadcast.pruned_blob.size(), sidechain, false, true), 0);

			auto v1 = block2.serialize_mainchain_data();
			v2 = block2.serialize_sidechain_data();
			v1.insert(v1.end(), v2.begin(), v2.end());

			ASSERT_EQ(v1, tip_full_blob);

			ASSERT_NE(block2.deserialize(broadcast.pruned_blob.data(), broadcast.pruned_blob.size(), sidechain, false, false), 0);
		}

		if (!broadcast.compact_blob.empty()) {
			PoolBlock block3;
			ASSERT_EQ(block3.deserialize(broadcast.compact_blob.data(), broadcast.compact_blob.size(), sidechain, true, true), 0);

			auto v1 = block3.serialize_mainchain_data();
			v2 = block3.serialize_sidechain_data();
			v1.insert(v1.end(), v2.begin(), v2.end());

			ASSERT_EQ(v1, tip_full_blob);
		}

		if (!broadcast.compact_unpruned_blob.empty()) {
			PoolBlock block4;
			ASSERT_EQ(block4.deserialize(broadcast.compact_unpruned_blob.data(), broadcast.compact_unpruned_blob.size(), sidechain, true, false), 0);

			auto v1 = block4.serialize_mainchain_data();
			v2 = block4.serialize_sidechain_data();
			v1.insert(v1.end(), v2.begin(), v2.end());

			ASSERT_EQ(v1, tip_full_blob);
		}
	}
	}
	thread_pool_destroy();
	destroy_crypto_cache();

#ifdef WITH_INDEXED_HASHES
	indexed_hash::cleanup_storage();
#endif
}

}
