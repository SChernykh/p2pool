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
#include "carrot.h"
#include "merkle.h"
#include "wallet.h"
#include "gtest/gtest.h"
#include <fstream>
#include <numeric>
#include <sstream>

namespace p2pool {

static hash H(const char* s)
{
	hash result;
	from_hex(s, strlen(s), result);
	return result;
};

TEST(pool_block, genesis_tx_key_seed)
{
	const hash consensus_hash = H("6126482df93599e022eb6e71f3e32f97ff00cc4e146cbf791afbf78d1ba7c94b");

	constexpr size_t N_PREV_IDS = 3;

	const hash prev_ids[N_PREV_IDS] = {
		H("0000000000000000000000000000000000000000000000000000000000000000"),
		H("81a0260b29d5224e88d04b11faff321fbdc11c4570779386b2a1817a86dc622c"),
		H("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
	};

	// One seed per (Monero height, previous Monero block id) pair: the seed must depend on both
	const struct {
		uint64_t height;
		hash seed[N_PREV_IDS];
	} tests[] = {
		{ 0, {
			H("15e3f76b370b48678b5444533d1b3f964caffdcd414c5179074971427c99e337"),
			H("a13a005c4c32227b99f917e5ab7f5a78f9e6c1c352aff2369d1fcdcf769d6e14"),
			H("df3f96ef116ce7abec29e57713f704c10bf0b9c5f78aa41bb06885bf66524ccb") } },
		{ 1, {
			H("b3354891c5722dabfe6200c2ee17efb008b38414471500826b0b46e5545c32bf"),
			H("9f3e9cffab3dc768649f2de52ffda2235f6ec4f479a777dfea7a82ff2a798215"),
			H("a1f0b44e5d144ef1c02779acf7a823ded868f7bd732fe634e5aba26a86b026b8") } },
		{ 3102800, {
			H("ebcfb71716e38168dc27801b1a9df3dbed1c69fe7c9cd51ed5e49a7560851cc9"),
			H("3a8e489cba8ff2db2f834619b213c8c2b5dfc74e3467af129e1889b8ba80e6ab"),
			H("9bc4081a78aa124e1ca2c62650e94e0b2d1135c7fc56c47bd0f6a5aacf73703d") } },
		{ 0x100000000ULL, {
			H("43d259d2173c487207e7a743ead45bea3c88649067ea03c97abb04bd57dd0536"),
			H("a846eea0b5581a1b90c13c1ae69eb709e6e18114e307055ddac12c159b52e18f"),
			H("3af367dd74529ea0e6afffe4453b57112e2a365636694fd7536cc85479499f90") } },
		{ UINT64_MAX, {
			H("b6bffc226bf657ef892cf291876e4e5eb8329aa352785caf948035ec89888338"),
			H("ada3f722d44d5bce44bee4ba57429d644efdcd05be01f14843546ee184a99845"),
			H("215fd3e2bce6dca5345175bd585c7a97ee1790e03ff2bcb393ce6837027b1a6a") } },
	};

	PoolBlock b;

	for (const auto& t : tests) {
		for (size_t i = 0; i < N_PREV_IDS; ++i) {
			SCOPED_TRACE(testing::Message() << "height=" << t.height << " prev_id=" << prev_ids[i]);

			b.m_txinGenHeight = t.height;
			b.m_prevId = prev_ids[i];

			const hash& seed = t.seed[i];

			b.m_majorVersion = HARDFORK_VERSION_CARROT - 1;
			EXPECT_EQ(b.calculate_genesis_tx_key_seed(consensus_hash), consensus_hash);

			b.m_majorVersion = HARDFORK_VERSION_CARROT;
			EXPECT_EQ(b.calculate_genesis_tx_key_seed(consensus_hash), seed);

			hash other_consensus_hash = consensus_hash;
			other_consensus_hash.h[0] ^= 1;
			EXPECT_NE(b.calculate_genesis_tx_key_seed(other_consensus_hash), seed);

			b.m_prevId.h[0] ^= 1;
			EXPECT_NE(b.calculate_genesis_tx_key_seed(consensus_hash), seed);
			b.m_prevId = prev_ids[i];

			b.m_majorVersion = HARDFORK_VERSION_CARROT + 1;
			EXPECT_EQ(b.calculate_genesis_tx_key_seed(consensus_hash), seed);
		}
	}
}

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

	const struct {
		const char* address;
		uint64_t reward;
	} payouts[] = {
		{ "4B4aCvEcZr6GcusVJfEds2LXixCeJ2dQBaDUCguWmzi5L7PW5tVXfAnE4cn1mQdiNzH6zWcEPMQTiYTsNcX44ryxCJWZKZH", 17411468548U },
		{ "43VbH7CQCJqhH1d327TBenCs9hFN3zvcgX5YZdGyJfEE5rabasAtKhyPsKmbYSU9AmMReACZrz9j5U2Ba6WXWoQpVi38AJn", 1404738424U },
		{ "46r3PD45TYH9jVf8sEejW9JdK1EgNe6BeYLdGyJTU1MRctoevAHXpzSjBMJhdkLirGXwiWdZejSRZ8MZP72artSD17LprKY", 1419699645U },
		{ "44MnN1f3Eto8DZYUWuE5XZNUtE3vcRzt2j6PzqWpPau34e6Cf4fAxt6X2MBmrm6F9YMEiMNjN6W4Shn4pLcfNAja621jwyg", 0U },
	};

	ASSERT_DOUBLE_EQ(sidechain.get_reward_share(Wallet(payouts[0].address)), 0.0);

	sidechain.set_chain_tip(&b);

	const uint64_t total_reward = std::accumulate(b.m_outputAmounts.begin(), b.m_outputAmounts.end(), 0ULL);
	ASSERT_GT(total_reward, 0U);

	for (const auto& payout : payouts) {
		SCOPED_TRACE(payout.address);

		const Wallet w(payout.address);
		ASSERT_TRUE(w.valid());

		ASSERT_EQ(b.get_payout(w), payout.reward);
		EXPECT_DOUBLE_EQ(sidechain.get_reward_share(w), static_cast<double>(payout.reward) / static_cast<double>(total_reward));
	}

	PoolBlock::MainchainLayout layout;

	const std::vector<uint8_t> mainchain_data = b.serialize_mainchain_data(&layout);
	const std::vector<uint8_t> sidechain_data = b.serialize_sidechain_data();

	ASSERT_EQ(mainchain_data.size(), 1829U);
	ASSERT_EQ(layout.header_size, 43U);
	ASSERT_EQ(layout.miner_tx_size, 1145U);
	ASSERT_EQ(layout.outputs_offset, 54);
	ASSERT_EQ(layout.outputs_blob_size, 1058);
	ASSERT_EQ(layout.pubkeys_offset, 1113);
	ASSERT_EQ(layout.pubkeys_blob_size, 33);

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

	b.m_outputAmounts.clear();
	EXPECT_EQ(b.get_payout(Wallet(payouts[0].address)), 0U);
	EXPECT_DOUBLE_EQ(sidechain.get_reward_share(Wallet(payouts[0].address)), 0.0);
	}
	destroy_crypto_cache();

#ifdef WITH_INDEXED_HASHES
	indexed_hash::cleanup_storage();
#endif
}

static void replace_carrot_varint(std::vector<uint8_t>& blob, size_t offset, uint64_t value)
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

		// Not RandomX, but it has to be non-zero and a function of the block
		keccak(p, static_cast<int>(size), result.h);
		return true;
	}
};

TEST(pool_block, deserialize_carrot)
{
	thread_pool_init();
	init_crypto_cache();

	auto on_scope_leave = ScopeGuard{[]() {
		thread_pool_destroy();
		destroy_crypto_cache();

#ifdef WITH_INDEXED_HASHES
		indexed_hash::cleanup_storage();
#endif
	}};

	SideChain sidechain(nullptr, NetworkType::Testnet, "default");

	sidechain.m_testMainChainDiff = difficulty_type(1000000000000ULL);

	Wallet no_payout(nullptr);

	ASSERT_TRUE(no_payout.assign(H("5866666666666666666666666666666666666666666666666666666666666666"), H("61b736ce93b62a3d3778ab204da85d3b4cdc07250f5da7e3df2629928134d526"), NetworkType::Testnet));
	ASSERT_DOUBLE_EQ(sidechain.get_reward_share(no_payout), 0.0);

	std::vector<Wallet> mining_wallets;

	// Starting with Carrot, a block pays out the PPLNS window of its parent, so block N pays N miners (block 0 pays 1)
	constexpr uint64_t payouts[4][4] = {
		{ 600123456789ULL, 0, 0, 0 },
		{ 600123456789ULL, 0, 0, 0 },
		{ 300000000000ULL, 300123456789ULL, 0, 0 },
		{ 199800000000ULL, 200400000000ULL, 199923456789ULL, 0 },
	};

	std::ifstream ancestors("block_carrot_ancestors.dat", std::ios::binary);
	ASSERT_TRUE(ancestors.is_open());

	const struct {
		size_t main_size;
		size_t pruned_size;
		size_t compact_size;
		size_t compact_unpruned_size;
		hash sidechain_id;
		hash coinbase_hash;
		const char* hashing_blob;
	} expected[] = {
		{ 4386, 5079, 0, 0, H("918309a3619958fc58717cfe64ad9ecdec437f3057f3f69d3e6de2b07916705e"), H("552d2704514754ff4475d87b889a48228786e2beb49e8e1a340e981369e685bb"), "111280cae2d006bdda1c810a375bad19096497a8e2129c9af02cbb6654571c900a1d82abbb3a897856341217fea4f8db518b3589e6f6218d941be7bdf4c8f362ade80e9f1613bd80c72d4e8301" },
		{ 4386, 5079, 1052, 1103, H("f98d904b199e6e2e761055f5ae50a33e11065f4fc7313bd8a991b7a01f3e266f"), H("c307697707ba66facc4d7fc700632db7531bf88ba793e15337b77bfe23dea6fa"), "11128acae2d006bdda1c810a375bad19096497a8e2129c9af02cbb6654571c900a1d82abbb3a897956341250c08b59031d71c0a6e7043079fb5da2fcc76f3fc0d64930877dd3cc0940bc2c8301" },
		{ 4477, 5079, 1052, 1194, H("1e203462d608ef086092b679ab8c12dd913652acfa12facd43143ca94eae9cf3"), H("ece6a6719e555abba178fbd6c0f5d6ca636986115163880f2af6dbaaf7a62905"), "111294cae2d006bdda1c810a375bad19096497a8e2129c9af02cbb6654571c900a1d82abbb3a897a5634121549d2f3e485ba5ce23cc878cbd63ad46956df848a2199e271cade56cbc53b238301" },
		{ 4568, 5081, 1086, 1317, H("d3b834bb52428d6a92118aab2d3aa595ab2d510526485ab7438befd8a6e7e3e3"), H("64df04e7d29cce1f2d35fcf16f2a6fb68e2795381be5bbc191d2f7a795416e10"), "11129ecae2d006bdda1c810a375bad19096497a8e2129c9af02cbb6654571c900a1d82abbb3a897b563412b88dbc5e4521790efefe93977aacc046850c14356a07084573a7527280ce39e08301" },
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
			ASSERT_LE(size, MAX_BLOCK_SIZE_NEW);

			buf.resize(size);
			ancestors.read(reinterpret_cast<char*>(buf.data()), buf.size());
			ASSERT_TRUE(ancestors.good());
		}
		else {
			std::ifstream f("block_carrot.dat", std::ios::binary | std::ios::ate);
			ASSERT_TRUE(f.is_open());
			ASSERT_GT(f.tellg(), 0);
			ASSERT_LE(static_cast<uint64_t>(f.tellg()), MAX_BLOCK_SIZE_NEW);

			buf.resize(static_cast<size_t>(f.tellg()));
			f.seekg(0);
			f.read(reinterpret_cast<char*>(buf.data()), buf.size());

			ASSERT_TRUE(f.good());
		}

		PoolBlock b;

		ASSERT_EQ(b.deserialize(buf.data(), buf.size(), sidechain, false, false), 0);
		mining_wallets.push_back(b.m_minerWallet);

		PoolBlock::MainchainLayout layout;
		const auto main = b.serialize_mainchain_data(&layout);
		const auto side = b.serialize_sidechain_data();

		ASSERT_EQ(main.size(), expected[i].main_size);
		ASSERT_EQ(b.m_sidechainId, expected[i].sidechain_id);

		// Post-Carrot the extra nonce must be exactly EXTRA_NONCE_SIZE bytes
		{
			const size_t extra_nonce_tag_offset = static_cast<size_t>(layout.pubkeys_offset + layout.pubkeys_blob_size);

			ASSERT_LT(extra_nonce_tag_offset + 1, buf.size());
			ASSERT_EQ(buf[extra_nonce_tag_offset], TX_EXTRA_NONCE);
			ASSERT_EQ(buf[extra_nonce_tag_offset + 1], EXTRA_NONCE_SIZE);

			std::vector<uint8_t> padded(buf);
			padded[extra_nonce_tag_offset + 1] = EXTRA_NONCE_SIZE + 1;

			PoolBlock rejected;
			ASSERT_NE(rejected.deserialize(padded.data(), padded.size(), sidechain, false, false), 0);
		}

		CarrotBlockTestHasher hasher;
		hash pow_hash;

		ASSERT_TRUE(b.get_pow_hash(&hasher, b.m_txinGenHeight, {}, pow_hash, false, RandomX_Hasher_Base::VM_LANE_P2P));
		ASSERT_EQ(b.m_coinbase_tx_hash, expected[i].coinbase_hash);

		b.m_powHash = pow_hash;

		std::vector<uint8_t> expected_hashing_blob;

		ASSERT_TRUE(from_hex(expected[i].hashing_blob, strlen(expected[i].hashing_blob), expected_hashing_blob));
		ASSERT_EQ(hasher.blob, expected_hashing_blob);

		ASSERT_EQ(b.m_majorVersion, HARDFORK_VERSION_CARROT);
		ASSERT_EQ(b.m_minorVersion, 18U);
		ASSERT_EQ(b.m_txinGenHeight, 3102800U);
		ASSERT_EQ(b.m_txkeySecSeed, H("fd912d9f62f086f659bf4cec729abaee5ee59cd17020d18e6bb1f6cfdadea104"));
		ASSERT_EQ(b.m_sidechainHeight, i);
		ASSERT_EQ(b.m_timestamp, 1780000000U + i * 10);
		ASSERT_EQ(b.m_nonce, 0x12345678U + i);
		ASSERT_EQ(b.m_extraNonce, 0x9abcdef0U + i);
		ASSERT_EQ(b.m_extraNonceSize, static_cast<uint64_t>(EXTRA_NONCE_SIZE));
		ASSERT_EQ(b.m_carrotOutputs.size(), std::max<size_t>(i, 1));
		ASSERT_TRUE(b.m_ephPublicKeys.empty());
		ASSERT_TRUE(b.m_outputAmounts.empty());
		ASSERT_TRUE(b.m_viewTags.empty());
		ASSERT_EQ(b.m_transactions.size(), 130U);
		ASSERT_EQ(b.m_fcmp_pp_n_tree_layers, 7U);
		ASSERT_EQ(b.m_fcmp_pp_tree_root, H("61b736ce93b62a3d3778ab204da85d3b4cdc07250f5da7e3df2629928134d526"));
		ASSERT_EQ(b.m_mergeMiningExtra.size(), 4U);
		ASSERT_FALSE(b.m_merkleProof.empty());
		ASSERT_EQ(b.m_sidechainExtraBuf[3], b.m_extraNonce);
		ASSERT_EQ(b.m_parentNonce, i ? (0x12345678U + i - 1) : 0U);

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

		const P2PServer::Broadcast broadcast(b, parent);

		ASSERT_EQ(broadcast.blob, buf);
		ASSERT_EQ(broadcast.pruned_blob.size(), expected[i].pruned_size);
		ASSERT_EQ(broadcast.compact_blob.size(), expected[i].compact_size);
		ASSERT_EQ(broadcast.compact_unpruned_blob.size(), expected[i].compact_unpruned_size);

		ASSERT_EQ(broadcast.id, b.m_sidechainId);
		ASSERT_EQ(broadcast.parent_hash, b.m_parent);
		ASSERT_EQ(broadcast.uncle_hashes, b.m_uncles);
		ASSERT_EQ(broadcast.received_timestamp, b.m_receivedTimestamp);

		PoolBlock inline_parent;
		inline_parent.m_transactions.emplace_back(hash{});
		for (hash tx : b.m_transactions) ASSERT_FALSE(tx.empty());

		const P2PServer::Broadcast inline_broadcast(b, &inline_parent);

		ASSERT_EQ(inline_broadcast.compact_blob.size(), broadcast.pruned_blob.size() + b.m_transactions.size());
		ASSERT_EQ(inline_broadcast.compact_unpruned_blob.size(), broadcast.blob.size() + b.m_transactions.size());

		const PoolBlock empty_parent;
		const P2PServer::Broadcast no_parent_transactions(b, &empty_parent);

		ASSERT_TRUE(no_parent_transactions.compact_blob.empty());
		ASSERT_TRUE(no_parent_transactions.compact_unpruned_blob.empty());

		ASSERT_EQ(no_parent_transactions.pruned_blob, broadcast.pruned_blob);
		ASSERT_EQ(no_parent_transactions.blob, broadcast.blob);

		for (bool cached : {false, true}) {
			SCOPED_TRACE(cached);

			if (cached) {
				ASSERT_TRUE(sidechain.add_block(b));
				const PoolBlock* stored = sidechain.find_block(b.m_sidechainId);
				ASSERT_NE(stored, nullptr);
				ASSERT_TRUE(stored->m_verified);
				ASSERT_FALSE(stored->m_invalid);
				ASSERT_EQ(sidechain.chainTip(), stored);

				for (size_t j = 0; j < mining_wallets.size(); ++j) {
					EXPECT_DOUBLE_EQ(sidechain.get_reward_share(mining_wallets[j]), static_cast<double>(payouts[i][j]) / static_cast<double>(reward)) << "miner " << j;
				}
				EXPECT_DOUBLE_EQ(sidechain.get_reward_share(no_payout), 0.0);
			}

			for (bool compact : {false, true}) {
				if (compact && !parent) continue;

				for (bool pruned : {false, true}) {
					for (bool all_inline : {false, true}) {
						if (all_inline && !compact) continue;

						SCOPED_TRACE(testing::Message() << "compact=" << compact << " pruned=" << pruned << " inline=" << all_inline);

						const auto& data = all_inline ? inline_broadcast : broadcast;

						const auto& wire = compact
							? (pruned ? data.compact_blob : data.compact_unpruned_blob)
							: (pruned ? data.pruned_blob : data.blob);

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

						for (size_t j = 0; j < mining_wallets.size(); ++j) {
							EXPECT_EQ(decoded.get_payout(mining_wallets[j]), payouts[i][j]) << "miner " << j;
						}
						EXPECT_EQ(decoded.get_payout(no_payout), 0U);

						if (pruned) {
							ASSERT_NE(decoded.deserialize(wire.data(), wire.size(), sidechain, compact, false), 0);
						}
					}
				}
			}

			const auto& pruned = broadcast.pruned_blob;

			const uint8_t* const begin = pruned.data();
			const uint8_t* const end = begin + pruned.size();

			uint64_t value;
			const size_t reward_offset = layout.outputs_offset + 1;
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

			for (uint64_t n : std::initializer_list<uint64_t>{0ULL, 53ULL, uint64_t(layout.outputs_blob_size - 1), uint64_t(layout.outputs_blob_size + 1), MAX_BLOCK_SIZE_NEW + 1, UINT64_MAX}) bad_varint(output_size_ptr - begin, n);
			for (uint64_t n : std::initializer_list<uint64_t>{0ULL, 32ULL, pubkeys_size - 1, pubkeys_size + 1, MAX_BLOCK_SIZE_NEW + 1, UINT64_MAX}) bad_varint(pubkeys_size_ptr - begin, n);

			bad_varint(extra_size_ptr - begin, extra_size - 1);
			bad_varint(extra_size_ptr - begin, extra_size + 1);
			bad_varint(extra_size_ptr - begin, extra_size - (pubkeys_size - (nonce_tag - pubkeys_size_ptr)));

			auto changed_nonces = pruned;
			changed_nonces[layout.header_size - NONCE_SIZE] ^= 0x80;

			ASSERT_EQ(decoded.deserialize(changed_nonces.data(), changed_nonces.size(), sidechain, false, true), 0);
			ASSERT_EQ(decoded.m_sidechainId, b.m_sidechainId);
			ASSERT_EQ(decoded.m_nonce, b.m_nonce ^ 0x80);
			ASSERT_EQ(decoded.m_extraNonce, b.m_extraNonce);

			const uint32_t nonce = b.m_nonce ^ 0x80;
			const uint32_t extra_nonce = b.m_extraNonce;

			ASSERT_EQ(decoded.serialize_mainchain_data(), b.serialize_mainchain_data(nullptr, &nonce, &extra_nonce));

			changed_nonces[(nonce_tag - begin) + 2] ^= 0x40;
			EXPECT_NE(decoded.deserialize(changed_nonces.data(), changed_nonces.size(), sidechain, false, true), 0);

			for (size_t offset : {size_t(id - begin), pruned.size() - 1, pruned.size() - side.size() - HASH_SIZE, pruned.size() - side.size() - HASH_SIZE - 2}) {
				auto bad = pruned;
				bad[offset] ^= 1;
				EXPECT_NE(decoded.deserialize(bad.data(), bad.size(), sidechain, false, true), 0) << offset;
			}

			auto bad_count = buf;
			replace_carrot_varint(bad_count, layout.outputs_offset, UINT64_MAX);
			EXPECT_NE(decoded.deserialize(bad_count.data(), bad_count.size(), sidechain, false, false), 0);

			if (i > 0) {
				auto bad_reward = buf;
				replace_carrot_varint(bad_reward, layout.outputs_offset + 1, UINT64_MAX);
				EXPECT_NE(decoded.deserialize(bad_reward.data(), bad_reward.size(), sidechain, false, false), 0);
			}

			if (!cached) {
				for (size_t n = 0; n < pruned.size(); ++n) EXPECT_NE(decoded.deserialize(pruned.data(), n, sidechain, false, true), 0) << n;
			}
		}
	}
	ASSERT_EQ(ancestors.peek(), std::char_traits<char>::eof());

	const PoolBlock* parent = sidechain.chainTip();
	ASSERT_NE(parent, nullptr);
	ASSERT_FALSE(parent->m_transactions.empty());

	{
		PoolBlock scan_block(*parent);

		PoolBlock* original_tip = sidechain.blocksById().at(parent->m_sidechainId);
		sidechain.set_chain_tip(&scan_block);

		auto restore_tip = ScopeGuard{[&]() { sidechain.set_chain_tip(original_tip); }};

		auto check_no_reward = [&]() {
			for (size_t i = 0; i < mining_wallets.size(); ++i) {
				EXPECT_EQ(scan_block.get_payout(mining_wallets[i]), 0U) << "miner " << i;
				EXPECT_DOUBLE_EQ(sidechain.get_reward_share(mining_wallets[i]), 0.0) << "miner " << i;
			}
		};

		for (size_t i = 0; i < CARROT_VIEW_TAG_BYTES; ++i) {
			SCOPED_TRACE(testing::Message() << "view-tag byte " << i);

			for (auto& o : scan_block.m_carrotOutputs) o.vt.data[i] ^= 1;

			check_no_reward();
			scan_block.m_carrotOutputs = parent->m_carrotOutputs;
		}

		for (auto& o : scan_block.m_carrotOutputs) ++o.amount;
		check_no_reward();
		scan_block.m_carrotOutputs = parent->m_carrotOutputs;

		for (auto& o : scan_block.m_carrotOutputs) o.eph_pub_key.h[0] ^= 1;
		check_no_reward();
		scan_block.m_carrotOutputs = parent->m_carrotOutputs;

		++scan_block.m_txinGenHeight;
		check_no_reward();
		scan_block.m_txinGenHeight = parent->m_txinGenHeight;

		scan_block.m_txkeySec.h[0] ^= 1;
		check_no_reward();
		scan_block.m_txkeySec = parent->m_txkeySec;

		scan_block.m_carrotOutputs.clear();
		check_no_reward();
	}

	MinerData data{};

	data.major_version = parent->m_majorVersion;
	data.height = parent->m_txinGenHeight;
	data.prev_id = parent->m_prevId;
	data.difficulty = sidechain.m_testMainChainDiff;
	data.median_weight = 300000;
	data.already_generated_coins = 18204981557254756780ULL;
	data.median_timestamp = parent->m_timestamp;
	data.fcmp_pp_n_tree_layers = parent->m_fcmp_pp_n_tree_layers;
	data.fcmp_pp_tree_root = parent->m_fcmp_pp_tree_root;

	Mempool mempool;

	Params params;
	params.m_miningWallet = parent->m_minerWallet;

	BlockTemplate tpl(&sidechain, nullptr);

	tpl.rng().seed(123);
	tpl.update(data, mempool, params);

	const PoolBlock* b = tpl.pool_block_template();
	ASSERT_TRUE(b->m_transactions.empty());

	const P2PServer::Broadcast broadcast(*b, parent);

	ASSERT_TRUE(broadcast.compact_blob.empty());
	ASSERT_TRUE(broadcast.compact_unpruned_blob.empty());

	for (bool pruned : {false, true}) {
		const auto& wire = pruned ? broadcast.pruned_blob : broadcast.blob;

		ASSERT_EQ(decoded.deserialize(wire.data(), wire.size(), sidechain, false, pruned), 0);
		ASSERT_EQ(decoded.m_sidechainId, b->m_sidechainId);
		ASSERT_EQ(decoded.serialize_mainchain_data(), b->serialize_mainchain_data());
		ASSERT_EQ(decoded.serialize_sidechain_data(), b->serialize_sidechain_data());
	}
}

struct ParentNonceTestHasher : RandomX_Hasher_Base
{
	uint32_t calls = 0;
	bool available = true;
	bool valid = true;
	uint64_t height = 0;
	hash seed;
	std::vector<uint8_t> blob;

	bool calculate(const void* data, size_t size, uint64_t h, const hash& s, hash& result, bool, size_t lane) override
	{
		++calls;
		height = h;
		seed = s;
		const auto* p = static_cast<const uint8_t*>(data);
		blob.assign(p, p + size);
		EXPECT_EQ(lane, size_t(VM_LANE_P2P));
		if (!available) return false;
		keccak(p, static_cast<int>(size), result.h);
		// Deterministic stand-in for mined solutions, comfortably below the test difficulty target.
		memset(result.h + HASH_SIZE - 4, 0, 4);
		if (!valid) memset(result.h, 0xFF, HASH_SIZE);
		return true;
	}
};

TEST(pool_block, duplicate_pow_solutions)
{
	thread_pool_init();
	init_crypto_cache();

	auto cleanup = ScopeGuard{[]() {
		thread_pool_destroy();
		destroy_crypto_cache();
#ifdef WITH_INDEXED_HASHES
		indexed_hash::cleanup_storage();
#endif
	}};

	SideChain sidechain(nullptr, NetworkType::Testnet, "default");
	sidechain.m_testMainChainDiff = difficulty_type(1000000000000ULL);
	ParentNonceTestHasher hasher;
	sidechain.m_testHasher = &hasher;
	BlockTemplate tpl(&sidechain, nullptr);
	Mempool mempool;
	Params params;
	params.m_miningWallet = Wallet("4B4aCvEcZr6GcusVJfEds2LXixCeJ2dQBaDUCguWmzi5L7PW5tVXfAnE4cn1mQdiNzH6zWcEPMQTiYTsNcX44ryxCJWZKZH");
	MinerData data{};
	data.major_version = HARDFORK_VERSION_CARROT;
	data.height = 3102800;
	data.prev_id = H("81a0260b29d5224e88d04b11faff321fbdc11c4570779386b2a1817a86dc622c");
	data.seed_hash = keccak("duplicate PoW seed");
	data.difficulty = sidechain.m_testMainChainDiff;
	data.median_weight = 300000;
	data.already_generated_coins = 18204981557254756780ULL;
	data.median_timestamp = 1780000000;
	tpl.update(data, mempool, params);

	const PoolBlock& block = *tpl.pool_block_template();
	const auto side = block.serialize_sidechain_data();
	PoolBlock variants[2];
	for (uint32_t i = 0; i < 2; ++i) {
		const uint32_t nonce = 42 + i;
		auto wire = block.serialize_mainchain_data(nullptr, &nonce);
		wire.insert(wire.end(), side.begin(), side.end());
		ASSERT_EQ(variants[i].deserialize(wire.data(), wire.size(), sidechain, false, false), 0);
		variants[i].m_seed = data.seed_hash;
		ASSERT_TRUE(variants[i].get_pow_hash(&hasher, data.height, data.seed_hash, variants[i].m_powHash, false, RandomX_Hasher_Base::VM_LANE_P2P));
		ASSERT_TRUE(variants[i].m_difficulty.check_pow(variants[i].m_powHash));
		ASSERT_FALSE(sidechain.incoming_block_seen(variants[i]));
	}
	ASSERT_EQ(variants[0].m_sidechainId, variants[1].m_sidechainId);
	ASSERT_NE(variants[0].m_powHash, variants[1].m_powHash);

	// Reproduce both external workers passing the initial lookup before either inserts its solution.
	std::atomic<uint32_t> ready{0};
	bool initially_missing[2] = {};
	bool accepted[2] = {};
	std::thread workers[2];
	for (uint32_t i = 0; i < 2; ++i) {
		workers[i] = std::thread([&, i]() {
			initially_missing[i] = !sidechain.find_block(variants[i].m_sidechainId);
			ready.fetch_add(1);
			while (ready.load() != 2) std::this_thread::yield();
			accepted[i] = sidechain.add_block(variants[i], true);
		});
	}
	for (auto& worker : workers) worker.join();
	ASSERT_TRUE(initially_missing[0]);
	ASSERT_TRUE(initially_missing[1]);
	ASSERT_TRUE(accepted[0]);
	ASSERT_TRUE(accepted[1]);
	ASSERT_EQ(sidechain.blocksById().size(), 1U);

	const PoolBlock* stored = sidechain.chainTip();
	ASSERT_NE(stored, nullptr);
	ASSERT_TRUE(stored->m_verified);
	ASSERT_FALSE(stored->m_invalid);
	ASSERT_GE(stored->m_nonce, 42U);
	ASSERT_LE(stored->m_nonce, 43U);
	const PoolBlock& winner = variants[stored->m_nonce - 42];
	EXPECT_EQ(stored->m_powHash, winner.m_powHash);
	EXPECT_EQ(stored->m_cumulativeDifficulty, winner.m_cumulativeDifficulty);

	// A later external duplicate succeeds without replacing the first stored solution.
	std::vector<hash> missing_blocks;
	ASSERT_TRUE(sidechain.add_external_block(variants[43 - stored->m_nonce], missing_blocks));
	EXPECT_TRUE(missing_blocks.empty());
	EXPECT_EQ(sidechain.chainTip(), stored);

	// Local submissions from both current and old templates must still reject another nonce for this ID.
	for (uint32_t nonce : { 44U, 45U }) {
		std::vector<uint8_t> blob;
		hash coinbase_hash, pow_hash;
		ASSERT_TRUE(winner.get_hashing_blob(blob, coinbase_hash, &nonce));
		ASSERT_TRUE(hasher.calculate(blob.data(), blob.size(), data.height, data.seed_hash, pow_hash, false, RandomX_Hasher_Base::VM_LANE_P2P));
		ASSERT_TRUE(winner.m_difficulty.check_pow(pow_hash));
		ASSERT_FALSE(tpl.submit_sidechain_block(1, nonce, 0, pow_hash));
		if (nonce == 44) tpl.update(data, mempool, params);
	}
	EXPECT_EQ(sidechain.blocksById().size(), 1U);
	EXPECT_EQ(tpl.pool_block_template()->m_parentNonce, winner.m_nonce);
	EXPECT_EQ(tpl.pool_block_template()->m_parentPowHash, winner.m_powHash);
}

TEST(pool_block, carrot_parent_nonce)
{
	thread_pool_init();
	init_crypto_cache();

	auto cleanup = ScopeGuard{[]() {
		thread_pool_destroy();
		destroy_crypto_cache();
#ifdef WITH_INDEXED_HASHES
		indexed_hash::cleanup_storage();
#endif
	}};

	const Wallet wallets[] = {
		Wallet("4B4aCvEcZr6GcusVJfEds2LXixCeJ2dQBaDUCguWmzi5L7PW5tVXfAnE4cn1mQdiNzH6zWcEPMQTiYTsNcX44ryxCJWZKZH"),
		Wallet("43VbH7CQCJqhH1d327TBenCs9hFN3zvcgX5YZdGyJfEE5rabasAtKhyPsKmbYSU9AmMReACZrz9j5U2Ba6WXWoQpVi38AJn"),
		Wallet("46r3PD45TYH9jVf8sEejW9JdK1EgNe6BeYLdGyJTU1MRctoevAHXpzSjBMJhdkLirGXwiWdZejSRZ8MZP72artSD17LprKY"),
	};

	const struct {
		const char* name;
		bool legacy, change_nonce, change_extra, valid, available, late_parent;
	} cases[] = {
		{ "cached", false, false, false, true, true, false },
		{ "other nonce", false, true, false, true, true, false },
		{ "insufficient parent PoW", false, true, false, false, true, false },
		{ "hasher unavailable", false, true, false, true, false, false },
		{ "legacy parent", true, false, false, true, true, false },
		{ "legacy extra nonce", true, false, true, true, true, false },
		{ "parent arrives later", false, true, false, true, true, true },
	};

	for (const auto& test : cases) {
		SCOPED_TRACE(test.name);
		SideChain source(nullptr, NetworkType::Testnet, "default");
		SideChain target(nullptr, NetworkType::Testnet, "default");
		source.m_testMainChainDiff = target.m_testMainChainDiff = difficulty_type(1000000000000ULL);
		ParentNonceTestHasher hasher;
		target.m_testHasher = &hasher;
		BlockTemplate tpl(&source, nullptr);
		tpl.rng().seed(123);
		Mempool mempool;
		Params params;
		MinerData data{};
		data.major_version = test.legacy ? (HARDFORK_VERSION_CARROT - 1) : HARDFORK_VERSION_CARROT;
		data.height = test.legacy ? 2762973 : 3102800;
		data.prev_id = H("81a0260b29d5224e88d04b11faff321fbdc11c4570779386b2a1817a86dc622c");
		data.seed_hash = keccak("parent RandomX seed");
		data.difficulty = source.m_testMainChainDiff;
		data.median_weight = 300000;
		data.already_generated_coins = 18204981557254756780ULL;
		data.median_timestamp = 1780000000;

		PoolBlock delayed_parent;
		for (uint32_t i = 0; i < 3; ++i) {
			params.m_miningWallet = wallets[i];
			tpl.update(data, mempool, params);
			PoolBlock mined(*tpl.pool_block_template());
			mined.m_nonce = 42 + i;
			ASSERT_TRUE(mined.get_pow_hash(&hasher, data.height, data.seed_hash, mined.m_powHash, false, RandomX_Hasher_Base::VM_LANE_P2P));
			ASSERT_TRUE(mined.m_difficulty.check_pow(mined.m_powHash));
			ASSERT_TRUE(tpl.submit_sidechain_block(i + 1, mined.m_nonce, 0, mined.m_powHash));
			ASSERT_EQ(source.chainTip()->m_seed, data.seed_hash);

			const uint32_t nonce = mined.m_nonce + ((i == 2 && test.change_nonce) ? 1 : 0);
			const uint32_t extra_nonce = (i == 2 && test.change_extra) ? 1 : 0;
			auto wire = mined.serialize_mainchain_data(nullptr, &nonce, &extra_nonce);
			const auto side = mined.serialize_sidechain_data();
			wire.insert(wire.end(), side.begin(), side.end());
			PoolBlock received;
			ASSERT_EQ(received.deserialize(wire.data(), wire.size(), target, false, false), 0);
			ASSERT_EQ(received.m_sidechainId, mined.m_sidechainId);
			received.m_seed = data.seed_hash;
			ASSERT_TRUE(received.get_pow_hash(&hasher, data.height, data.seed_hash, received.m_powHash, false, RandomX_Hasher_Base::VM_LANE_P2P));
			if ((i == 2) && test.late_parent) {
				delayed_parent = received;
			}
			else {
				ASSERT_TRUE(target.add_block(received));
			}
			ASSERT_TRUE(target.chainTip()->m_verified);
			ASSERT_FALSE(target.chainTip()->m_invalid);
			data.median_timestamp += source.block_time();
		}

		const PoolBlock* parent = source.chainTip();
		const PoolBlock* stored_parent = test.late_parent ? &delayed_parent : target.chainTip();
		const auto parent_main = stored_parent->serialize_mainchain_data();
		const auto parent_blob = stored_parent->m_hashingBlob;
		const hash parent_coinbase = stored_parent->m_coinbase_tx_hash;
		const hash parent_pow = stored_parent->m_powHash;

		data.major_version = HARDFORK_VERSION_CARROT;
		data.height = 3102801;
		data.prev_id.h[0] ^= 1;
		data.seed_hash = keccak("child RandomX seed");
		tpl.update(data, mempool, params);
		const PoolBlock& child = *tpl.pool_block_template();
		ASSERT_EQ(child.m_parentNonce, parent->m_nonce);
		ASSERT_EQ(child.m_parentPowHash, parent->m_powHash);
		ASSERT_EQ(child.m_carrotOutputs.size(), 3U);
		const P2PServer::Broadcast broadcast(child, parent);

		PoolBlock decoded;
		const uint32_t calls = hasher.calls;
		const bool different = test.change_nonce || test.change_extra;
		const int pruned_result = decoded.deserialize(broadcast.pruned_blob.data(), broadcast.pruned_blob.size(), target, false, true);
		if (test.late_parent) {
			ASSERT_NE(pruned_result, 0);
		}
		else {
			ASSERT_EQ(pruned_result, different ? static_cast<int>(PoolBlock::DeserializeStatus::NEEDS_PARENT_POW) : 0);
		}
		ASSERT_EQ(hasher.calls, calls); // Deserialization must never calculate RandomX.

		// The serialized parent nonce is committed by the child's sidechain ID.
		auto changed = broadcast.blob;
		changed[child.serialize_mainchain_data().size() + HASH_SIZE * 4] ^= 1;
		ASSERT_NE(decoded.deserialize(changed.data(), changed.size(), target, false, false), 0);
		ASSERT_EQ(decoded.deserialize(broadcast.blob.data(), broadcast.blob.size(), target, false, false), 0);
		decoded.m_seed = data.seed_hash;
		ASSERT_TRUE(decoded.get_pow_hash(&hasher, data.height, data.seed_hash, decoded.m_powHash, false, RandomX_Hasher_Base::VM_LANE_P2P));
		ASSERT_TRUE(decoded.m_difficulty.check_pow(decoded.m_powHash));

		hasher.calls = 0;
		hasher.valid = test.valid;
		hasher.available = test.available;
		if (!test.valid) decoded.m_outputsComputed = true; // Must not bypass the parent proof check.
		ASSERT_TRUE(target.add_block(decoded));
		const PoolBlock* checked = target.find_block(child.m_sidechainId);
		ASSERT_NE(checked, nullptr);
		if (test.late_parent) {
			ASSERT_FALSE(checked->m_verified);
			ASSERT_EQ(hasher.calls, 0U);
			ASSERT_TRUE(target.add_block(delayed_parent));
			stored_parent = target.find_block(parent->m_sidechainId);
			ASSERT_NE(stored_parent, nullptr);
		}
		EXPECT_EQ(checked->m_verified, test.available);
		EXPECT_EQ(checked->m_invalid, !test.valid);
		EXPECT_EQ(hasher.calls, different ? 1U : 0U);
		if (different) {
			EXPECT_EQ(hasher.height, parent->m_txinGenHeight);
			EXPECT_EQ(hasher.seed, parent->m_seed);
			std::vector<uint8_t> expected_blob;
			hash coinbase_hash;
			ASSERT_TRUE(parent->get_hashing_blob(expected_blob, coinbase_hash));
			EXPECT_EQ(hasher.blob, expected_blob);
		}
		EXPECT_EQ(stored_parent->serialize_mainchain_data(), parent_main);
		EXPECT_EQ(stored_parent->m_hashingBlob, parent_blob);
		EXPECT_EQ(stored_parent->m_coinbase_tx_hash, parent_coinbase);
		EXPECT_EQ(stored_parent->m_powHash, parent_pow);

		if (test.valid && test.available) {
			ASSERT_TRUE(checked->m_parentPowHashValid);
			EXPECT_EQ(checked->m_parentPowHash, parent->m_powHash);
			EXPECT_EQ(checked->serialize_mainchain_data(), child.serialize_mainchain_data());
			// A known child can subsequently be reconstructed even when the local parent nonce differs.
			ASSERT_EQ(decoded.deserialize(broadcast.pruned_blob.data(), broadcast.pruned_blob.size(), target, false, true), 0);
			EXPECT_EQ(decoded.serialize_mainchain_data(), child.serialize_mainchain_data());
		}
	}
}

TEST(pool_block, cached_shares)
{
	thread_pool_init();
	init_crypto_cache();

	auto cleanup = ScopeGuard{[]() {
		thread_pool_destroy();
		destroy_crypto_cache();
#ifdef WITH_INDEXED_HASHES
		indexed_hash::cleanup_storage();
#endif
	}};

	// Same as in side_chain.cpp
	constexpr uint64_t UNCLE_BLOCK_DEPTH = 3;

	const Wallet wallets[] = {
		Wallet("4B4aCvEcZr6GcusVJfEds2LXixCeJ2dQBaDUCguWmzi5L7PW5tVXfAnE4cn1mQdiNzH6zWcEPMQTiYTsNcX44ryxCJWZKZH"),
		Wallet("43VbH7CQCJqhH1d327TBenCs9hFN3zvcgX5YZdGyJfEE5rabasAtKhyPsKmbYSU9AmMReACZrz9j5U2Ba6WXWoQpVi38AJn"),
		Wallet("46r3PD45TYH9jVf8sEejW9JdK1EgNe6BeYLdGyJTU1MRctoevAHXpzSjBMJhdkLirGXwiWdZejSRZ8MZP72artSD17LprKY"),
	};

	// The same wallet objects (the blocks' own), weights, order and truncation
	auto same_window = [](const PPLNSWindow& a, const PPLNSWindow& b) {
		if ((a.size() != b.size()) || (a.m_weightTruncated != b.m_weightTruncated)) {
			return false;
		}
		for (size_t i = 0; i < a.size(); ++i) {
			if ((a.m_shares[i].m_weight != b.m_shares[i].m_weight) || (a.m_shares[i].m_wallet != b.m_shares[i].m_wallet)) {
				return false;
			}
		}
		return true;
	};

	const struct {
		const char* name;
		uint8_t major_version;
		uint64_t height;
		bool cached;
		uint64_t mainchain_diff;
	} cases[] = {
		{ "Carrot", HARDFORK_VERSION_CARROT, 3102800, true, 1000000000000ULL },
		// Max PPLNS weight is 2x Monero difficulty, so the window is cut after 4 blocks with the minimum difficulty (100000)
		{ "Carrot, window cut by weight", HARDFORK_VERSION_CARROT, 3102800, true, 150000 },
		// The next Monero block is Carrot (testnet), so the first Carrot blocks will take these blocks' windows
		{ "last pre-Carrot Monero block", HARDFORK_VERSION_CARROT - 1, 3102799, true, 1000000000000ULL },
		{ "pre-Carrot", HARDFORK_VERSION_CARROT - 1, 2762973, false, 1000000000000ULL },
	};

	for (const auto& test : cases) {
		SCOPED_TRACE(test.name);

		SideChain sidechain(nullptr, NetworkType::Testnet, "default");
		sidechain.m_testMainChainDiff = difficulty_type(test.mainchain_diff);

		ParentNonceTestHasher hasher;
		BlockTemplate tpl(&sidechain, nullptr);
		tpl.rng().seed(123);

		Mempool mempool;
		Params params;

		MinerData data{};
		data.major_version = test.major_version;
		data.height = test.height;
		data.prev_id = H("81a0260b29d5224e88d04b11faff321fbdc11c4570779386b2a1817a86dc622c");
		data.seed_hash = keccak("cached shares seed");
		data.difficulty = difficulty_type(1000000000000ULL);
		data.median_weight = 300000;
		data.already_generated_coins = 18204981557254756780ULL;
		data.median_timestamp = 1780000000;

		auto check_template = [&](const PoolBlock* tip) {
			PPLNSWindow fresh;
			uint64_t bottom_height = 0;
			ASSERT_TRUE(sidechain.test_get_shares(tip, fresh, &bottom_height));
			EXPECT_TRUE(same_window(tpl.get_payout_window(), fresh));
			EXPECT_EQ(tpl.get_payout_window().m_powHash, tip->m_powHash);
			EXPECT_EQ(tpl.get_bottom_height(), bottom_height);
		};

		std::vector<const PoolBlock*> chain;

		for (uint32_t i = 0; i < 8; ++i) {
			SCOPED_TRACE(i);

			params.m_miningWallet = wallets[i % 3];
			tpl.update(data, mempool, params);

			// A Carrot template takes the window of the tip it's built on
			if (!chain.empty() && (test.major_version >= HARDFORK_VERSION_CARROT)) {
				check_template(chain.back());
			}

			// The template is not a side-chain block, so it never gets a cached window
			EXPECT_TRUE(tpl.pool_block_template()->m_cachedShares.empty());

			PoolBlock mined(*tpl.pool_block_template());
			mined.m_nonce = 42 + i;
			ASSERT_TRUE(mined.get_pow_hash(&hasher, data.height, data.seed_hash, mined.m_powHash, false, RandomX_Hasher_Base::VM_LANE_P2P));
			ASSERT_TRUE(mined.m_difficulty.check_pow(mined.m_powHash));
			ASSERT_TRUE(tpl.submit_sidechain_block(i + 1, mined.m_nonce, 0, mined.m_powHash));
			EXPECT_TRUE(tpl.pool_block_template()->m_cachedShares.empty());

			const PoolBlock* tip = sidechain.chainTip();
			ASSERT_NE(tip, nullptr);
			ASSERT_EQ(tip->m_sidechainHeight, i);
			ASSERT_EQ(tip->m_majorVersion, test.major_version);
			chain.push_back(tip);

			// The tip and up to UNCLE_BLOCK_DEPTH blocks below it have exactly what get_shares() calculates, deeper blocks have nothing
			for (const PoolBlock* b : chain) {
				SCOPED_TRACE(b->m_sidechainHeight);

				const bool expected = test.cached && (b->m_sidechainHeight + UNCLE_BLOCK_DEPTH >= tip->m_sidechainHeight);
				ASSERT_EQ(!b->m_cachedShares.empty(), expected);

				if (expected) {
					PPLNSWindow fresh;
					uint64_t bottom_height = 0;
					ASSERT_TRUE(sidechain.test_get_shares(b, fresh, &bottom_height));
					EXPECT_TRUE(same_window(b->m_cachedShares, fresh));
					EXPECT_EQ(b->m_cachedShares.m_powHash, b->m_powHash);
					EXPECT_EQ(b->m_cachedSharesBottomHeight, bottom_height);
				}
				else {
					EXPECT_EQ(b->m_cachedSharesBottomHeight, 0U);
				}
			}

			EXPECT_EQ(sidechain.test_cached_shares_blocks(), test.cached ? std::min<size_t>(i + 1, UNCLE_BLOCK_DEPTH + 1) : 0U);

			// Copies (block templates, incoming blocks) never get a cached window from the block they copy
			PoolBlock with_cache(*tip);
			with_cache.m_cachedShares.m_shares.emplace_back(tip->m_difficulty, &tip->m_minerWallet);
			with_cache.m_cachedSharesBottomHeight = 1;

			const PoolBlock copy(with_cache);
			EXPECT_TRUE(copy.m_cachedShares.empty());
			EXPECT_EQ(copy.m_cachedSharesBottomHeight, 0U);

			PoolBlock assigned;
			assigned.m_cachedShares = with_cache.m_cachedShares;
			assigned.m_cachedSharesBottomHeight = 1;
			assigned = with_cache;
			EXPECT_TRUE(assigned.m_cachedShares.empty());
			EXPECT_EQ(assigned.m_cachedSharesBottomHeight, 0U);

			with_cache.reset_offchain_data();
			EXPECT_TRUE(with_cache.m_cachedShares.empty());
			EXPECT_EQ(with_cache.m_cachedSharesBottomHeight, 0U);

			data.median_timestamp += sidechain.block_time();
		}

		// Otherwise the bottom height and m_weightTruncated of the cached windows wouldn't be tested
		if (test.mainchain_diff < 1000000) {
			EXPECT_TRUE(chain.back()->m_cachedShares.m_weightTruncated);
			EXPECT_GT(chain.back()->m_cachedSharesBottomHeight, 0U);
		}

		// The first Carrot template after the fork takes the window of the last pre-Carrot tip
		if (test.cached && (test.major_version < HARDFORK_VERSION_CARROT)) {
			data.major_version = HARDFORK_VERSION_CARROT;
			data.height = test.height + 1;
			data.prev_id.h[0] ^= 1;
			tpl.update(data, mempool, params);

			check_template(chain.back());
		}
	}
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
		{ "default", "sidechain_dump.dat", 3456189, 11704382, 53, false, H("5c8a0b2459abf27ec062bf5baa0539511bd0a7ffc3ec585a1bd7a8bb5cf84c37") },
		{ "default", "sidechain_dump.dat", 3456189, 11704382, 53, true, H("5c8a0b2459abf27ec062bf5baa0539511bd0a7ffc3ec585a1bd7a8bb5cf84c37") },
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

			uint32_t n;

			memcpy(&n, p, sizeof(uint32_t));
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

		PPLNSWindow window;

		ASSERT_TRUE(sidechain.fill_sidechain_data(block, window));

		ASSERT_EQ(block.m_sidechainHeight, t.m_sidechainHeight + 1);
		ASSERT_EQ(window.size(), t.m_expectedSharesNextBlock);

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
