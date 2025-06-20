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
#include "pool_block.h"
#include "pow_hash.h"
#include "side_chain.h"
#include "gtest/gtest.h"
#include <fstream>

namespace p2pool {

TEST(pool_block, deserialize)
{
	init_crypto_cache();

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

	ASSERT_EQ(b.deserialize(buf.data(), buf.size(), sidechain, nullptr, false), 0);

	size_t header_size, miner_tx_size;
	int outputs_offset, outputs_blob_size;
	const std::vector<uint8_t> mainchain_data = b.serialize_mainchain_data(&header_size, &miner_tx_size, &outputs_offset, &outputs_blob_size);

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
	ASSERT_EQ(b.m_outputs.size(), 27U);
	ASSERT_EQ(b.m_extraNonceSize, 4U);
	ASSERT_EQ(b.m_extraNonce, 2983923783U);
	ASSERT_EQ(b.m_transactions.size(), 21U);
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

	hash seed;
	{
		std::stringstream s;
		s << "bf513dbe52c22b09e65edae222ec902d6adb75585a0141b81a165f0fb0c9c0bc";
		s >> seed;
	}

	RandomX_Hasher hasher(nullptr);
	hasher.set_seed(seed);

	hash pow_hash;
	ASSERT_EQ(b.get_pow_hash(&hasher, 0, seed, pow_hash), true);

	std::stringstream s;
	s << pow_hash;
	ASSERT_EQ(s.str(), "0906c001cc0900098fe1b62593f8ba52bd1ae2a0806096aa361a9f1702000000");

	ASSERT_EQ(b.m_difficulty.check_pow(pow_hash), true);

	destroy_crypto_cache();
}

TEST(pool_block, verify)
{
	init_crypto_cache();

	struct STest
	{
		const char* m_poolName;
		const char* m_fileName;
		uint64_t m_txinGenHeight;
		uint64_t m_sidechainHeight;
		bool m_shuffle;
	} tests[4] = {
		{ "default", "sidechain_dump.dat", 3258121, 9443762, false },
		{ "default", "sidechain_dump.dat", 3258121, 9443762, true },
		{ "mini", "sidechain_dump_mini.dat", 3258121, 8912067, false },
		{ "mini", "sidechain_dump_mini.dat", 3258121, 8912067, true },
	};

	for (const STest& t : tests)
	{
		SideChain sidechain(nullptr, NetworkType::Mainnet, t.m_poolName);

		// Difficulty of block 3256320
		sidechain.m_testMainChainDiff = difficulty_type(374140388237ULL, 0ULL);

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
			ASSERT_EQ(b->deserialize(p, n, sidechain, nullptr, false), 0);
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
	}

	destroy_crypto_cache();
}

}
