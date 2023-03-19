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

	ASSERT_EQ(mainchain_data.size(), 1757);
	ASSERT_EQ(header_size, 43);
	ASSERT_EQ(miner_tx_size, 1457);
	ASSERT_EQ(outputs_offset, 54);
	ASSERT_EQ(outputs_blob_size, 1371);

	ASSERT_EQ(b.m_majorVersion, 16);
	ASSERT_EQ(b.m_minorVersion, 16);
	ASSERT_EQ(b.m_timestamp, 1679221824);
	ASSERT_EQ(b.m_nonce, 1247);
	ASSERT_EQ(b.m_txinGenHeight, 2845298);
	ASSERT_EQ(b.m_outputs.size(), 35);
	ASSERT_EQ(b.m_extraNonceSize, 4);
	ASSERT_EQ(b.m_extraNonce, 1482827308);
	ASSERT_EQ(b.m_transactions.size(), 9);
	ASSERT_EQ(b.m_uncles.size(), 0);
	ASSERT_EQ(b.m_sidechainHeight, 4674483);
	ASSERT_EQ(b.m_difficulty.lo, 1854596983);
	ASSERT_EQ(b.m_difficulty.hi, 0);
	ASSERT_EQ(b.m_cumulativeDifficulty.lo, 7172845253120126ull);
	ASSERT_EQ(b.m_cumulativeDifficulty.hi, 0);
	ASSERT_EQ(b.m_depth, 0);
	ASSERT_EQ(b.m_verified, false);
	ASSERT_EQ(b.m_invalid, false);
	ASSERT_EQ(b.m_broadcasted, false);
	ASSERT_EQ(b.m_wantBroadcast, false);

	RandomX_Hasher hasher(nullptr);

	hash seed;
	{
		std::stringstream s;
		s << "6fc9c4a55eb513eb31955c084d9342e0082987f9e42da042449b7c9001176d3a";
		s >> seed;
	}

	hasher.set_seed(seed);

	hash pow_hash;
	ASSERT_EQ(b.get_pow_hash(&hasher, 0, seed, pow_hash), true);

	std::stringstream s;
	s << pow_hash;
	ASSERT_EQ(s.str(), "aa7a3c4a2d67cb6a728e244288219bf038024f3b511b0da197a19ec601000000");

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
	} tests[2] = {
		{ "default", "sidechain_dump.dat", 2845288, 4674368 },
		{ "mini", "sidechain_dump_mini.dat", 2845293, 4129185 },
	};

	for (const STest& t : tests)
	{
		PoolBlock b;
		SideChain sidechain(nullptr, NetworkType::Mainnet, t.m_poolName);

		// Difficulty of block 2844672
		sidechain.m_testMainChainDiff = difficulty_type(321967641416ULL, 0ULL);

		std::ifstream f(t.m_fileName, std::ios::binary | std::ios::ate);
		ASSERT_EQ(f.good() && f.is_open(), true);

		std::vector<uint8_t> buf(f.tellg());
		f.seekg(0);
		f.read(reinterpret_cast<char*>(buf.data()), buf.size());
		ASSERT_EQ(f.good(), true);

		for (const uint8_t *p = buf.data(), *e = buf.data() + buf.size(); p < e;) {
			ASSERT_TRUE(p + sizeof(uint32_t) <= e);
			const uint32_t n = *reinterpret_cast<const uint32_t*>(p);
			p += sizeof(uint32_t);

			ASSERT_TRUE(p + n <= e);
			ASSERT_EQ(b.deserialize(p, n, sidechain, nullptr, false), 0);
			p += n;

			sidechain.add_block(b);
			ASSERT_TRUE(sidechain.find_block(b.m_sidechainId) != nullptr);
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
