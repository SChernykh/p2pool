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

	ASSERT_EQ(mainchain_data.size(), 1757U);
	ASSERT_EQ(header_size, 43U);
	ASSERT_EQ(miner_tx_size, 1457U);
	ASSERT_EQ(outputs_offset, 54);
	ASSERT_EQ(outputs_blob_size, 1371);

	ASSERT_EQ(b.m_majorVersion, 16U);
	ASSERT_EQ(b.m_minorVersion, 16U);
	ASSERT_EQ(b.m_timestamp, 1679221824U);
	ASSERT_EQ(b.m_nonce, 1247U);
	ASSERT_EQ(b.m_txinGenHeight, 2845298U);
	ASSERT_EQ(b.m_outputs.size(), 35U);
	ASSERT_EQ(b.m_extraNonceSize, 4U);
	ASSERT_EQ(b.m_extraNonce, 1482827308U);
	ASSERT_EQ(b.m_transactions.size(), 9U);
	ASSERT_EQ(b.m_uncles.size(), 0U);
	ASSERT_EQ(b.m_sidechainHeight, 4674483U);
	ASSERT_EQ(b.m_difficulty.lo, 1854596983U);
	ASSERT_EQ(b.m_difficulty.hi, 0U);
	ASSERT_EQ(b.m_cumulativeDifficulty.lo, 7172845253120126ull);
	ASSERT_EQ(b.m_cumulativeDifficulty.hi, 0U);
	ASSERT_EQ(b.m_depth, 0U);
	ASSERT_EQ(b.m_verified, false);
	ASSERT_EQ(b.m_invalid, false);
	ASSERT_EQ(b.m_broadcasted, false);
	ASSERT_EQ(b.m_wantBroadcast, false);

	class RandomX_Hasher_Test : public RandomX_Hasher_Base
	{
	public:
		bool calculate(const void* data, size_t size, uint64_t, const hash&, hash& result, bool /*force_light_mode*/) override
		{
			if (size == 76) {
				char buf[76 * 2 + 1];
				{
					log::Stream s(buf);
					s << log::hex_buf(reinterpret_cast<const uint8_t*>(data), size);
					buf[76 * 2] = '\0';
				}
				const char ref[] = "1010c0c8dba006b78e04571806733a74ef1014f404484d3358bfca889a75bb0fe9aff64a41c92bdf040000ecf0a11f83c6eced7d7cdfbdcd5a193f64d334b2c5491a9c595b4527e531ae7209";
				if (memcmp(buf, ref, sizeof(buf)) == 0) {
					std::stringstream s;
					s << "aa7a3c4a2d67cb6a728e244288219bf038024f3b511b0da197a19ec601000000";
					s >> result;
					return true;
				}
			}
			return false;
		}
	} hasher;

	hash seed, pow_hash;
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
		bool m_shuffle;
	} tests[2] = {
		{ "default", "sidechain_dump.dat", 2870010, 4957203, true },
		{ "mini", "sidechain_dump_mini.dat", 2870010, 4414446, false },
	};

	for (const STest& t : tests)
	{
		SideChain sidechain(nullptr, NetworkType::Mainnet, t.m_poolName);

		// Difficulty of block 2869248
		sidechain.m_testMainChainDiff = difficulty_type(345786476185ULL, 0ULL);

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
