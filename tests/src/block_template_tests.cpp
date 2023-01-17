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
#include "block_template.h"
#include "mempool.h"
#include "side_chain.h"
#include "wallet.h"
#include "keccak.h"
#include "gtest/gtest.h"

namespace p2pool {

TEST(block_template, update)
{
	init_crypto_cache();

	SideChain sidechain(nullptr, NetworkType::Mainnet);
	BlockTemplate tpl(&sidechain, nullptr);
	tpl.rng().seed(123);

	auto H = [](const char* s)
	{
		std::stringstream ss;
		ss << s;
		hash result;
		ss >> result;
		return result;
	};

	MinerData data;
	data.major_version = 16;
	data.height = 2762973;
	data.prev_id = H("81a0260b29d5224e88d04b11faff321fbdc11c4570779386b2a1817a86dc622c");
	data.seed_hash = H("33d0fb381466f04d6a1919ced3b698f54a28add3da5a6479b096c67df7a4974c");
	data.difficulty = { 300346053753ULL, 0 };
	data.median_weight = 300000;
	data.already_generated_coins = 18204981557254756780ULL;
	data.median_timestamp = (1ULL << 35) - 2;

	Mempool mempool;
	Wallet wallet("44MnN1f3Eto8DZYUWuE5XZNUtE3vcRzt2j6PzqWpPau34e6Cf4fAxt6X2MBmrm6F9YMEiMNjN6W4Shn4pLcfNAja621jwyg");

	// Test 1: empty template
	tpl.update(data, mempool, &wallet);

	const PoolBlock* b = tpl.pool_block_template();
	ASSERT_EQ(b->m_sidechainId, H("16d6a5c45d452288fcc439e5a258e8230798dfb6bbfd32220303efe932061aa9"));

	std::vector<uint8_t> blobs;
	uint64_t height;
	difficulty_type diff, sidechain_diff;
	hash seed_hash;
	size_t nonce_offset;
	uint32_t template_id;
	tpl.get_hashing_blobs(0, 10000, blobs, height, diff, sidechain_diff, seed_hash, nonce_offset, template_id);

	ASSERT_EQ(height, 2762973);
	ASSERT_EQ(diff, 300346053753ULL);
	ASSERT_EQ(sidechain_diff, sidechain.difficulty());
	ASSERT_EQ(seed_hash, data.seed_hash);
	ASSERT_EQ(nonce_offset, 39);
	ASSERT_EQ(template_id, 1);

	hash blobs_hash;
	keccak(blobs.data(), static_cast<int>(blobs.size()), blobs_hash.h);
	ASSERT_EQ(blobs_hash, H("27bd8678420c8a0948f71c71356252be790899d61f14e35b2d0440a30d730f4c"));

	// Test 2: mempool with high fee and low fee transactions, it must choose high fee transactions
	for (uint64_t i = 0; i < 512; ++i) {
		TxMempoolData tx;
		*reinterpret_cast<uint64_t*>(tx.id.h) = i;
		tx.fee = (i < 256) ? 30000000 : 60000000;
		tx.weight = 1500;
		mempool.add(tx);
	}

	tpl.update(data, mempool, &wallet);

	for (size_t i = 1; i < b->m_transactions.size(); ++i) {
		ASSERT_GE(*reinterpret_cast<const uint64_t*>(b->m_transactions[i].h), 256);
	}

	destroy_crypto_cache();
}

}
