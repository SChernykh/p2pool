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
	ASSERT_EQ(tpl.get_reward(), 600000000000ULL);

	const PoolBlock* b = tpl.pool_block_template();
	ASSERT_EQ(b->m_sidechainId, H("2c90c1926a75c81afd49bf4a4b63e9de7b4c153866411c47e7af864b547c23ec"));

	std::vector<uint8_t> blobs;
	uint64_t height;
	difficulty_type diff, aux_diff, sidechain_diff;
	hash seed_hash;
	size_t nonce_offset;
	uint32_t template_id;
	tpl.get_hashing_blobs(0, 1000, blobs, height, diff, aux_diff, sidechain_diff, seed_hash, nonce_offset, template_id);

	ASSERT_EQ(height, 2762973);
	ASSERT_EQ(diff, 300346053753ULL);
	ASSERT_EQ(sidechain_diff, sidechain.difficulty());
	ASSERT_EQ(seed_hash, data.seed_hash);
	ASSERT_EQ(nonce_offset, 39U);
	ASSERT_EQ(template_id, 1U);

	hash blobs_hash;
	keccak(blobs.data(), static_cast<int>(blobs.size()), blobs_hash.h);
	ASSERT_EQ(blobs_hash, H("da11e1ee86779a559df63a55e0b238ce5a67b977e0f68a0b347a39d37096a4bc"));

	// Test 2: mempool with high fee and low fee transactions, it must choose high fee transactions
	for (uint64_t i = 0; i < 512; ++i) {
		TxMempoolData tx;
		*reinterpret_cast<uint64_t*>(tx.id.h) = i;
		tx.fee = (i < 256) ? 30000000 : 60000000;
		tx.weight = 1500;
		mempool.add(tx);
	}

	tpl.update(data, mempool, &wallet);
	ASSERT_EQ(tpl.get_reward(), 612054770773ULL);

	ASSERT_EQ(b->m_sidechainId, H("c9df4853003ab436416b9fc9a5a072d16b4dede849e697a8be2ebb9c88c8ec72"));
	ASSERT_EQ(b->m_transactions.size(), 203);

	for (size_t i = 1; i < b->m_transactions.size(); ++i) {
		ASSERT_GE(*reinterpret_cast<const uint64_t*>(b->m_transactions[i].h), 256);
	}

	tpl.get_hashing_blobs(0, 1000, blobs, height, diff, aux_diff, sidechain_diff, seed_hash, nonce_offset, template_id);

	ASSERT_EQ(height, 2762973);
	ASSERT_EQ(diff, 300346053753ULL);
	ASSERT_EQ(sidechain_diff, sidechain.difficulty());
	ASSERT_EQ(seed_hash, data.seed_hash);
	ASSERT_EQ(nonce_offset, 39U);
	ASSERT_EQ(template_id, 2U);

	keccak(blobs.data(), static_cast<int>(blobs.size()), blobs_hash.h);
	ASSERT_EQ(blobs_hash, H("20aa6a98ca92bc4564bcdc367c078425d4b44b156c2bc7bb703ef055e4fd2c1b"));

	// Test 3: small but not empty mempool, and aux chains

	std::vector<TxMempoolData> transactions;

	for (uint64_t i = 0; i < 10; ++i) {
		TxMempoolData tx;
		*reinterpret_cast<uint64_t*>(tx.id.h) = i;
		tx.fee = 30000000;
		tx.weight = 1500;
		transactions.push_back(tx);
	}
	mempool.swap(transactions);

	data.aux_chains.emplace_back(H("01f0cf665bd4cd31cbb2b2470236389c483522b350335e10a4a5dca34cb85990"), H("d9de1cfba7cdbd47f12f77addcb39b24c1ae7a16c35372bf28d6aee5d7579ee6"), difficulty_type(1000000));

	tpl.update(data, mempool, &wallet);
	ASSERT_EQ(tpl.get_reward(), 600300000000ULL);

	ASSERT_EQ(b->m_sidechainId, H("c32abac2cad40e263a94f5f43f90e0a7d7d4b151305b79951dbc8c88c3180613"));
	ASSERT_EQ(b->m_transactions.size(), 11);

	tpl.get_hashing_blobs(0, 1000, blobs, height, diff, aux_diff, sidechain_diff, seed_hash, nonce_offset, template_id);

	ASSERT_EQ(height, 2762973);
	ASSERT_EQ(diff, 300346053753ULL);
	ASSERT_EQ(sidechain_diff, sidechain.difficulty());
	ASSERT_EQ(seed_hash, data.seed_hash);
	ASSERT_EQ(nonce_offset, 39U);
	ASSERT_EQ(template_id, 3U);

	keccak(blobs.data(), static_cast<int>(blobs.size()), blobs_hash.h);
	ASSERT_EQ(blobs_hash, H("536c0ee8013718b174b63613939379939cee2267e803f77cdabb05fcb47e846f"));

	// Test 4: mempool with a lot of transactions with various fees, all parts of transaction picking algorithm should be tested

	mempool.clear();

	std::mt19937_64 rng;

	for (uint64_t i = 0; i < 10000; ++i) {
		TxMempoolData tx;

		*reinterpret_cast<uint64_t*>(tx.id.h) = i;

		tx.weight = 1500 + (rng() % 10007);
		tx.fee = 30000000 + (rng() % 100000007);

		mempool.add(tx);
	}

	tpl.update(data, mempool, &wallet);
	ASSERT_EQ(tpl.get_reward(), 619742028747ULL);

	ASSERT_EQ(b->m_sidechainId, H("69e7dd43dd99ac6be3f57ca333cc0d814189e83aee1773c99a341aca085c0d46"));
	ASSERT_EQ(b->m_transactions.size(), 174);

	tpl.get_hashing_blobs(0, 1000, blobs, height, diff, aux_diff, sidechain_diff, seed_hash, nonce_offset, template_id);

	ASSERT_EQ(height, 2762973);
	ASSERT_EQ(diff, 300346053753ULL);
	ASSERT_EQ(sidechain_diff, sidechain.difficulty());
	ASSERT_EQ(seed_hash, data.seed_hash);
	ASSERT_EQ(nonce_offset, 39U);
	ASSERT_EQ(template_id, 4U);

	keccak(blobs.data(), static_cast<int>(blobs.size()), blobs_hash.h);
	ASSERT_EQ(blobs_hash, H("4f62562aa84400eb085f58447d8daa45257369f1ec046b2150212329c9e86ae4"));

	destroy_crypto_cache();
}

}
