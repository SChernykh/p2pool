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
#include "params.h"
#include "gtest/gtest.h"

namespace p2pool {

static hash H(const char* s)
{
	hash result;
	from_hex(s, strlen(s), result);
	return result;
};

TEST(block_template, update)
{
	thread_pool_init();
	init_crypto_cache();
	{
	SideChain sidechain(nullptr, NetworkType::Mainnet);
	BlockTemplate tpl(&sidechain, nullptr);
	tpl.rng().seed(123);

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
	Params params;

	params.m_miningWallet = Wallet("44MnN1f3Eto8DZYUWuE5XZNUtE3vcRzt2j6PzqWpPau34e6Cf4fAxt6X2MBmrm6F9YMEiMNjN6W4Shn4pLcfNAja621jwyg");

	// Test 1: empty template
	tpl.update(data, mempool, params);
	ASSERT_EQ(tpl.get_reward(), 600000000000ULL);

	const PoolBlock* b = tpl.pool_block_template();
	ASSERT_EQ(b->m_sidechainId, H("d7f65ee9fd858ce9eec01e38289084fa4b8587e87044e176794eebabd42c921c"));

	std::vector<uint8_t> blobs;
	uint64_t height;
	difficulty_type diff, aux_diff, sidechain_diff;
	hash seed_hash;
	size_t nonce_offset;
	uint32_t template_id;
	ASSERT_EQ(tpl.get_hashing_blobs(0, 1000, blobs, height, diff, aux_diff, sidechain_diff, seed_hash, nonce_offset, template_id), 76);

	ASSERT_EQ(height, 2762973);
	ASSERT_EQ(diff, 300346053753ULL);
	ASSERT_EQ(sidechain_diff, sidechain.difficulty());
	ASSERT_EQ(seed_hash, data.seed_hash);
	ASSERT_EQ(nonce_offset, 39U);
	ASSERT_EQ(template_id, 1U);

	hash blobs_hash;
	keccak(blobs.data(), static_cast<int>(blobs.size()), blobs_hash.h);
	ASSERT_EQ(blobs_hash, H("343b1525a0f68da61f3c94cce02db67a022a48d80ff25b808be97bb1047779c6"));

	// Test 2: mempool with high fee and low fee transactions, it must choose high fee transactions
	for (uint64_t i = 0; i < 513; ++i) {
		hash h;
		h.u64()[0] = i;

		TxMempoolData tx;
		tx.id = static_cast<indexed_hash>(h);
		tx.fee = (i < 256) ? 30000000 : 60000000;
		tx.weight = 1500;
		mempool.add(tx);
	}
	ASSERT_EQ(mempool.size(), 513);

	// Test transaction removing from mempool
	{
		std::vector<hash> tx_hashes;

		// Empty list, should do nothing
		mempool.remove(tx_hashes);
		ASSERT_EQ(mempool.size(), 513);

		hash h;
		*reinterpret_cast<uint64_t*>(h.h) = 512;
		tx_hashes.push_back(h);

		// Should remove a single hash
		mempool.remove(tx_hashes);
	}
	ASSERT_EQ(mempool.size(), 512);

	tpl.update(data, mempool, params);
	ASSERT_EQ(tpl.get_reward(), 612054770773ULL);

	ASSERT_EQ(b->m_sidechainId, H("5fcd597c6061bae558c25e85435766b20e411265032dc401652a53524165f56a"));
	ASSERT_EQ(b->m_transactions.size(), 202);

	for (size_t i = 0; i < b->m_transactions.size(); ++i) {
		ASSERT_GE(static_cast<hash>(b->m_transactions[i]).u64()[0], 256);
	}

	ASSERT_EQ(tpl.get_hashing_blobs(0, 1000, blobs, height, diff, aux_diff, sidechain_diff, seed_hash, nonce_offset, template_id), 77);

	ASSERT_EQ(height, 2762973);
	ASSERT_EQ(diff, 300346053753ULL);
	ASSERT_EQ(sidechain_diff, sidechain.difficulty());
	ASSERT_EQ(seed_hash, data.seed_hash);
	ASSERT_EQ(nonce_offset, 39U);
	ASSERT_EQ(template_id, 2U);

	keccak(blobs.data(), static_cast<int>(blobs.size()), blobs_hash.h);
	ASSERT_EQ(blobs_hash, H("f58ef83eaa5d9d16f5a5cb7f7a82e2521ea6d28001a8584b5cc2716612296d79"));

	// Test 3: small but not empty mempool, and aux chains

	std::vector<TxMempoolData> transactions;

	for (uint64_t i = 0; i < 10; ++i) {
		hash h;
		h.u64()[0] = i;

		TxMempoolData tx;
		tx.id = static_cast<indexed_hash>(h);
		tx.fee = 30000000;
		tx.weight = 1500;
		transactions.push_back(tx);
	}
	mempool.swap_transactions(transactions);
	ASSERT_EQ(mempool.size(), 10);

	data.aux_chains.emplace_back(H("01f0cf665bd4cd31cbb2b2470236389c483522b350335e10a4a5dca34cb85990"), H("d9de1cfba7cdbd47f12f77addcb39b24c1ae7a16c35372bf28d6aee5d7579ee6"), difficulty_type(1000000));

	tpl.update(data, mempool, params);
	ASSERT_EQ(tpl.get_reward(), 600300000000ULL);

	ASSERT_EQ(b->m_sidechainId, H("318543c2020c1154ec4b8127c1849777ef7d9cfe255ebbf8806f2e0231c82adb"));
	ASSERT_EQ(b->m_transactions.size(), 10);

	ASSERT_EQ(tpl.get_hashing_blobs(0, 1000, blobs, height, diff, aux_diff, sidechain_diff, seed_hash, nonce_offset, template_id), 76);

	ASSERT_EQ(height, 2762973);
	ASSERT_EQ(diff, 300346053753ULL);
	ASSERT_EQ(sidechain_diff, sidechain.difficulty());
	ASSERT_EQ(seed_hash, data.seed_hash);
	ASSERT_EQ(nonce_offset, 39U);
	ASSERT_EQ(template_id, 3U);

	keccak(blobs.data(), static_cast<int>(blobs.size()), blobs_hash.h);
	ASSERT_EQ(blobs_hash, H("be3bfe1033ff3959c7b7cbaae2eb1ab90bc2696ff7cc1206fa3a792a92c279de"));

	// Test 4: mempool with a lot of transactions with various fees, all parts of transaction picking algorithm should be tested

	mempool.clear();

	std::mt19937_64 rng;

	for (uint64_t i = 0; i < 10000; ++i) {
		hash h;
		h.u64()[0] = i;

		TxMempoolData tx;
		tx.id = static_cast<indexed_hash>(h);
		tx.weight = 1500 + (rng() % 10007);
		tx.fee = 30000000 + (rng() % 100000007);

		mempool.add(tx);
	}
	ASSERT_EQ(mempool.size(), 10000);

	tpl.update(data, mempool, params);
	ASSERT_EQ(tpl.get_reward(), 619742028747ULL);

	ASSERT_EQ(b->m_sidechainId, H("76e680114a10a0499a78f9160f12f27bdc86453f8a5f2b25726b7dc91bd4809b"));
	ASSERT_EQ(b->m_transactions.size(), 173);

	ASSERT_EQ(tpl.get_hashing_blobs(0, 1000, blobs, height, diff, aux_diff, sidechain_diff, seed_hash, nonce_offset, template_id), 77);

	ASSERT_EQ(height, 2762973);
	ASSERT_EQ(diff, 300346053753ULL);
	ASSERT_EQ(sidechain_diff, sidechain.difficulty());
	ASSERT_EQ(seed_hash, data.seed_hash);
	ASSERT_EQ(nonce_offset, 39U);
	ASSERT_EQ(template_id, 4U);

	keccak(blobs.data(), static_cast<int>(blobs.size()), blobs_hash.h);
	ASSERT_EQ(blobs_hash, H("a99583f1c602609e61cc5045c88237f1eaf8c1a54a358cadf2784e350b126f0a"));
	}
	thread_pool_destroy();
	destroy_crypto_cache();

#ifdef WITH_INDEXED_HASHES
	indexed_hash::cleanup_storage();
#endif
}

TEST(block_template, submit_sidechain_block)
{
	thread_pool_init();
	init_crypto_cache();
	{
	SideChain sidechain(nullptr, NetworkType::Mainnet, "unit_test");

	ASSERT_EQ(sidechain.consensus_hash(), H("81d45b62c10afa4fdda7cebb02dd5ad82c43b577eb3fb0857824427c55fd8a8d"));

	BlockTemplate tpl(&sidechain, nullptr);
	tpl.rng().seed(123);

	BlockTemplate tpl2(&sidechain, nullptr);
	tpl2.rng().seed(456);

	BlockTemplate tpl3(&sidechain, nullptr);
	tpl3.rng().seed(789);

	MinerData data;
	data.major_version = 16;
	data.height = 2762973;
	data.prev_id = H("81a0260b29d5224e88d04b11faff321fbdc11c4570779386b2a1817a86dc622c");
	data.seed_hash = H("33d0fb381466f04d6a1919ced3b698f54a28add3da5a6479b096c67df7a4974c");
	data.difficulty = { 300346053753ULL, 0 };
	data.median_weight = 300000;
	data.already_generated_coins = 18204981557254756780ULL;
	data.median_timestamp = (1ULL << 35) - (sidechain.chain_window_size() * 2 + 10) * sidechain.block_time() - 3600;

	Mempool mempool;
	Params params;

	params.m_miningWallet = Wallet("44MnN1f3Eto8DZYUWuE5XZNUtE3vcRzt2j6PzqWpPau34e6Cf4fAxt6X2MBmrm6F9YMEiMNjN6W4Shn4pLcfNAja621jwyg");

	std::mt19937_64 rng(101112);

	for (uint64_t i = 0, i2 = 0, i3 = 0; i < sidechain.chain_window_size() * 3; ++i) {
		tpl.update(data, mempool, params);

		if ((rng() % 31) == 0) {
			tpl2.update(data, mempool, params);

			if ((rng() % 11) == 0) {
				tpl3.update(data, mempool, params);
				++i3;
				ASSERT_TRUE(tpl3.submit_sidechain_block(i3, 0, 0));
			}

			++i2;
			ASSERT_TRUE(tpl2.submit_sidechain_block(i2, 0, 0));
		}

		ASSERT_TRUE(tpl.submit_sidechain_block(i + 1, 0, 0));
		data.median_timestamp += sidechain.block_time();
	}

	ASSERT_EQ(sidechain.difficulty(), 219467);
	ASSERT_EQ(sidechain.blocksById().size(), 4493);
	ASSERT_TRUE(sidechain.precalcFinished());

	const PoolBlock* tip = sidechain.chainTip();

	ASSERT_TRUE(tip != nullptr);
	ASSERT_TRUE(tip->m_verified);
	ASSERT_FALSE(tip->m_invalid);

	ASSERT_EQ(tip->m_txinGenHeight, data.height);
	ASSERT_EQ(tip->m_sidechainHeight, sidechain.chain_window_size() * 3 - 1);

	ASSERT_EQ(tip->m_sidechainId, H("9288f32340aefc06db63db2b31342c87d5ce8e9c7b5e476b01bc2caf860be924"));
	}
	thread_pool_destroy();
	destroy_crypto_cache();

#ifdef WITH_INDEXED_HASHES
	indexed_hash::cleanup_storage();
#endif
}

TEST(block_template, genesis_block_max_timestamp)
{
	thread_pool_init();
	init_crypto_cache();
	{
	SideChain sidechain(nullptr, NetworkType::Mainnet, "unit_test");
	ASSERT_EQ(sidechain.consensus_hash(), H("81d45b62c10afa4fdda7cebb02dd5ad82c43b577eb3fb0857824427c55fd8a8d"));

	BlockTemplate tpl(&sidechain, nullptr);
	tpl.rng().seed(0);

	MinerData data;
	data.major_version = 16;
	data.height = 2762973;
	data.prev_id = H("81a0260b29d5224e88d04b11faff321fbdc11c4570779386b2a1817a86dc622c");
	data.seed_hash = H("33d0fb381466f04d6a1919ced3b698f54a28add3da5a6479b096c67df7a4974c");
	data.difficulty = { 300346053753ULL, 0 };
	data.median_weight = 300000;
	data.already_generated_coins = 18204981557254756780ULL;
	data.median_timestamp = std::numeric_limits<uint64_t>::max() - 1;

	Mempool mempool;
	Params params;

	params.m_miningWallet = Wallet("44MnN1f3Eto8DZYUWuE5XZNUtE3vcRzt2j6PzqWpPau34e6Cf4fAxt6X2MBmrm6F9YMEiMNjN6W4Shn4pLcfNAja621jwyg");

	tpl.update(data, mempool, params);

	ASSERT_TRUE(tpl.submit_sidechain_block(1, 0, 0));
	ASSERT_EQ(sidechain.difficulty(), 100000);

	const PoolBlock* tip = sidechain.chainTip();

	ASSERT_TRUE(tip != nullptr);
	ASSERT_TRUE(tip->m_verified);
	ASSERT_FALSE(tip->m_invalid);

	ASSERT_EQ(tip->m_timestamp, std::numeric_limits<uint64_t>::max());
	ASSERT_EQ(tip->m_txinGenHeight, data.height);
	ASSERT_EQ(tip->m_sidechainHeight, 0);

	ASSERT_EQ(tip->m_sidechainId, H("dd61acdbeae1eab72880aab278428c4fafcbfecc67028b1f228a788eaf13b3f9"));
	}
	thread_pool_destroy();
	destroy_crypto_cache();

#ifdef WITH_INDEXED_HASHES
	indexed_hash::cleanup_storage();
#endif
}

}
