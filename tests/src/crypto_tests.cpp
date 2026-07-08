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
#include "util.h"
extern "C" {
#include "crypto-ops.h"
}
#include "fcmp_pp_crypto.h"
#include "thread_pool.h"
#include "keccak.h"

#include "gtest/gtest.h"
#include <fstream>

namespace p2pool {

TEST(crypto, ops)
{
	init_crypto_cache();
	{
	constexpr uint8_t entropy[] = "Test entropy";
	hash pub, sec;
	generate_keys_deterministic(pub, sec, entropy, sizeof(entropy) - 1);
	ASSERT_TRUE(check_keys(pub, sec));

	sec.h[HASH_SIZE - 1] = 0xff;
	ASSERT_FALSE(check_keys(pub, sec));

	// Run the tests several times to check how crypto cache works
	for (int i = 0; i < 4; ++i) {
		if (i == 2) {
			clear_crypto_cache(seconds_since_epoch() - 1);
		}
		else if (i == 3) {
			clear_crypto_cache(seconds_since_epoch() + 1);
		}

		std::ifstream f("crypto_tests.txt");
		ASSERT_EQ(f.good() && f.is_open(), true);
		do {
			std::string name;
			f >> name;
			if (name == "generate_key_derivation") {
				hash key1, key2, derivation, expected_derivation;
				std::string result_str;
				f >> key1 >> key2 >> result_str;
				const bool result = (result_str == "true");
				if (result) {
					f >> expected_derivation;
				}
				uint8_t view_tag;
				ASSERT_EQ(p2pool::generate_key_derivation(key1, key2, 0, derivation, view_tag), result);
				ASSERT_EQ(p2pool::generate_key_derivation(key1, key2, 1, derivation, view_tag), result);
				ASSERT_EQ(p2pool::generate_key_derivation(key1, key2, 2, derivation, view_tag), result);
				ASSERT_EQ(p2pool::generate_key_derivation(key1, key2, 3, derivation, view_tag), result);
				if (result) {
					ASSERT_EQ(derivation, expected_derivation);
				}
			}
			else if (name == "derive_public_key") {
				hash derivation, base, derived_key, expected_derived_key;
				std::string result_str;
				size_t output_index;
				f >> derivation >> output_index >> base >> result_str;
				const bool result = (result_str == "true");
				if (result) {
					f >> expected_derived_key;
				}
				ASSERT_EQ(derive_public_key(derivation, output_index, base, derived_key), result);
				if (result) {
					ASSERT_EQ(derived_key, expected_derived_key);
				}
			}
			else if (name == "derive_view_tag") {
				hash derivation;
				uint64_t output_index;
				std::string result_str;
				f >> derivation >> output_index >> result_str;
				uint8_t view_tag;
				p2pool::derive_view_tag(derivation, output_index, view_tag);

				char buf[log::Stream::BUF_SIZE + 1];
				log::Stream s(buf);
				s << log::hex_buf(&view_tag, 1) << '\0';

				ASSERT_EQ(buf, result_str);
			}
			else if (name == "get_tx_keys") {
				hash wallet_spend_key, monero_block_id, pub_check, sec_check;
				f >> wallet_spend_key >> monero_block_id >> pub_check >> sec_check;

				hash pub, sec;
				p2pool::get_tx_keys(pub, sec, wallet_spend_key, monero_block_id);

				ASSERT_EQ(pub, pub_check);
				ASSERT_EQ(sec, sec_check);
			}
			else if (name == "check_key") {
				hash pub_key;
				std::string result_str;

				f >> pub_key >> result_str;				

				ge_p3 p;
				ASSERT_EQ(ge_frombytes_vartime(&p, pub_key.h) == 0, result_str == "true");
			}
			else if (name == "check_torsion") {
				hash pub_key;
				std::string result_str;

				f >> pub_key >> result_str;				

				ge_p3 p;
				ASSERT_EQ(
					(ge_frombytes_vartime(&p, pub_key.h) == 0)
					&& !fcmp_pp::mul8_is_identity(p)
					&& fcmp_pp::torsion_check_vartime(p)
				, result_str == "true");
			}
		} while (!f.eof());
	}
	}
	clear_crypto_cache(0);
	destroy_crypto_cache();

#ifdef WITH_INDEXED_HASHES
	indexed_hash::cleanup_storage();
#endif
}

TEST(crypto, batch)
{
	init_crypto_cache();
	thread_pool_init();

	constexpr size_t N = 1000;

	std::vector<std::pair<hash, size_t>> in;
	std::vector<std::pair<hash, int32_t>> reference_out;

	std::vector<batch_public_key_input> in2;
	std::vector<std::pair<hash, bool>> reference_out2;

	size_t i = 0;

	hash txkey_pub, txkey_sec;
	p2pool::generate_keys_deterministic(txkey_pub, txkey_sec, reinterpret_cast<uint8_t*>(&i), sizeof(i));

	i = N + 1;

	hash pub2, sec2;
	p2pool::generate_keys_deterministic(pub2, sec2, reinterpret_cast<uint8_t*>(&i), sizeof(i));

	for (i = 1; i <= N; ++i) {
		// Generate a valid pubkey
		hash pub, sec;
		p2pool::generate_keys_deterministic(pub, sec, reinterpret_cast<uint8_t*>(&i), sizeof(i));

		in.emplace_back(pub, i);

		hash derivation;
		uint8_t view_tag;
		ASSERT_TRUE(p2pool::generate_key_derivation(pub, txkey_sec, i, derivation, view_tag));

		reference_out.emplace_back(derivation, view_tag);

		hash derived_key;
		bool result = p2pool::derive_public_key(derivation, i, pub2, derived_key);

		in2.emplace_back(derivation, i, pub2);
		reference_out2.emplace_back(derived_key, result);

		// Now make it random (use keccak as a deterministic random number generator)
		p2pool::keccak(pub.h, HASH_SIZE, pub.h);
		in.emplace_back(pub, i);

		result = p2pool::generate_key_derivation(pub, txkey_sec, i, derivation, view_tag);
		reference_out.emplace_back(derivation, result ? view_tag : -1);

		result = p2pool::derive_public_key(derivation, i, pub, derived_key);

		in2.emplace_back(derivation, i, pub);
		reference_out2.emplace_back(derived_key, result);
	}

	clear_crypto_cache(0);

#ifdef WITH_INDEXED_HASHES
	indexed_hash::cleanup_storage();
#endif

	std::vector<std::pair<hash, int32_t>> out;
	p2pool::batch_derivations(in, txkey_sec, out);

	ASSERT_EQ(out.size(), reference_out.size());

	for (size_t i = 0; i < out.size(); ++i) {
		if (reference_out[i].second >= 0) {
			ASSERT_EQ(out[i], reference_out[i]);
		}
		else {
			ASSERT_EQ(out[i].second, reference_out[i].second);
		}
	}

	std::vector<std::pair<hash, bool>> out2;
	p2pool::batch_public_keys(in2, out2);

	ASSERT_EQ(out2.size(), reference_out2.size());

	for (size_t i = 0; i < out2.size(); ++i) {
		if (reference_out2[i].second) {
			ASSERT_EQ(out2[i].first, reference_out2[i].first);
		}
		else {
			ASSERT_FALSE(out2[i].second);
		}
	}

	thread_pool_destroy();
	destroy_crypto_cache();

#ifdef WITH_INDEXED_HASHES
	indexed_hash::cleanup_storage();
#endif
}

}
