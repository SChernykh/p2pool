/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2023 SChernykh <https://github.com/SChernykh>
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
#include "gtest/gtest.h"
#include <fstream>

namespace p2pool {

TEST(crypto, derivation)
{
	init_crypto_cache();

	// Run the tests twice to check how crypto cache works
	for (int i = 0; i < 2; ++i) {
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
		} while (!f.eof());
	}

	destroy_crypto_cache();
}

}
