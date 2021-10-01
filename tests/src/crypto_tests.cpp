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
				ASSERT_EQ(p2pool::generate_key_derivation(key1, key2, derivation), result);
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
		} while (!f.eof());
	}

	destroy_crypto_cache();
}

}
