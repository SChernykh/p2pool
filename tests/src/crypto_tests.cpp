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

static void parse_hash(const std::string& s, hash& h)
{
	for (size_t i = 0; i < HASH_SIZE; ++i) {
		uint8_t d[2];
		if (!from_hex(s[i * 2], d[0]) || !from_hex(s[i * 2 + 1], d[1])) {
			h = {};
			break;
		}
		h.h[i] = (d[0] << 4) | d[1];
	}
}

TEST(crypto, derivation)
{
	std::ifstream f("crypto_tests.txt");
	ASSERT_EQ(f.good(), true);
	do {
		std::string name;
		f >> name;
		if (name == "generate_key_derivation") {
			std::string key1_str, key2_str, result_str, expected_derivation_str;
			f >> key1_str >> key2_str >> result_str;
			const bool result = (result_str == "true");
			if (result) {
				f >> expected_derivation_str;
			}
			hash key1, key2, derivation, expected_derivation;
			parse_hash(key1_str, key1);
			parse_hash(key2_str, key2);
			ASSERT_EQ(p2pool::generate_key_derivation(key1, key2, derivation), result);
			if (result) {
				parse_hash(expected_derivation_str, expected_derivation);
				ASSERT_EQ(derivation, expected_derivation);
			}
		}
		else if (name == "derive_public_key") {
			std::string derivation_str, base_str, result_str, expected_derived_key_str;
			size_t output_index;
			f >> derivation_str >> output_index >> base_str >> result_str;
			const bool result = (result_str == "true");
			if (result) {
				f >> expected_derived_key_str;
			}
			hash derivation, base, derived_key, expected_derived_key;
			parse_hash(derivation_str, derivation);
			parse_hash(base_str, base);
			ASSERT_EQ(derive_public_key(derivation, output_index, base, derived_key), result);
			if (result) {
				parse_hash(expected_derived_key_str, expected_derived_key);
				ASSERT_EQ(derived_key, expected_derived_key);
			}
		}
	} while (!f.eof());
}

}