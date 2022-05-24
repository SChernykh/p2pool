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
#include "gtest/gtest.h"
#include <random>
#include <sstream>

namespace p2pool {

TEST(hash, constructor)
{
	hash h;
	uint8_t buf[HASH_SIZE]{};
	ASSERT_EQ(memcmp(h.h, buf, HASH_SIZE), 0);

	memset(h.h, -1, HASH_SIZE);
	h = {};
	ASSERT_EQ(memcmp(h.h, buf, HASH_SIZE), 0);
}

TEST(hash, compare)
{
	hash hashes[HASH_SIZE + 1];

	for (size_t i = 1; i <= HASH_SIZE; ++i) {
		hashes[i].h[i - 1] = 1;
	}

	for (size_t i = 0; i <= HASH_SIZE; ++i) {
		for (size_t j = 0; j <= HASH_SIZE; ++j) {
			ASSERT_EQ(hashes[i] <  hashes[j], i <  j);
			ASSERT_EQ(hashes[i] == hashes[j], i == j);
			ASSERT_EQ(hashes[i] != hashes[j], i != j);
		}
	}
}

TEST(hash, empty)
{
	hash h;
	ASSERT_EQ(h.empty(), true);

	for (size_t i = 0; i < HASH_SIZE; ++i) {
		hash h2;
		h2.h[i] = 1;
		ASSERT_EQ(h2.empty(), false);
	}
}

TEST(hash, input_output)
{
	auto check = [](const hash& h, const char* s) {
		std::stringstream ss;
		ss << h;
		ASSERT_EQ(ss.str(), s);
		hash h2;
		ss >> h2;
		ASSERT_EQ(h2, h);
	};

	hash h;
	check(h, "0000000000000000000000000000000000000000000000000000000000000000");

	memset(h.h, -1, HASH_SIZE);
	check(h, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

	for (uint8_t i = 0; i < HASH_SIZE; ++i) {
		h.h[i] = i;
	}
	check(h, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");

	for (uint8_t i = 0; i < HASH_SIZE; ++i) {
		h.h[i] = 0xff - i;
	}
	check(h, "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0");
}

}
