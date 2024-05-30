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
#include "keccak.h"
#include "RandomX/src/cpu.hpp"
#include "gtest/gtest.h"

namespace p2pool {

static void test_keccak()
{
	auto check = [](const void* input, size_t size, const char* expected_output) {
		hash output;
		const uint8_t* data = reinterpret_cast<const uint8_t*>(input);
		const int len = static_cast<int>(size);
		keccak(data, len, output.h);

		char buf[log::Stream::BUF_SIZE + 1];
		log::Stream s(buf);
		s << output;
		ASSERT_EQ(memcmp(buf, expected_output, HASH_SIZE * 2), 0);

		memset(output.h, 0, HASH_SIZE);
		memset(buf, 0, sizeof(buf));
		s.m_pos = 0;

		keccak_custom([data](int offset) { return data[offset]; }, len, output.h, HASH_SIZE);
		s << output;
		ASSERT_EQ(memcmp(buf, expected_output, HASH_SIZE * 2), 0);
	};

	check("", 0, "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
	check("\xcc", 1, "eead6dbfc7340a56caedc044696a168870549a6a7f6f56961e84a54bd9970b8a");
	check("\x41\xfb", 2, "a8eaceda4d47b3281a795ad9e1ea2122b407baf9aabcb9e18b5717b7873537d2");
	check("\xc1\xec\xfd\xfc", 4, "b149e766d7612eaf7d55f74e1a4fdd63709a8115b14f61fcd22aa4abc8b8e122");

	const uint8_t data[] = { 0x9f, 0x2f, 0xcc, 0x7c, 0x90, 0xde, 0x09, 0x0d, 0x6b, 0x87, 0xcd, 0x7e, 0x97, 0x18, 0xc1, 0xea, 0x6c, 0xb2, 0x11, 0x18, 0xfc, 0x2d, 0x5d, 0xe9, 0xf9, 0x7e, 0x5d, 0xb6, 0xac, 0x1e, 0x9c, 0x10 };
	check(data, sizeof(data), "24dd2ee02482144f539f810d2caa8a7b75d0fa33657e47932122d273c3f6f6d1");

	std::vector<uint8_t> v(1000000, 'a');
	check(v.data(), v.size(), "fadae6b49f129bbb812be8407b7b2894f34aecf6dbd1f9b0f0c7e9853098fc96");

	hash test;
	for (int i = 0; i < 1000000; ++i) {
		keccak(test.h, HASH_SIZE, test.h);
	}

	char buf[log::Stream::BUF_SIZE + 1];
	log::Stream s(buf);
	s << test;
	ASSERT_EQ(memcmp(buf, "16e199635319b8c568a0405a570382994a90a56d5f116892d8cbcb3b13cda0eb", HASH_SIZE * 2), 0);
}

TEST(keccak, hashing)
{
	auto t = keccakf;
	keccakf = keccakf_plain;

	test_keccak();

	keccakf = t;
}

#if defined(__x86_64__) || defined(_M_AMD64)
TEST(keccak, hashing_bmi)
{
	if (randomx::Cpu().hasBmi()) {
		auto t = keccakf;
		keccakf = keccakf_bmi;

		test_keccak();

		keccakf = t;
	}
}
#endif

}
