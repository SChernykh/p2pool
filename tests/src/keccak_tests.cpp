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

TEST(keccak, SHA3)
{
	auto check = [](const char* input, const char* expected_output) {
		std::vector<uint8_t> data;
		ASSERT_TRUE(from_hex(input, strlen(input), data));

		hash h;

		keccak_custom([&data](int offset) { return data[offset]; }, data.size(), h.h, HASH_SIZE, true);

		char buf[log::Stream::BUF_SIZE + 1];
		log::Stream s(buf);
		s << h;

		ASSERT_EQ(memcmp(buf, expected_output, HASH_SIZE * 2), 0);
	};

	check("", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");

	check("e9", "f0d04dd1e6cfc29a4460d521796852f25d9ef8d28b44ee91ff5b759d72c1e6d6");
	check("d477", "94279e8f5ccdf6e17f292b59698ab4e614dfe696a46c46da78305fc6a3146ab7");
	check("b053fa", "9d0ff086cd0ec06a682c51c094dc73abdc492004292344bd41b82a60498ccfdb");
	check("e7372105", "3a42b68ab079f28c4ca3c752296f279006c4fe78b1eb79d989777f051e4046ae");

	check("989fc49594afc73405bacee4dbbe7135804f800368de39e2ea3bbec04e59c6c52752927ee3aa233ba0d8aab5410240f4c109d770c8c570777c928fce9a0bec9bc5156c821e204f0f14a9ab547e0319d3e758ae9e28eb2dbc3d9f7acf51bd52f41bf23aeb6d97b5780a35ba08b94965989744edd3b1d6d67ad26c68099af85f98d0f0e4fff9", "b10adeb6a9395a48788931d45a7b4e4f69300a76d8b716c40c614c3113a0f051");
	check("e5022f4c7dfe2dbd207105e2f27aaedd5a765c27c0bc60de958b49609440501848ccf398cf66dfe8dd7d131e04f1432f32827a057b8904d218e68ba3b0398038d755bd13d5f168cfa8a11ab34c0540873940c2a62eace3552dcd6953c683fdb29983d4e417078f1988c560c9521e6f8c78997c32618fc510db282a985f868f2d973f82351d11", "3293a4b9aeb8a65e1014d3847500ffc8241594e9c4564cbd7ce978bfa50767fe");
	check("b1f6076509938432145bb15dbe1a7b2e007934be5f753908b50fd24333455970a7429f2ffbd28bd6fe1804c4688311f318fe3fcd9f6744410243e115bcb00d7e039a4fee4c326c2d119c42abd2e8f4155a44472643704cc0bc72403b8a8ab0fd4d68e04a059d6e5ed45033b906326abb4eb4147052779bad6a03b55ca5bd8b140e131bed2dfada", "f82d9602b231d332d902cb6436b15aef89acc591cb8626233ced20c0a6e80d7a");
	check("56ea14d7fcb0db748ff649aaa5d0afdc2357528a9aad6076d73b2805b53d89e73681abfad26bee6c0f3d20215295f354f538ae80990d2281be6de0f6919aa9eb048c26b524f4d91ca87b54c0c54aa9b54ad02171e8bf31e8d158a9f586e92ffce994ecce9a5185cc80364d50a6f7b94849a914242fcb73f33a86ecc83c3403630d20650ddb8cd9c4", "4beae3515ba35ec8cbd1d94567e22b0d7809c466abfbafe9610349597ba15b45");

	std::string s;
	s.reserve(2000000);

	for (size_t i = 0; i < 1000000; ++i) {
		s += "61";
	}
	check(s.c_str(), "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1");
}

}
