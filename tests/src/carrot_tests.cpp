/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2026 SChernykh <https://github.com/SChernykh>
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
#include "carrot.h"
#include "keccak.h"
#include "blake2/blake2.h"

#include "gtest/gtest.h"

namespace p2pool {

static constexpr auto t = carrot::transcript("test", static_cast<uint32_t>(0x12345678));

static_assert(
	(t.size() == 9) &&
	(t[0] == 4) &&
	(t[1] == 't') && (t[2] == 'e') && (t[3] == 's') && (t[4] == 't') &&
	(t[5] == 0x78) && (t[6] == 0x56) && (t[7] == 0x34) && (t[8] == 0x12),
	"constexpr carrot::transcript code check failed"
);

TEST(carrot, transcript)
{
	uint8_t t1 = 0x12;
	uint16_t t2 = 0x1234;
	uint32_t t3 = 0x12345678;
	uint64_t t4 = 0x123456789abcdef0;

	auto t = carrot::transcript("test", t1, t2, t3, t4, keccak_0x00);

	std::array<uint8_t, 52> check = {
		4, 't', 'e', 's', 't',
		0x12,
		0x34, 0x12,
		0x78, 0x56, 0x34, 0x12,
		0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12,
		0xbc, 0x36, 0x78, 0x9e, 0x7a, 0x1e, 0x28, 0x14, 0x36, 0x46, 0x42, 0x29, 0x82, 0x8f, 0x81, 0x7d, 0x66, 0x12, 0xf7, 0xb4, 0x77, 0xd6, 0x65, 0x91, 0xff, 0x96, 0xa9, 0xe0, 0x64, 0xbc, 0xc9, 0x8a
	};

	ASSERT_EQ(t, check);
}

TEST(carrot, hash_to_bytes)
{
	uint8_t buf[128];

	ASSERT_FALSE(carrot::hash_to_bytes(nullptr, 0, buf, 16, nullptr));
	ASSERT_FALSE(carrot::hash_to_bytes("test", 4, nullptr, 0, nullptr));
	ASSERT_FALSE(carrot::hash_to_bytes("test", 4, buf, sizeof(buf), nullptr));
	ASSERT_FALSE(carrot::hash_to_bytes("test", 4, buf, 0, nullptr));

	constexpr hash key = keccak("hash_to_bytes key");

	hash h3;
	ASSERT_TRUE(carrot::hash_to_bytes("test", 4, h3.h, 3, nullptr));
	ASSERT_EQ(h3, hash("e6f9210000000000000000000000000000000000000000000000000000000000"));

	ASSERT_TRUE(carrot::hash_to_bytes("test", 4, h3.h, 3, key.h));
	ASSERT_EQ(h3, hash("11ce720000000000000000000000000000000000000000000000000000000000"));

	hash h8;
	ASSERT_TRUE(carrot::hash_to_bytes("test", 4, h8.h, 8, nullptr));
	ASSERT_EQ(h8, hash("aaa0ffa7c54356af000000000000000000000000000000000000000000000000"));

	ASSERT_TRUE(carrot::hash_to_bytes("test", 4, h8.h, 8, key.h));
	ASSERT_EQ(h8, hash("35dc4643f1e7cb42000000000000000000000000000000000000000000000000"));

	hash h16;
	ASSERT_TRUE(carrot::hash_to_bytes("test", 4, h16.h, 16, nullptr));
	ASSERT_EQ(h16, hash("626e43b9d900ba19bbd00676bcb80d0e00000000000000000000000000000000"));

	ASSERT_TRUE(carrot::hash_to_bytes("test", 4, h16.h, 16, key.h));
	ASSERT_EQ(h16, hash("4e4caa4254997b3d5cc2658eebec2dbc00000000000000000000000000000000"));

	hash h32;
	ASSERT_TRUE(carrot::hash_to_bytes("test", 4, h32.h, 32, nullptr));
	ASSERT_EQ(h32, hash("f2cf7bfcc95d4ed1dc57f490d928869d9cdf265c3c19129c9d82cb9b9c4bae62"));

	ASSERT_TRUE(carrot::hash_to_bytes("test", 4, h32.h, 32, key.h));
	ASSERT_EQ(h32, hash("26fee298add01626671e6973ea4b91e05a7f2349bec9fa17ca49985578f570a0"));

	hash h64[2];
	ASSERT_TRUE(carrot::hash_to_bytes("test", 4, &h64, 64, nullptr));
	ASSERT_EQ(h64[0], hash("0b80a879a216e72f6e125152218e7bbc06c1feea657873324f98f2f504326782"));
	ASSERT_EQ(h64[1], hash("137ad1fb1fa8df9267066a03e8b609f220f09ce63654aa4f4182fb2671bb26ff"));

	ASSERT_TRUE(carrot::hash_to_bytes("test", 4, &h64, 64, key.h));
	ASSERT_EQ(h64[0], hash("e483fc85cc424217dc8402a63b0976f4c29a2f01ba02636c78825edb4c819e7f"));
	ASSERT_EQ(h64[1], hash("65650211ee373680fbcb1a2b747ca439a36e26826f35eccc64187841f1760c64"));
}

TEST(carrot, hash_to_scalar)
{
	uint8_t buf[128];

	ASSERT_FALSE(carrot::hash_to_scalar(nullptr, 0, buf, nullptr));
	ASSERT_FALSE(carrot::hash_to_scalar("test", 4, nullptr, nullptr));

	constexpr hash key = keccak("hash_to_scalar key");

	hash h;
	ASSERT_TRUE(carrot::hash_to_scalar("test", 4, h.h, nullptr));
	ASSERT_EQ(h, hash("06fa2ad0139e43e746e5c1f96b117497083f0d076fc76ccbf1a8a7b24b1df30f"));

	ASSERT_TRUE(carrot::hash_to_scalar("test", 4, h.h, key.h));
	ASSERT_EQ(h, hash("d0d300be17f60b471e558875aceecb9155cf9a25738060b995e5559ec5bb9104"));
}

}
