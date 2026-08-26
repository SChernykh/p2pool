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
#include "wallet.h"
#include "keccak.h"
#include "thread_pool.h"
#include "blake2/blake2.h"

#include "gtest/gtest.h"

namespace p2pool {

namespace carrot {

static constexpr auto t = transcript("test", static_cast<uint32_t>(0x12345678), padding<1, 0xff>());

static_assert(
	(t.size() == 10) &&
	(t[0] == 4) &&
	(t[1] == 't') && (t[2] == 'e') && (t[3] == 's') && (t[4] == 't') &&
	(t[5] == 0x78) && (t[6] == 0x56) && (t[7] == 0x34) && (t[8] == 0x12) &&
	(t[9] == 0xff),
	"constexpr transcript code check failed"
);

TEST(carrot, transcript)
{
	uint8_t t1 = 0x12;
	uint16_t t2 = 0x1234;
	uint32_t t3 = 0x12345678;
	uint64_t t4 = 0x123456789abcdef0;

	auto t = transcript("test", t1, t2, t3, t4, padding<3, 0>(), keccak_0x00);

	std::array<uint8_t, 55> check = {
		4, 't', 'e', 's', 't',
		0x12,
		0x34, 0x12,
		0x78, 0x56, 0x34, 0x12,
		0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12,
		0, 0, 0,
		0xbc, 0x36, 0x78, 0x9e, 0x7a, 0x1e, 0x28, 0x14, 0x36, 0x46, 0x42, 0x29, 0x82, 0x8f, 0x81, 0x7d, 0x66, 0x12, 0xf7, 0xb4, 0x77, 0xd6, 0x65, 0x91, 0xff, 0x96, 0xa9, 0xe0, 0x64, 0xbc, 0xc9, 0x8a
	};

	ASSERT_EQ(t, check);
}

TEST(carrot, hash_to_bytes)
{
	uint8_t buf[128];

	ASSERT_FALSE(hash_to_bytes(nullptr, 0, buf, 16, nullptr));
	ASSERT_FALSE(hash_to_bytes("test", 4, nullptr, 0, nullptr));
	ASSERT_FALSE(hash_to_bytes("test", 4, buf, sizeof(buf), nullptr));
	ASSERT_FALSE(hash_to_bytes("test", 4, buf, 0, nullptr));

	constexpr hash key = keccak("hash_to_bytes key");

	hash h3;
	ASSERT_TRUE(hash_to_bytes("test", 4, h3.h, 3, nullptr));
	ASSERT_EQ(h3, hash("e6f9210000000000000000000000000000000000000000000000000000000000"));

	ASSERT_TRUE(hash_to_bytes("test", 4, h3.h, 3, key.h));
	ASSERT_EQ(h3, hash("11ce720000000000000000000000000000000000000000000000000000000000"));

	hash h8;
	ASSERT_TRUE(hash_to_bytes("test", 4, h8.h, 8, nullptr));
	ASSERT_EQ(h8, hash("aaa0ffa7c54356af000000000000000000000000000000000000000000000000"));

	ASSERT_TRUE(hash_to_bytes("test", 4, h8.h, 8, key.h));
	ASSERT_EQ(h8, hash("35dc4643f1e7cb42000000000000000000000000000000000000000000000000"));

	hash h16;
	ASSERT_TRUE(hash_to_bytes("test", 4, h16.h, 16, nullptr));
	ASSERT_EQ(h16, hash("626e43b9d900ba19bbd00676bcb80d0e00000000000000000000000000000000"));

	ASSERT_TRUE(hash_to_bytes("test", 4, h16.h, 16, key.h));
	ASSERT_EQ(h16, hash("4e4caa4254997b3d5cc2658eebec2dbc00000000000000000000000000000000"));

	hash h32;
	ASSERT_TRUE(hash_to_bytes("test", 4, h32.h, 32, nullptr));
	ASSERT_EQ(h32, hash("f2cf7bfcc95d4ed1dc57f490d928869d9cdf265c3c19129c9d82cb9b9c4bae62"));

	ASSERT_TRUE(hash_to_bytes("test", 4, h32.h, 32, key.h));
	ASSERT_EQ(h32, hash("26fee298add01626671e6973ea4b91e05a7f2349bec9fa17ca49985578f570a0"));

	hash h64[2];
	ASSERT_TRUE(hash_to_bytes("test", 4, &h64, 64, nullptr));
	ASSERT_EQ(h64[0], hash("0b80a879a216e72f6e125152218e7bbc06c1feea657873324f98f2f504326782"));
	ASSERT_EQ(h64[1], hash("137ad1fb1fa8df9267066a03e8b609f220f09ce63654aa4f4182fb2671bb26ff"));

	ASSERT_TRUE(hash_to_bytes("test", 4, &h64, 64, key.h));
	ASSERT_EQ(h64[0], hash("e483fc85cc424217dc8402a63b0976f4c29a2f01ba02636c78825edb4c819e7f"));
	ASSERT_EQ(h64[1], hash("65650211ee373680fbcb1a2b747ca439a36e26826f35eccc64187841f1760c64"));
}

TEST(carrot, hash_to_scalar)
{
	uint8_t buf[128];

	ASSERT_FALSE(hash_to_scalar(nullptr, 0, buf, nullptr));
	ASSERT_FALSE(hash_to_scalar("test", 4, nullptr, nullptr));

	constexpr hash key = keccak("hash_to_scalar key");

	hash h;
	ASSERT_TRUE(hash_to_scalar("test", 4, h.h, nullptr));
	ASSERT_EQ(h, hash("06fa2ad0139e43e746e5c1f96b117497083f0d076fc76ccbf1a8a7b24b1df30f"));

	ASSERT_TRUE(hash_to_scalar("test", 4, h.h, key.h));
	ASSERT_EQ(h, hash("d0d300be17f60b471e558875aceecb9155cf9a25738060b995e5559ec5bb9104"));
}

TEST(carrot, gen_janus_anchor)
{
	constexpr hash txkey_sec = keccak("gen_janus_anchor test");
	Wallet w("44MnN1f3Eto8DZYUWuE5XZNUtE3vcRzt2j6PzqWpPau34e6Cf4fAxt6X2MBmrm6F9YMEiMNjN6W4Shn4pLcfNAja621jwyg");

	char buf[CARROT_JANUS_ANCHOR_BYTES * 2 + 1] = {};
	log::Stream s(buf);

	s << gen_janus_anchor(txkey_sec, 0, w);

	ASSERT_EQ(std::string_view(buf, CARROT_JANUS_ANCHOR_BYTES * 2), "b45ba3471efd4d621b70009b48e2dc73");
}

TEST(carrot, gen_eph_privkey)
{
	const janus_anchor anchor_norm = {
		{ 0xca, 0xee, 0x13, 0x81, 0x77, 0x54, 0x87, 0xa0, 0x98, 0x25, 0x57, 0xf0, 0xd2, 0x68, 0x0b, 0x55 }
	};

	Wallet w("44MnN1f3Eto8DZYUWuE5XZNUtE3vcRzt2j6PzqWpPau34e6Cf4fAxt6X2MBmrm6F9YMEiMNjN6W4Shn4pLcfNAja621jwyg");

	hash eph_priv_key;
	ASSERT_TRUE(gen_eph_privkey(anchor_norm, 3812345, w, eph_priv_key));
	ASSERT_EQ(eph_priv_key, hash("46a29e25fb6caafe8d5f40e279ff4830fdcca68232237461b0884520e2dea507"));
}

TEST(carrot, gen_eph_pubkey)
{
	const hash one{ 1 };
	const hash group_order_minus_one("ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
	const hash eph_priv_key("46a29e25fb6caafe8d5f40e279ff4830fdcca68232237461b0884520e2dea507");
	const hash eph_priv_key_negated("a73157371ff66759483db7c064fa95e40233597dcddc8b9e4f77badf1d215a08");
	const hash monero_convergence_eph_priv_key("6aea0ed0c34ad3483415377658841a75e0da8b462e637d8bf783b9bcd320b303");
	const hash base_x25519("0900000000000000000000000000000000000000000000000000000000000000");
	const hash expected("924e14b4c6664450530266de4aafa87a019484a22e193728d6cad09824690224");
	const hash monero_convergence_expected("8df2a40a42ecc10348a461310c1afc2c2b1be7b29fd27a3921a1aefba5efa27b");

	hash out;
	ASSERT_TRUE(gen_eph_pubkey(one, out));
	ASSERT_EQ(out, base_x25519);

	// ConvertPointE erases the Edwards point's sign, so 1*G and -1*G have the same u-coordinate.
	ASSERT_TRUE(gen_eph_pubkey(group_order_minus_one, out));
	ASSERT_EQ(out, base_x25519);

	ASSERT_TRUE(gen_eph_pubkey(eph_priv_key, out));
	ASSERT_EQ(out, expected);

	ASSERT_TRUE(gen_eph_pubkey(eph_priv_key_negated, out));
	ASSERT_EQ(out, expected);

	// Vector from Monero's carrot_convergence.make_carrot_enote_ephemeral_pubkey_cryptonote test.
	ASSERT_TRUE(gen_eph_pubkey(monero_convergence_eph_priv_key, out));
	ASSERT_EQ(out, monero_convergence_expected);

	out = eph_priv_key;
	ASSERT_TRUE(gen_eph_pubkey(out, out));
	ASSERT_EQ(out, expected);
}

TEST(carrot, batch_eph_pubkeys)
{
	thread_pool_init();
	ON_SCOPE_LEAVE([]() { thread_pool_destroy(); });

	const hash one{ 1 };
	const hash group_order("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
	const hash group_order_minus_one("ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
	const hash known_scalar("46a29e25fb6caafe8d5f40e279ff4830fdcca68232237461b0884520e2dea507");
	const hash known_scalar_negated("a73157371ff66759483db7c064fa95e40233597dcddc8b9e4f77badf1d215a08");

	std::vector<hash> out(1);
	ASSERT_TRUE(batch_eph_pubkeys({}, out));
	ASSERT_TRUE(out.empty());

	// Both scalars produce the identity and therefore Z - Y = 0. The group order case verifies that
	// batch_eph_pubkeys() checks the actual denominator instead of only checking whether the input is zero.
	const std::array<hash, 2> zero_denominator_scalars = { hash(), group_order };

	for (const hash& scalar : zero_denominator_scalars) {
		for (size_t invalid_index = 0; invalid_index < 3; ++invalid_index) {
			std::vector<hash> in(3, one);
			in[invalid_index] = scalar;
			out.resize(1);

			EXPECT_FALSE(batch_eph_pubkeys(in, out));
			EXPECT_TRUE(out.empty());
		}
	}

	// Exercise every possible bit position in a canonical scalar, with all combinations of the three low bits.
	// This also intentionally includes duplicate scalars.
	std::vector<hash> in;
	in.reserve(253 * 8 + 5);

	for (size_t bit = 0; bit <= 252; ++bit) {
		for (uint8_t low_bits = 0; low_bits < 8; ++low_bits) {
			hash k;
			k.h[bit / 8] = static_cast<uint8_t>(1U << (bit % 8));
			k.h[0] |= low_bits;
			in.emplace_back(k);
		}
	}

	// Boundary, known-vector, duplicate, and sign-erasure cases.
	in.emplace_back(group_order_minus_one);
	in.emplace_back(known_scalar);
	in.emplace_back(known_scalar_negated);
	in.emplace_back(one);
	in.emplace_back(one);

	std::vector<hash> reference(in.size());
	for (size_t i = 0; i < in.size(); ++i) {
		ASSERT_TRUE(gen_eph_pubkey(in[i], reference[i])) << "scalar index " << i;
	}

	// Sizes around all possible parallel_run thread-count boundaries exercise segmented inversion.
	for (size_t n = 1; n <= 33; ++n) {
		const std::vector<hash> prefix(in.begin(), in.begin() + n);
		out.resize(1);

		ASSERT_TRUE(batch_eph_pubkeys(prefix, out)) << "batch size " << n;
		ASSERT_EQ(out.size(), n);
		for (size_t i = 0; i < n; ++i) {
			EXPECT_EQ(out[i], reference[i]) << "batch size " << n << ", scalar index " << i;
		}
	}

	ASSERT_TRUE(batch_eph_pubkeys(in, out));
	ASSERT_EQ(out.size(), reference.size());
	for (size_t i = 0; i < out.size(); ++i) {
		EXPECT_EQ(out[i], reference[i]) << "scalar index " << i;
	}

	// Duplicate and negated scalars are valid inputs here; transaction-level code checks D_e uniqueness.
	ASSERT_EQ(out[out.size() - 1], out[out.size() - 2]);
	ASSERT_EQ(out[out.size() - 3], out[out.size() - 4]);
}

} // namespace carrot

} // namespace p2pool
