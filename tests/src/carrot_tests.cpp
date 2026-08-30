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
#include "crypto.h"
#include "wallet.h"
#include "keccak.h"
#include "thread_pool.h"
#include "blake2/blake2.h"

#include "gtest/gtest.h"
#include <random>

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

static constexpr hash one{ 1 };
static constexpr hash two{ 2 };

static constexpr hash identity_public_key{ 1 };

static constexpr hash group_order("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
static constexpr hash group_order_minus_one("ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
static constexpr hash base_x25519("0900000000000000000000000000000000000000000000000000000000000000");
static constexpr hash torsion_public_key("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");

static constexpr hash all_ones("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

static constexpr const hash& invalid_public_key = all_ones;

static constexpr janus_anchor all_ones_anchor = {
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }
};

static constexpr hash hash_to_bytes_key = keccak("hash_to_bytes key");
static constexpr hash hash_to_scalar_key = keccak("hash_to_scalar key");
static constexpr hash gen_janus_anchor_txkey_sec = keccak("gen_janus_anchor test");

static constexpr char test_wallet_address[] = "44MnN1f3Eto8DZYUWuE5XZNUtE3vcRzt2j6PzqWpPau34e6Cf4fAxt6X2MBmrm6F9YMEiMNjN6W4Shn4pLcfNAja621jwyg";

static constexpr hash eph_priv_key("46a29e25fb6caafe8d5f40e279ff4830fdcca68232237461b0884520e2dea507");
static constexpr hash eph_priv_key_negated("a73157371ff66759483db7c064fa95e40233597dcddc8b9e4f77badf1d215a08");
static constexpr hash eph_pub_key("924e14b4c6664450530266de4aafa87a019484a22e193728d6cad09824690224");

static constexpr janus_anchor convergence_anchor = {
	{ 0xca, 0xee, 0x13, 0x81, 0x77, 0x54, 0x87, 0xa0, 0x98, 0x25, 0x57, 0xf0, 0xd2, 0x68, 0x0b, 0x55 }
};

static constexpr hash convergence_eph_priv_key("6aea0ed0c34ad3483415377658841a75e0da8b462e637d8bf783b9bcd320b303");
static constexpr hash convergence_eph_pub_key_cryptonote("8df2a40a42ecc10348a461310c1afc2c2b1be7b29fd27a3921a1aefba5efa27b");
static constexpr hash convergence_eph_pub_key_subaddress("a3c3cdf84fd301cfc4675096f1c896543f2efc1001d899bbab3a0fd137f6a630");
static constexpr hash convergence_view_public_key("369bdcf4f434f42eb09f4372cb6be30de7b17d21e4f98e244459a90b58cd0610");
static constexpr hash convergence_spend_public_key("8f2f38e702678ae59751dc55818240e0330851e77bfaff003b671885ed06871e");
static constexpr hash convergence_sender_receiver_secret("1f848f8384e7a9f217dc9dc2691703cf392eaf6c92931acd0fc840c900d3ed49");
static constexpr hash convergence_contextualized_secret("6e99852ed7b3744177bb669e73fd1c544d88555ea6fffe3787ca6af48d2fe9f6");
static constexpr hash convergence_onetime_address("522347147e41f22ebe155abc32b9def985b2e454045c6edd8921ee4253cd4516");
static constexpr hash convergence_onetime_address_coinbase("0c4ee83d079ebd77882f894b2e0a43e3d572af9c330871f1dfbcc62f5c64e4ae");
static constexpr uint64_t convergence_amount = 67000000000000ULL;

static constexpr hash convergence_account_spend_public_key("4198f391723f6c64eb75e4f0e341d576dc344e8a8ad3164444451855dbd862b4");
static constexpr hash convergence_account_view_public_key("14d12188409591353096b41abeccf66a88d916dfe0e6d1998672293ebc1cc83d");

// unbiased_hash_to_ec(keccak("Monero Generator T")), the FCMP++ generator
static constexpr uint8_t T_bytes[HASH_SIZE] = {
	97, 183, 54, 206, 147, 182, 42, 61, 55, 120, 171, 32, 77, 168, 93, 59,
	76, 220, 7, 37, 15, 93, 167, 227, 223, 38, 41, 146, 129, 52, 213, 38
};


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
	ASSERT_FALSE(hash_to_bytes("test", 4, nullptr, 32, nullptr));
	ASSERT_FALSE(hash_to_bytes("test", 4, buf, 0, nullptr));
	ASSERT_FALSE(hash_to_bytes("test", 4, buf, sizeof(buf), nullptr));

	hash h3;
	ASSERT_TRUE(hash_to_bytes("test", 4, h3.h, 3, nullptr));
	ASSERT_EQ(h3, hash("e6f9210000000000000000000000000000000000000000000000000000000000"));

	ASSERT_TRUE(hash_to_bytes("test", 4, h3.h, 3, hash_to_bytes_key.h));
	ASSERT_EQ(h3, hash("11ce720000000000000000000000000000000000000000000000000000000000"));

	hash h8;
	ASSERT_TRUE(hash_to_bytes("test", 4, h8.h, 8, nullptr));
	ASSERT_EQ(h8, hash("aaa0ffa7c54356af000000000000000000000000000000000000000000000000"));

	ASSERT_TRUE(hash_to_bytes("test", 4, h8.h, 8, hash_to_bytes_key.h));
	ASSERT_EQ(h8, hash("35dc4643f1e7cb42000000000000000000000000000000000000000000000000"));

	hash h16;
	ASSERT_TRUE(hash_to_bytes("test", 4, h16.h, 16, nullptr));
	ASSERT_EQ(h16, hash("626e43b9d900ba19bbd00676bcb80d0e00000000000000000000000000000000"));

	ASSERT_TRUE(hash_to_bytes("test", 4, h16.h, 16, hash_to_bytes_key.h));
	ASSERT_EQ(h16, hash("4e4caa4254997b3d5cc2658eebec2dbc00000000000000000000000000000000"));

	hash h32;
	ASSERT_TRUE(hash_to_bytes("test", 4, h32.h, 32, nullptr));
	ASSERT_EQ(h32, hash("f2cf7bfcc95d4ed1dc57f490d928869d9cdf265c3c19129c9d82cb9b9c4bae62"));

	ASSERT_TRUE(hash_to_bytes("test", 4, h32.h, 32, hash_to_bytes_key.h));
	ASSERT_EQ(h32, hash("26fee298add01626671e6973ea4b91e05a7f2349bec9fa17ca49985578f570a0"));

	hash h64[2];
	ASSERT_TRUE(hash_to_bytes("test", 4, &h64, 64, nullptr));
	ASSERT_EQ(h64[0], hash("0b80a879a216e72f6e125152218e7bbc06c1feea657873324f98f2f504326782"));
	ASSERT_EQ(h64[1], hash("137ad1fb1fa8df9267066a03e8b609f220f09ce63654aa4f4182fb2671bb26ff"));

	ASSERT_TRUE(hash_to_bytes("test", 4, &h64, 64, hash_to_bytes_key.h));
	ASSERT_EQ(h64[0], hash("e483fc85cc424217dc8402a63b0976f4c29a2f01ba02636c78825edb4c819e7f"));
	ASSERT_EQ(h64[1], hash("65650211ee373680fbcb1a2b747ca439a36e26826f35eccc64187841f1760c64"));
}

TEST(carrot, hash_to_scalar)
{
	uint8_t buf[128];

	ASSERT_FALSE(hash_to_scalar(nullptr, 0, buf, nullptr));
	ASSERT_FALSE(hash_to_scalar("test", 4, nullptr, nullptr));

	hash h;
	ASSERT_TRUE(hash_to_scalar("test", 4, h.h, nullptr));
	ASSERT_EQ(h, hash("06fa2ad0139e43e746e5c1f96b117497083f0d076fc76ccbf1a8a7b24b1df30f"));

	ASSERT_TRUE(hash_to_scalar("test", 4, h.h, hash_to_scalar_key.h));
	ASSERT_EQ(h, hash("d0d300be17f60b471e558875aceecb9155cf9a25738060b995e5559ec5bb9104"));
}

TEST(carrot, gen_janus_anchor)
{
	Wallet w(test_wallet_address);

	char buf[CARROT_JANUS_ANCHOR_BYTES * 2 + 1] = {};

	auto check = [&buf](const janus_anchor& anchor, const char* expected)
	{
		log::Stream s(buf);
		s << anchor;

		EXPECT_EQ(std::string_view(buf, CARROT_JANUS_ANCHOR_BYTES * 2), expected);
	};

	check(gen_janus_anchor(gen_janus_anchor_txkey_sec, 0, w), "b45ba3471efd4d621b70009b48e2dc73");
	check(gen_janus_anchor(gen_janus_anchor_txkey_sec, 1, w), "15ea44a43f4f0904f5cda6474de93670");
	check(gen_janus_anchor(gen_janus_anchor_txkey_sec, 2, w), "61f05b971bd72bfa9d59c2d1b5840f30");
	check(gen_janus_anchor(gen_janus_anchor_txkey_sec, 255, w), "de500896f8e7fd099c0f1e9cfc4785fc");
}

TEST(carrot, gen_eph_privkey)
{
	Wallet w(test_wallet_address);

	hash out;
	ASSERT_TRUE(gen_eph_privkey(convergence_anchor, 3812345, w, out));
	ASSERT_EQ(out, eph_priv_key);

	ASSERT_TRUE(gen_eph_privkey(convergence_anchor, 0, w, out));
	ASSERT_EQ(out, hash("f74b73f6c1000b129e3d5e45b890a1270d502d355d19d2ab306335c1a2fdba0a"));

	ASSERT_TRUE(gen_eph_privkey(convergence_anchor, 1, w, out));
	ASSERT_EQ(out, hash("11b2458517d9302ee01f36861f87994a445e80269c6aa5850911d25d01158c03"));

	ASSERT_TRUE(gen_eph_privkey(convergence_anchor, 0x100000000ULL, w, out));
	ASSERT_EQ(out, hash("c5c08ca1732aa701b67ead205f775a7e5c6c54a89e519034a71bf2eea55df80d"));

	ASSERT_TRUE(gen_eph_privkey(convergence_anchor, 0x100000000000000ULL, w, out));
	ASSERT_EQ(out, hash("387538402d587c1cf9ab46f26c9e3de604d3015dc9d75b6b7a2a5127ce71d308"));

	ASSERT_TRUE(gen_eph_privkey(convergence_anchor, std::numeric_limits<uint64_t>::max(), w, out));
	ASSERT_EQ(out, hash("ee85353f13513e88e8b4c30d7916bd5cf88e80c35728027e7cf1fa9a2c19bf00"));

	ASSERT_TRUE(gen_eph_privkey(all_ones_anchor, 3812345, w, out));
	ASSERT_EQ(out, hash("6de606ddb6e11c57f6ab2cc9af485388350a93c1ac330bc968eaa490eee9ef05"));

	ASSERT_EQ(sc_check(out.h), 0);
	ASSERT_FALSE(out.empty());
}

TEST(carrot, gen_eph_pubkey)
{
	hash out;
	ASSERT_TRUE(gen_eph_pubkey(one, out));
	ASSERT_EQ(out, base_x25519);

	// ConvertPointE erases the Edwards point's sign, so 1*G and -1*G have the same u-coordinate.
	ASSERT_TRUE(gen_eph_pubkey(group_order_minus_one, out));
	ASSERT_EQ(out, base_x25519);

	ASSERT_TRUE(gen_eph_pubkey(eph_priv_key, out));
	ASSERT_EQ(out, eph_pub_key);

	ASSERT_TRUE(gen_eph_pubkey(eph_priv_key_negated, out));
	ASSERT_EQ(out, eph_pub_key);

	// Vector from Monero's carrot_convergence.make_carrot_enote_ephemeral_pubkey_cryptonote test.
	ASSERT_TRUE(gen_eph_pubkey(convergence_eph_priv_key, out));
	ASSERT_EQ(out, convergence_eph_pub_key_cryptonote);

	out = eph_priv_key;
	ASSERT_TRUE(gen_eph_pubkey(out, out));
	ASSERT_EQ(out, eph_pub_key);

	// d_e * G is the point at infinity for these scalars, so ConvertPointE (and therefore D_e) is not defined
	ASSERT_FALSE(gen_eph_pubkey(hash(), out));
	ASSERT_FALSE(gen_eph_pubkey(group_order, out));
}

TEST(carrot, gen_sender_receiver_secret)
{
	// Vector from Monero's carrot_convergence.try_make_carrot_shared_key_sender test.
	hash out;
	ASSERT_TRUE(gen_sender_receiver_secret(convergence_eph_priv_key, convergence_view_public_key, out));
	ASSERT_EQ(out, convergence_sender_receiver_secret);

	out = convergence_eph_priv_key;
	ASSERT_TRUE(gen_sender_receiver_secret(out, convergence_view_public_key, out));
	ASSERT_EQ(out, convergence_sender_receiver_secret);

	out = convergence_view_public_key;
	ASSERT_TRUE(gen_sender_receiver_secret(convergence_eph_priv_key, out, out));
	ASSERT_EQ(out, convergence_sender_receiver_secret);

	ASSERT_FALSE(gen_sender_receiver_secret(hash(), convergence_view_public_key, out));
	ASSERT_FALSE(gen_sender_receiver_secret(group_order, convergence_view_public_key, out));
	ASSERT_FALSE(gen_sender_receiver_secret(convergence_eph_priv_key, identity_public_key, out));
	ASSERT_FALSE(gen_sender_receiver_secret(convergence_eph_priv_key, invalid_public_key, out));
	ASSERT_FALSE(gen_sender_receiver_secret(convergence_eph_priv_key, torsion_public_key, out));
	ASSERT_FALSE(gen_sender_receiver_secret(two, torsion_public_key, out));
	ASSERT_TRUE(gen_sender_receiver_secret(one, torsion_public_key, out));
}

TEST(carrot, gen_contextualized_sender_receiver_secret)
{
	ASSERT_EQ(gen_contextualized_sender_receiver_secret(convergence_sender_receiver_secret, convergence_eph_pub_key_subaddress, 3812345),                              hash("25cb54120bdf74a519f8953c50c3ce5f00d0928ab83add4ec43b75af8dded1ac"));
	ASSERT_EQ(gen_contextualized_sender_receiver_secret(convergence_sender_receiver_secret, convergence_eph_pub_key_subaddress, 0),                                    hash("08a86fbc7ab62721ed896c56273944cf465086288c4947dd1b2e38d08afd35a0"));
	ASSERT_EQ(gen_contextualized_sender_receiver_secret(convergence_sender_receiver_secret, convergence_eph_pub_key_subaddress, 1),                                    hash("4697636430bb5fa613bd46a619ccb90c4462a40f8b6ecf7ed61c1f48298ed6fe"));
	ASSERT_EQ(gen_contextualized_sender_receiver_secret(convergence_sender_receiver_secret, convergence_eph_pub_key_subaddress, 0xff),                                 hash("20f5f62e40926823d005c54b283a82666348d7aaae55a9346213cf017dcea55d"));
	ASSERT_EQ(gen_contextualized_sender_receiver_secret(convergence_sender_receiver_secret, convergence_eph_pub_key_subaddress, 0x100),                                hash("1a3709ff74a527fb54551f3434beec3d5395cdc86218a6bbddcc2a2b67792129"));
	ASSERT_EQ(gen_contextualized_sender_receiver_secret(convergence_sender_receiver_secret, convergence_eph_pub_key_subaddress, 0xffffffffUL),                         hash("36e5d243210c6300b1f99015534ee6475e714d248c331a0fa33df0d94b6ceae8"));
	ASSERT_EQ(gen_contextualized_sender_receiver_secret(convergence_sender_receiver_secret, convergence_eph_pub_key_subaddress, 0x100000000ULL),                       hash("45d1069cd97a3d50bb8d97aab8f25e10fdc8a790d3a1871b2f628e09844e2b5c"));
	ASSERT_EQ(gen_contextualized_sender_receiver_secret(convergence_sender_receiver_secret, convergence_eph_pub_key_subaddress, 0x100000000000000ULL),                 hash("d9af3e721e68a0811168eb8180f2f46fa922eeb13532fd4bc73b488db6e2f49b"));
	ASSERT_EQ(gen_contextualized_sender_receiver_secret(convergence_sender_receiver_secret, convergence_eph_pub_key_subaddress, std::numeric_limits<uint64_t>::max()), hash("3a14bdf375b0ff2163f8a5e61a384f57af7afa3ac28f5856db892626baf85e3d"));

	ASSERT_NE(gen_contextualized_sender_receiver_secret(convergence_sender_receiver_secret, convergence_eph_pub_key_subaddress, 1),
	          gen_contextualized_sender_receiver_secret(convergence_sender_receiver_secret, convergence_eph_pub_key_subaddress, 0x100000000000000ULL));

	// D_e is hashed as data while s_sr is the hash key, so swapping them must not give the same secret
	ASSERT_NE(gen_contextualized_sender_receiver_secret(convergence_sender_receiver_secret, convergence_eph_pub_key_cryptonote, 3812345),
	          gen_contextualized_sender_receiver_secret(convergence_eph_pub_key_cryptonote, convergence_sender_receiver_secret, 3812345));

	ASSERT_EQ(gen_contextualized_sender_receiver_secret(convergence_eph_pub_key_cryptonote, convergence_sender_receiver_secret, 3812345), hash("9404ae50361f3da6028e03078fe11c1caddc8b6940d4f5a39db31d9b8bd28c4c"));
	ASSERT_EQ(gen_contextualized_sender_receiver_secret(hash(), convergence_eph_pub_key_subaddress, 0), hash("f3898a68e2da50294286d29f7fd30d405f04ec961839a5706fc9901dd84b9c1d"));
	ASSERT_EQ(gen_contextualized_sender_receiver_secret(convergence_sender_receiver_secret, hash(), 0), hash("9dd4e5cb4a63419c744f2a0d59238c9bcf9d9ca5a8c2c297f2a97ad9b970233a"));
	ASSERT_EQ(gen_contextualized_sender_receiver_secret(hash(), hash(), 0), hash("2fc1bf02347d71f095d7a1fb678234efe6e80eef7d2a7da49b9d2bdec942ce99"));

	// The whole P2Pool coinbase derivation chain, checked against Monero's vectors at every step
	hash eph_pub_key_out, sender_receiver_secret_out;

	ASSERT_TRUE(gen_eph_pubkey(convergence_eph_priv_key, eph_pub_key_out));
	ASSERT_EQ(eph_pub_key_out, convergence_eph_pub_key_cryptonote);

	ASSERT_TRUE(gen_sender_receiver_secret(convergence_eph_priv_key, convergence_view_public_key, sender_receiver_secret_out));
	ASSERT_EQ(sender_receiver_secret_out, convergence_sender_receiver_secret);

	ASSERT_EQ(gen_contextualized_sender_receiver_secret(sender_receiver_secret_out, eph_pub_key_out, 3812345), hash("422e64bff67b3c0be6a745556b6c1f01d769bd893a70689e82da83a4525ed429"));
}

TEST(carrot, gen_sender_extension)
{
	const hash& s = convergence_contextualized_secret;
	const hash& k = convergence_spend_public_key;

	ASSERT_EQ(gen_sender_extension_g(s, convergence_amount, k), hash("86c8e59ec3f19b652711e1feb53c69af595713d5dac7933525cc122ad2611707"));
	ASSERT_EQ(gen_sender_extension_t(s, convergence_amount, k), hash("b286e46164b6eca2b4fd48ef53a110dda7d7760aa8e817741ba130b4f2abb607"));

	ASSERT_NE(gen_sender_extension_g(s, convergence_amount, k), gen_sender_extension_t(s, convergence_amount, k));

	ASSERT_EQ(gen_sender_extension_g(s, 0, k), hash("22ffd5f470876ad254f4be748c0c710bfc386364fea49bcc37864b1a32746800"));
	ASSERT_EQ(gen_sender_extension_t(s, 0, k), hash("82c14d47c80e86c373c1df11cb0f8c52dbfe9c72dfa6e4ef050460aeba9f7903"));

	ASSERT_EQ(gen_sender_extension_g(s, 1, k), hash("678dec72c356aa92e2021b591941f83cdbf7283765108fa516586c2685bd4300"));
	ASSERT_EQ(gen_sender_extension_t(s, 1, k), hash("eaf647dedad80295022449f8f360888dd8edc4a6807b6c135601db11778b4e01"));

	ASSERT_EQ(gen_sender_extension_g(s, 0xff, k), hash("e5013a58a56ca3025af3a40b8dad0e81ff37f58991da59ce16523faef2a4f900"));
	ASSERT_EQ(gen_sender_extension_t(s, 0xff, k), hash("dd7105a6cf03e6dfc3e1728999aa608054131948e63ea0aaa1656adea5313706"));

	ASSERT_EQ(gen_sender_extension_g(s, 0x100, k), hash("6eba7bb81e19e5b5f9d17b36d071d7606085d9c5888ff06e2c1782ea6f82bd05"));
	ASSERT_EQ(gen_sender_extension_t(s, 0x100, k), hash("14712a1a1c2e4e86b4a870db485e95f067f6e46843566aff58aa0cb6d90a410b"));

	ASSERT_EQ(gen_sender_extension_g(s, 0xffffffffUL, k), hash("e8111f7bb5e99253f04ec238dfaff205b8984ca8d28cdf23fd320c6493ebba0e"));
	ASSERT_EQ(gen_sender_extension_t(s, 0xffffffffUL, k), hash("8dce683278006a5fa09e6ff44d0163d814c63e24d21a66243da8a41bcc7e640a"));

	ASSERT_EQ(gen_sender_extension_g(s, 0x100000000ULL, k), hash("068eae9fdb7a283c1ac556620b7cdb380465e24578c5a05e97e8394d2dec2705"));
	ASSERT_EQ(gen_sender_extension_t(s, 0x100000000ULL, k), hash("56c93999c03505d842cc826c32c059722db4b7b0c0f85139a82a183b1edaae0e"));

	ASSERT_EQ(gen_sender_extension_g(s, 0x100000000000000ULL, k), hash("51beeeb1b8d34a4fc544cc9f0a6b408e6d05042fe130fb52956c8f32df7e3d0b"));
	ASSERT_EQ(gen_sender_extension_t(s, 0x100000000000000ULL, k), hash("0a3a72afe33d63b4a80cc2d2c2707cb76c5873ffdf1293411d76e512f1da2205"));

	ASSERT_NE(gen_sender_extension_g(s, 1, k), gen_sender_extension_g(s, 0x100000000000000ULL, k));

	ASSERT_EQ(gen_sender_extension_g(s, std::numeric_limits<uint64_t>::max(), k), hash("c5401a4e69149b641ce3b0c8a922f3b239860a4a7a3f3445f12259ad6e13e302"));
	ASSERT_EQ(gen_sender_extension_t(s, std::numeric_limits<uint64_t>::max(), k), hash("ca07ec683dec8de3efd8bc482e82a2f454e4ceead35fdfcce4c17908828bdf0b"));

	ASSERT_EQ(gen_sender_extension_g(hash(), convergence_amount, k), hash("520dab93cab6762d55c4507f614bba5686a4445c8488d51e5d60ec45cfa84f0b"));
	ASSERT_EQ(gen_sender_extension_t(hash(), convergence_amount, k), hash("8e7524e25feca23a5caf903fc2c0060096eba84186c0bb8fd7e5a618d2388100"));

	ASSERT_EQ(gen_sender_extension_g(s, convergence_amount, hash()), hash("02c24bca4071cc201ee259ff1e6b8063810e92929f991ea4fe56736232b3c30c"));
	ASSERT_EQ(gen_sender_extension_t(s, convergence_amount, hash()), hash("07b76a1adf93ab7fae4be3ed86324c990e22f8552e3abbe58856e48d0dc9a302"));

	ASSERT_EQ(gen_sender_extension_g(all_ones, std::numeric_limits<uint64_t>::max(), all_ones), hash("6a8e6d4aee5412e82dabf437008cd48dbfe3995cd8b3896d51ed9ee71018ae05"));
	ASSERT_EQ(gen_sender_extension_t(all_ones, std::numeric_limits<uint64_t>::max(), all_ones), hash("6c8b0c36142877510353c8893b7a3c348c3f981994b075611da31f0525d6d80a"));

	const std::array<uint64_t, 6> amounts = { 0, 1, 0xff, 0x100000000ULL, convergence_amount, std::numeric_limits<uint64_t>::max() };

	for (const uint64_t amount : amounts) {
		const hash ext_g = gen_sender_extension_g(s, amount, k);
		const hash ext_t = gen_sender_extension_t(s, amount, k);

		EXPECT_EQ(sc_check(ext_g.h), 0) << "amount " << amount;
		EXPECT_EQ(sc_check(ext_t.h), 0) << "amount " << amount;
	}
}

// K_o = K_s + k^o_g G + k^o_t T, built from scratch with the generic scalar multiplication routines
static hash reference_onetime_address(const hash& spend_public_key, const hash& sender_extension_g, const hash& sender_extension_t)
{
	ge_p3 T, spend_point;
	EXPECT_EQ(ge_frombytes_vartime(&T, T_bytes), 0);
	EXPECT_EQ(ge_frombytes_vartime(&spend_point, spend_public_key.h), 0);

	ge_p3 extension_g_point, extension_t_point;
	ge_scalarmult_base(&extension_g_point, sender_extension_g.h);
	ge_scalarmult_p3(&extension_t_point, sender_extension_t.h, &T);

	ge_cached tmp_cached;
	ge_p1p1 tmp_p1p1;
	ge_p3 result;

	ge_p3_to_cached(&tmp_cached, &extension_g_point);
	ge_add(&tmp_p1p1, &spend_point, &tmp_cached);
	ge_p1p1_to_p3(&result, &tmp_p1p1);

	ge_p3_to_cached(&tmp_cached, &extension_t_point);
	ge_add(&tmp_p1p1, &result, &tmp_cached);
	ge_p1p1_to_p3(&result, &tmp_p1p1);

	hash out;
	ge_p3_tobytes(out.h, &result);

	return out;
}

TEST(carrot, gen_onetime_address)
{
	const hash& s = convergence_contextualized_secret;
	const hash& k = convergence_spend_public_key;

	const hash sender_extension_g = gen_sender_extension_g(s, convergence_amount, k);
	const hash sender_extension_t = gen_sender_extension_t(s, convergence_amount, k);

	hash onetime_address;

	ASSERT_TRUE(gen_onetime_address(k, sender_extension_g, sender_extension_t, onetime_address));
	ASSERT_EQ(onetime_address, convergence_onetime_address_coinbase);
	ASSERT_EQ(onetime_address, reference_onetime_address(k, sender_extension_g, sender_extension_t));

	// Zero extensions leave the spend public key untouched
	{
		hash h;
		ASSERT_TRUE(gen_onetime_address(k, hash(), hash(), h));
		ASSERT_EQ(h, k);
	}

	// The extensions are not interchangeable
	{
		hash h;
		ASSERT_TRUE(gen_onetime_address(k, sender_extension_t, sender_extension_g, h));
		ASSERT_NE(h, onetime_address);
	}

	// Only one of the two extensions
	{
		hash h1, h2;
		ASSERT_TRUE(gen_onetime_address(k, sender_extension_g, hash(), h1));
		ASSERT_TRUE(gen_onetime_address(k, hash(), sender_extension_t, h2));
		ASSERT_NE(h1, onetime_address);
		ASSERT_NE(h2, onetime_address);
		ASSERT_NE(h1, h2);
		ASSERT_EQ(h1, reference_onetime_address(k, sender_extension_g, hash()));
		ASSERT_EQ(h2, reference_onetime_address(k, hash(), sender_extension_t));
	}

	// With the identity as the spend key, K_o is the sender extension point on its own
	{
		ge_p3 point;
		ge_double_scalarmult_base_T_vartime(&point, sender_extension_g.h, sender_extension_t.h);

		hash extension_point;
		ge_p3_tobytes(extension_point.h, &point);

		hash h;
		ASSERT_TRUE(gen_onetime_address(identity_public_key, sender_extension_g, sender_extension_t, h));
		ASSERT_EQ(h, extension_point);
	}

	// A spend public key which isn't a curve point at all
	ASSERT_FALSE(gen_onetime_address(invalid_public_key, sender_extension_g, sender_extension_t, onetime_address));

	// Points with torsion are accepted here: rejecting them is Wallet's job, because K_o has torsion if and only if K_s does
	{
		hash h;
		ASSERT_TRUE(gen_onetime_address(torsion_public_key, sender_extension_g, sender_extension_t, h));
		ASSERT_EQ(h, reference_onetime_address(torsion_public_key, sender_extension_g, sender_extension_t));
	}

	// Every amount must produce a different one-time address, since k^o_g and k^o_t depend on it
	{
		const std::array<uint64_t, 6> amounts = { 0, 1, 0xff, 0x100000000ULL, convergence_amount, std::numeric_limits<uint64_t>::max() };

		std::vector<hash> addresses;

		for (uint64_t amount : amounts) {
			hash h;
			ASSERT_TRUE(gen_onetime_address(k, gen_sender_extension_g(s, amount, k), gen_sender_extension_t(s, amount, k), h));
			ASSERT_TRUE(std::find(addresses.begin(), addresses.end(), h) == addresses.end());
			addresses.emplace_back(h);
		}
	}

	// Random extensions, cross-checked against the generic routines
	{
		std::mt19937_64 rng(123);

		for (int i = 0; i < 200; ++i) {
			hash a, b;

			for (size_t j = 0; j < HASH_SIZE / sizeof(uint64_t); ++j) {
				a.u64()[j] = rng();
				b.u64()[j] = rng();
			}

			sc_reduce32(a.h);
			sc_reduce32(b.h);

			hash h;
			ASSERT_TRUE(gen_onetime_address(k, a, b, h));
			ASSERT_EQ(h, reference_onetime_address(k, a, b));
		}
	}
}


TEST(carrot, gen_view_tag)
{
	const hash& s_sr = convergence_sender_receiver_secret;
	const hash& k = convergence_onetime_address;

	char buf[CARROT_VIEW_TAG_BYTES * 2 + 1] = {};

	auto check = [&buf](const view_tag& v, const char* expected)
	{
		log::Stream s(buf);
		s << log::hex_buf(&v);

		EXPECT_EQ(std::string_view(buf, CARROT_VIEW_TAG_BYTES * 2), expected);
	};

	check(gen_view_tag(s_sr, 0, k), "e1b385");
	check(gen_view_tag(s_sr, 1, k), "f8fd45");
	check(gen_view_tag(s_sr, 3812345, k), "130d27");
	check(gen_view_tag(s_sr, 0x100000000ULL, k), "4f6c36");
	check(gen_view_tag(s_sr, std::numeric_limits<uint64_t>::max(), k), "71c4f9");

	check(gen_view_tag(s_sr, 0x100000000000000ULL, k), "bb7369");

	check(gen_view_tag(s_sr, 3812345, convergence_onetime_address_coinbase), "e7828b");

	check(gen_view_tag(convergence_contextualized_secret, 3812345, k), "4e67ad");

	check(gen_view_tag(hash(), 0, k), "eab61b");
	check(gen_view_tag(s_sr, 0, hash()), "fd0dcb");
}

TEST(carrot, gen_encrypted_janus_anchor)
{
	const hash& s_ctx = convergence_contextualized_secret;
	const hash& k = convergence_onetime_address;

	char buf[CARROT_JANUS_ANCHOR_BYTES * 2 + 1] = {};

	auto check = [&buf](const janus_anchor& anchor, const char* expected)
	{
		log::Stream s(buf);
		s << anchor;

		EXPECT_EQ(std::string_view(buf, CARROT_JANUS_ANCHOR_BYTES * 2), expected);
	};

	check(gen_encrypted_janus_anchor(s_ctx, convergence_anchor, k), "a149f2098c65dd728daf9146b74c0381");

	check(gen_encrypted_janus_anchor(s_ctx, convergence_anchor, convergence_onetime_address_coinbase), "4473243363dae8741fa6f787bbc77b22");

	check(gen_encrypted_janus_anchor(s_ctx, janus_anchor{}, k), "6ba7e188fb315ad2158ac6b6652408d4");

	check(gen_encrypted_janus_anchor(s_ctx, all_ones_anchor, k), "94581e7704cea52dea7539499adbf72b");

	check(gen_encrypted_janus_anchor(hash(), convergence_anchor, k), "8eb6677cec2f7ddb79947c3c627a4368");
	check(gen_encrypted_janus_anchor(s_ctx, convergence_anchor, hash()), "e6ee29d3243a451d2254dd2b625ebe43");

	const std::array<janus_anchor, 3> anchors = { convergence_anchor, janus_anchor{}, all_ones_anchor };

	for (const janus_anchor& anchor : anchors) {
		const janus_anchor encrypted = gen_encrypted_janus_anchor(s_ctx, anchor, k);
		const janus_anchor decrypted = gen_encrypted_janus_anchor(s_ctx, encrypted, k);

		EXPECT_EQ(memcmp(decrypted.data, anchor.data, CARROT_JANUS_ANCHOR_BYTES), 0);
		EXPECT_NE(memcmp(encrypted.data, anchor.data, CARROT_JANUS_ANCHOR_BYTES), 0);
	}
}

TEST(carrot, coinbase_enote)
{
	constexpr uint64_t amount = 600000000000ULL;
	constexpr uint64_t height = 3812345;

	Wallet w(nullptr);

	ASSERT_TRUE(w.assign(convergence_account_spend_public_key, convergence_account_view_public_key, NetworkType::Mainnet));

	// d_e = H_n(anchor_norm, input_context, K_s, pid)
	hash eph_priv_key_out;
	ASSERT_TRUE(gen_eph_privkey(convergence_anchor, height, w, eph_priv_key_out));

	// D_e = ConvertPointE(d_e G)
	hash eph_pub_key_out;
	ASSERT_TRUE(gen_eph_pubkey(eph_priv_key_out, eph_pub_key_out));
	ASSERT_EQ(eph_pub_key_out, hash("e665b92465a2c041a9ea58aeba5231402556b3d5e578ce6cdd29ff7c5dc75d68"));

	// s_sr = ConvertPointE(d_e K_v)
	hash sender_receiver_secret;
	ASSERT_TRUE(gen_sender_receiver_secret(eph_priv_key_out, w.view_public_key(), sender_receiver_secret));

	// s^ctx_sr = H_32[s_sr](D_e, input_context)
	const hash contextualized_secret = gen_contextualized_sender_receiver_secret(sender_receiver_secret, eph_pub_key_out, height);

	// k^o_g and k^o_t
	const hash sender_extension_g = gen_sender_extension_g(contextualized_secret, amount, w.spend_public_key());
	const hash sender_extension_t = gen_sender_extension_t(contextualized_secret, amount, w.spend_public_key());

	// K_o = K_s + k^o_g G + k^o_t T
	hash onetime_address;
	ASSERT_TRUE(gen_onetime_address(w.spend_public_key(), sender_extension_g, sender_extension_t, onetime_address));
	ASSERT_EQ(onetime_address, hash("79899297f3e205ec2e37db9ff31cf08fa6c5c1112003936490810e06ed1f19ee"));

	char buf[CARROT_JANUS_ANCHOR_BYTES * 2 + 1] = {};

	// vt = H_3[s_sr](input_context, K_o)
	{
		const view_tag v = gen_view_tag(sender_receiver_secret, height, onetime_address);

		log::Stream s(buf);
		s << log::hex_buf(&v);

		ASSERT_EQ(std::string_view(buf, CARROT_VIEW_TAG_BYTES * 2), "3005d4");
	}

	// anchor_enc = anchor_norm XOR H_16[s^ctx_sr](K_o)
	{
		const janus_anchor anchor_enc = gen_encrypted_janus_anchor(contextualized_secret, convergence_anchor, onetime_address);

		log::Stream s(buf);
		s << anchor_enc;

		ASSERT_EQ(std::string_view(buf, CARROT_JANUS_ANCHOR_BYTES * 2), "246b90aaa7e33b9e1c0619d70860c56c");
	}
}

TEST(carrot, coinbase_enote_vectors)
{
	// Known answers produced by Monero's own carrot_core, walking the coinbase chain for each case:
	// make_carrot_enote_ephemeral_privkey, make_carrot_enote_ephemeral_pubkey_cryptonote,
	// try_make_carrot_shared_key_sender, make_carrot_contextualized_sender_receiver_secret,
	// try_make_carrot_onetime_address_coinbase, make_carrot_view_tag and make_carrot_anchor_encryption_mask,
	// each with make_carrot_input_context_coinbase(height).
	//
	// Monero's carrot_convergence fixtures can't be reused directly for the whole chain: several of them
	// take an input_context, and the one they use is an arbitrary 33 bytes, while a coinbase input context
	// is "C" || height || zeros. These were regenerated from the same reference code for the coinbase case,
	// which is the only shape p2pool ever builds.
	struct Vector
	{
		hash spend_public_key;
		hash view_public_key;
		janus_anchor anchor;
		uint64_t height;
		uint64_t amount;
		hash eph_priv_key;
		hash eph_pub_key;
		hash sender_receiver_secret;
		hash contextualized_secret;
		hash onetime_address;
		const char* view_tag;
		const char* anchor_enc;
	};

	static const Vector vectors[] = {
		// convergence account, the vector carrot.coinbase_enote already uses
		{ hash("4198f391723f6c64eb75e4f0e341d576dc344e8a8ad3164444451855dbd862b4"),
		  hash("14d12188409591353096b41abeccf66a88d916dfe0e6d1998672293ebc1cc83d"),
		  { { 0xca, 0xee, 0x13, 0x81, 0x77, 0x54, 0x87, 0xa0, 0x98, 0x25, 0x57, 0xf0, 0xd2, 0x68, 0x0b, 0x55 } },
		  3812345ULL, 600000000000ULL,
		  hash("1d7e3ad3b7fb1ba4a935f1afd9715462b6bd7904a7cb386d1b3035660c0fcf0b"),
		  hash("e665b92465a2c041a9ea58aeba5231402556b3d5e578ce6cdd29ff7c5dc75d68"),
		  hash("81b0c5305287189d7e9ccf68e723cb7fb838d593874f925bc6cab59e906a7a05"),
		  hash("f973ae7cd118cb988f5ee89410142c4894df1f49c138f33a0b1a5c27ee6eef44"),
		  hash("79899297f3e205ec2e37db9ff31cf08fa6c5c1112003936490810e06ed1f19ee"),
		  "3005d4", "246b90aaa7e33b9e1c0619d70860c56c" },
		// height 0, amount 0
		{ hash("4198f391723f6c64eb75e4f0e341d576dc344e8a8ad3164444451855dbd862b4"),
		  hash("14d12188409591353096b41abeccf66a88d916dfe0e6d1998672293ebc1cc83d"),
		  { { 0xca, 0xee, 0x13, 0x81, 0x77, 0x54, 0x87, 0xa0, 0x98, 0x25, 0x57, 0xf0, 0xd2, 0x68, 0x0b, 0x55 } },
		  0ULL, 0ULL,
		  hash("43b0a2e192c6aae9fb02ec729fab9d1b8e8ea48542a980b516266961d5b29600"),
		  hash("91faf11fe12752ffb90b2c637e377991dde3cc887eee56aca53d1b5e35c0e069"),
		  hash("103d9cc297da5c6870a7c0f9d905e23396df938571bd64ebc379372d6a934d71"),
		  hash("eb856676e772926a7544bc93a6ede7d67b9f520ff09bdbdee75f91300ab64373"),
		  hash("f9fda7a4cc21b3d4eea22f7fde8527c1095f03759e3eeba0dc6d9463631aa3a9"),
		  "62a6e7", "24925c2428114fc86fc8f6d50d1b44b2" },
		// maximum amount
		{ hash("4198f391723f6c64eb75e4f0e341d576dc344e8a8ad3164444451855dbd862b4"),
		  hash("14d12188409591353096b41abeccf66a88d916dfe0e6d1998672293ebc1cc83d"),
		  { { 0xca, 0xee, 0x13, 0x81, 0x77, 0x54, 0x87, 0xa0, 0x98, 0x25, 0x57, 0xf0, 0xd2, 0x68, 0x0b, 0x55 } },
		  1ULL, 18446744073709551615ULL,
		  hash("74fb5c26d7c23e2e7be763394833d0d7d242275eef39b90f3a61db05c0564608"),
		  hash("66b2f4c657732d604859272f3e601a8685e816e36f25eafc61189cc4220a0d3e"),
		  hash("93d4f009b19de0da5064db77c3d404b7946c6a6ea0abb55194f8d6039777861e"),
		  hash("ce840a7e9eb700aa836bbd3a12c0a641b50f6486e251c12148cbb1d4e33e89eb"),
		  hash("67a9ba75af0680b750bd5c6eaf8ab811f871e73b558fe45b13cf541541f8b9fe"),
		  "c893a8", "d3a0143df0f55753158443527b5bff2d" },
		// test wallet, height 2^32, zero anchor
		{ hash("48313a5b1865002b25225520212c24806ccb92347089a3fba869a8c7e6586e15"),
		  hash("c24e9aa0f7aef7b37f4ad0a906210f78fc5794b4fa9f73f3ca2bf5a09423b12c"),
		  { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
		  4294967296ULL, 67000000000000ULL,
		  hash("bd0f590dbe1084cecb8a6e9f0ccf8ccdd32d02c2a0463649319d078255891408"),
		  hash("4295788adced1aee81ef7bebf2af71cc51b3ed37e6a94b493552c311158ac82a"),
		  hash("9341ad2394d4d4022491e4400181547e97e8f1256f47b683d2a5b9601239671f"),
		  hash("30218e47d03d4899b265191253c31a073327431cbbadeb11d4dc2d7aaad6aedd"),
		  hash("7cecb3e0cff3524a3c6b5e667de847541ab9b559e5ae900a08bae8f689ae8e99"),
		  "51df2b", "9fea1a0d41518bdc2d97b3ef1d5539e8" },
		// test wallet, maximum height, all-ones anchor
		{ hash("48313a5b1865002b25225520212c24806ccb92347089a3fba869a8c7e6586e15"),
		  hash("c24e9aa0f7aef7b37f4ad0a906210f78fc5794b4fa9f73f3ca2bf5a09423b12c"),
		  { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } },
		  18446744073709551615ULL, 1ULL,
		  hash("eb1f5bc40545c3cd7be4c45881c2bbbe55cf776c981ac6335624c53ab167070a"),
		  hash("44543cb8a7182115c7079d9f42392704470074a59e5a7880138ff2381e1cc20f"),
		  hash("eac4c77e893c9ee0d9f78ba2a23cd6dbdc9d070c899f0e4737a71bb3cc401b25"),
		  hash("77daef1421818a739c8c0513b1d683efcbea2ad7a224db85c4bdc6203556af81"),
		  hash("d090ec2d448bd4ea3a3db320b3e044e0c0e2bde34dc8bc4ba5d2ccb043337c72"),
		  "6cf282", "eaf2251fd3ff70acf02766117355bd07" },
	};

	char buf[CARROT_JANUS_ANCHOR_BYTES * 2 + 1] = {};

	for (const Vector& v : vectors) {
		SCOPED_TRACE(testing::Message() << "height " << v.height << ", amount " << v.amount);

		Wallet w(nullptr);
		ASSERT_TRUE(w.assign(v.spend_public_key, v.view_public_key, NetworkType::Mainnet));

		// d_e = H_n(anchor_norm, input_context, K_s, pid)
		hash eph_priv_key;
		ASSERT_TRUE(gen_eph_privkey(v.anchor, v.height, w, eph_priv_key));
		EXPECT_EQ(eph_priv_key, v.eph_priv_key);

		// D_e = ConvertPointE(d_e G)
		hash eph_pub_key;
		ASSERT_TRUE(gen_eph_pubkey(eph_priv_key, eph_pub_key));
		EXPECT_EQ(eph_pub_key, v.eph_pub_key);

		// s_sr = ConvertPointE(d_e K_v)
		hash sender_receiver_secret;
		ASSERT_TRUE(gen_sender_receiver_secret(eph_priv_key, w.view_public_key(), sender_receiver_secret));
		EXPECT_EQ(sender_receiver_secret, v.sender_receiver_secret);

		// s^ctx_sr = H_32[s_sr](D_e, input_context)
		const hash contextualized_secret = gen_contextualized_sender_receiver_secret(sender_receiver_secret, eph_pub_key, v.height);
		EXPECT_EQ(contextualized_secret, v.contextualized_secret);

		// K_o = K_s + k^o_g G + k^o_t T
		const hash sender_extension_g = gen_sender_extension_g(contextualized_secret, v.amount, w.spend_public_key());
		const hash sender_extension_t = gen_sender_extension_t(contextualized_secret, v.amount, w.spend_public_key());

		hash onetime_address;
		ASSERT_TRUE(gen_onetime_address(w.spend_public_key(), sender_extension_g, sender_extension_t, onetime_address));
		EXPECT_EQ(onetime_address, v.onetime_address);

		// vt = H_3[s_sr](input_context, K_o)
		{
			const view_tag vt = gen_view_tag(sender_receiver_secret, v.height, onetime_address);
			log::Stream s1(buf);
			s1 << log::hex_buf(&vt);
			EXPECT_EQ(std::string_view(buf, CARROT_VIEW_TAG_BYTES * 2), v.view_tag);
		}

		// anchor_enc = anchor_norm XOR H_16[s^ctx_sr](K_o)
		{
			const janus_anchor anchor_enc = gen_encrypted_janus_anchor(contextualized_secret, v.anchor, onetime_address);
			log::Stream s2(buf);
			s2 << anchor_enc;
			EXPECT_EQ(std::string_view(buf, CARROT_JANUS_ANCHOR_BYTES * 2), v.anchor_enc);
		}

		// The batch function has to agree with the scalar chain on all three amount-dependent values
		coinbase_output_input in{};
		in.spend_public_key = w.spend_public_key();
		in.sender_receiver_secret = sender_receiver_secret;
		in.contextualized_sender_receiver_secret = contextualized_secret;
		in.anchor = v.anchor;
		in.amount = v.amount;

		init_crypto_cache();
		thread_pool_init();

		std::vector<coinbase_output> out;
		const bool ok = batch_coinbase_outputs(v.height, { in }, out);

		thread_pool_destroy();
		destroy_crypto_cache();

		ASSERT_TRUE(ok);
		ASSERT_EQ(out.size(), 1U);
		EXPECT_EQ(out[0].onetime_address, v.onetime_address);

		log::Stream s3(buf);
		s3 << log::hex_buf(&out[0].vt);
		EXPECT_EQ(std::string_view(buf, CARROT_VIEW_TAG_BYTES * 2), v.view_tag);

		log::Stream s4(buf);
		s4 << out[0].anchor_enc;
		EXPECT_EQ(std::string_view(buf, CARROT_JANUS_ANCHOR_BYTES * 2), v.anchor_enc);
	}
}

static bool equal_values(const std::vector<std::pair<hash, bool>>& values, const std::vector<hash>& reference)
{
	if (values.size() != reference.size()) {
		return false;
	}

	for (size_t i = 0, n = values.size(); i < n; ++i) {
		if (!values[i].second || (values[i].first != reference[i])) {
			return false;
		}
	}

	return true;
}

TEST(carrot, batch_eph_pubkeys)
{
	init_crypto_cache();
	thread_pool_init();

	ON_SCOPE_LEAVE([]() {
		thread_pool_destroy();
		destroy_crypto_cache();
	});

	std::vector<std::pair<hash, bool>> out(1);

	ASSERT_TRUE(batch_eph_pubkeys({}, out));
	ASSERT_TRUE(out.empty());

	hash one_pub;
	ASSERT_TRUE(gen_eph_pubkey(one, one_pub));

	// Both scalars produce the identity and therefore Z - Y = 0. The group order case verifies that
	// batch_eph_pubkeys() checks the actual denominator instead of only checking whether the input is zero.
	const std::array<hash, 2> zero_denominator_scalars = { hash(), group_order };

	for (const hash& scalar : zero_denominator_scalars) {
		for (size_t invalid_index = 0; invalid_index < 3; ++invalid_index) {
			std::vector<hash> in(3, one);

			in[invalid_index] = scalar;
			out.resize(1);

			// Only the failed element is marked, the rest of the batch is still calculated
			EXPECT_FALSE(batch_eph_pubkeys(in, out));
			ASSERT_EQ(out.size(), 3U);

			for (size_t i = 0; i < 3; ++i) {
				const bool expected_ok = (i != invalid_index);
				EXPECT_EQ(out[i].second, expected_ok) << "scalar " << scalar << ", index " << i;
				EXPECT_EQ(out[i].first, expected_ok ? one_pub : hash()) << "scalar " << scalar << ", index " << i;
			}
		}
	}

	// Exercise every possible bit position in a canonical scalar, with all combinations of the three low bits.
	// This also intentionally includes duplicate scalars.
	std::vector<hash> in;
	in.reserve(253 * 8 + 6);

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

	const size_t eph_priv_key_index = in.size();

	in.emplace_back(eph_priv_key);
	in.emplace_back(eph_priv_key_negated);

	const size_t convergence_index = in.size();

	in.emplace_back(convergence_eph_priv_key);
	in.emplace_back(one);
	in.emplace_back(one);

	std::vector<hash> reference(in.size());

	for (size_t i = 0; i < in.size(); ++i) {
		ASSERT_TRUE(gen_eph_pubkey(in[i], reference[i])) << "scalar index " << i;
	}

	ASSERT_EQ(reference[convergence_index], convergence_eph_pub_key_cryptonote);

	// Disjoint ranges with sizes around all possible parallel_run thread-count boundaries exercise segmented inversion.
	constexpr size_t BOUNDARY_INPUTS = 33 * 34 / 2;

	std::vector<hash> boundary_in;
	std::vector<hash> boundary_reference;

	boundary_in.reserve(BOUNDARY_INPUTS);
	boundary_reference.reserve(BOUNDARY_INPUTS);

	for (uint64_t i = 0; i < BOUNDARY_INPUTS; ++i) {
		hash pub, sec, eph_pub_key;

		const uint64_t entropy = 0xC4A2100000000000ULL + i;
		generate_keys_deterministic(pub, sec, reinterpret_cast<const uint8_t*>(&entropy), sizeof(entropy));

		ASSERT_TRUE(std::find(boundary_in.begin(), boundary_in.end(), sec) == boundary_in.end());
		ASSERT_TRUE(gen_eph_pubkey(sec, eph_pub_key));

		boundary_in.emplace_back(sec);
		boundary_reference.emplace_back(eph_pub_key);
	}

	size_t range_begin = 0;

	for (size_t n = 1; n <= 33; ++n) {
		const size_t range_end = range_begin + n;

		const std::vector<hash> range(boundary_in.begin() + range_begin, boundary_in.begin() + range_end);
		const std::vector<hash> range_reference(boundary_reference.begin() + range_begin, boundary_reference.begin() + range_end);

		out.resize(1);

		ASSERT_TRUE(batch_eph_pubkeys(range, out)) << "batch size " << n;
		EXPECT_EQ(get_last_carrot_public_key_batch_size(), n) << "batch size " << n;
		ASSERT_EQ(out.size(), n);
		EXPECT_TRUE(equal_values(out, range_reference)) << "batch size " << n;

		range_begin = range_end;
	}

	ASSERT_EQ(range_begin, BOUNDARY_INPUTS);

	ASSERT_TRUE(batch_eph_pubkeys(in, out));
	ASSERT_EQ(out.size(), reference.size());

	for (size_t i = 0; i < out.size(); ++i) {
		EXPECT_TRUE(out[i].second) << "scalar index " << i;
		EXPECT_EQ(out[i].first, reference[i]) << "scalar index " << i;
	}

	// Duplicate and negated scalars are valid inputs here; transaction-level code checks D_e uniqueness.
	ASSERT_EQ(out[out.size() - 1].first, out[out.size() - 2].first);
	ASSERT_EQ(out[eph_priv_key_index].first, out[eph_priv_key_index + 1].first);

	// A repeated batch is served entirely from the cache and schedules no parallel work.
	ASSERT_TRUE(batch_eph_pubkeys(in, out));
	EXPECT_EQ(get_last_carrot_public_key_batch_size(), 0U);
	ASSERT_TRUE(equal_values(out, reference));

	// Scatter new scalars across the original index range and process only those compacted misses.
	std::vector<hash> scattered_in = in;
	std::vector<hash> scattered_reference = reference;

	const std::array<size_t, 3> scattered_indices = { 0, in.size() / 2, in.size() - 1 };

	for (const size_t i : scattered_indices) {
		hash pub;

		const uint64_t entropy = 0xC4A2200000000000ULL + i;
		generate_keys_deterministic(pub, scattered_in[i], reinterpret_cast<const uint8_t*>(&entropy), sizeof(entropy));

		ASSERT_TRUE(std::find(in.begin(), in.end(), scattered_in[i]) == in.end());
		ASSERT_TRUE(std::find(boundary_in.begin(), boundary_in.end(), scattered_in[i]) == boundary_in.end());
		ASSERT_TRUE(gen_eph_pubkey(scattered_in[i], scattered_reference[i]));
	}

	ASSERT_TRUE(batch_eph_pubkeys(scattered_in, out));
	EXPECT_EQ(get_last_carrot_public_key_batch_size(), scattered_indices.size());
	ASSERT_TRUE(equal_values(out, scattered_reference));

	// A single failed element doesn't hide the results for a large batch, and it isn't cached either
	std::vector<hash> mixed_in = in;
	mixed_in[in.size() / 3] = group_order;

	ASSERT_FALSE(batch_eph_pubkeys(mixed_in, out));
	EXPECT_EQ(get_last_carrot_public_key_batch_size(), 1U);
	ASSERT_EQ(out.size(), reference.size());

	for (size_t i = 0; i < out.size(); ++i) {
		if (i == in.size() / 3) {
			EXPECT_FALSE(out[i].second) << "scalar index " << i;
			EXPECT_EQ(out[i].first, hash()) << "scalar index " << i;
		}
		else {
			EXPECT_TRUE(out[i].second) << "scalar index " << i;
			EXPECT_EQ(out[i].first, reference[i]) << "scalar index " << i;
		}
	}

	ASSERT_FALSE(batch_eph_pubkeys(mixed_in, out));
	EXPECT_EQ(get_last_carrot_public_key_batch_size(), 1U);
}

TEST(carrot, batch_sender_receiver_secrets)
{
	init_crypto_cache();
	thread_pool_init();

	ON_SCOPE_LEAVE([]() {
		thread_pool_destroy();
		destroy_crypto_cache();
	});

	std::vector<std::pair<hash, bool>> out(1);

	ASSERT_TRUE(batch_sender_receiver_secrets({}, {}, out));
	ASSERT_TRUE(out.empty());

	ASSERT_FALSE(batch_sender_receiver_secrets({ one }, {}, out));
	ASSERT_TRUE(out.empty());
	ASSERT_FALSE(batch_sender_receiver_secrets({}, { convergence_view_public_key }, out));
	ASSERT_TRUE(out.empty());

	hash good_secret;
	ASSERT_TRUE(gen_sender_receiver_secret(one, convergence_view_public_key, good_secret));

	for (const hash& k : { convergence_view_public_key, torsion_public_key, identity_public_key, invalid_public_key }) {
		hash scalar_secret;
		const bool scalar_ok = gen_sender_receiver_secret(one, k, scalar_secret);

		std::vector<std::pair<hash, bool>> batched;
		const bool batch_ok = batch_sender_receiver_secrets({ one }, { k }, batched);

		ASSERT_EQ(batched.size(), 1U);
		ASSERT_EQ(scalar_ok, batch_ok);
		ASSERT_EQ(scalar_ok, batched[0].second);

		if (scalar_ok) {
			ASSERT_EQ(scalar_secret, batched[0].first);
		}
	}

	// Only the failed element is marked in each of these cases, the rest of the batch is still calculated
	const std::array<hash, 2> invalid_view_public_keys = { identity_public_key, invalid_public_key };

	for (const hash& invalid_key : invalid_view_public_keys) {
		for (size_t invalid_index = 0; invalid_index < 3; ++invalid_index) {
			const std::vector<hash> eph_priv_keys(3, one);
			std::vector<hash> view_public_keys(3, convergence_view_public_key);

			view_public_keys[invalid_index] = invalid_key;
			out.resize(1);

			EXPECT_FALSE(batch_sender_receiver_secrets(eph_priv_keys, view_public_keys, out));
			ASSERT_EQ(out.size(), 3U);

			for (size_t i = 0; i < 3; ++i) {
				const bool expected_ok = (i != invalid_index);

				EXPECT_EQ(out[i].second, expected_ok) << "key " << invalid_key << ", index " << i;
				EXPECT_EQ(out[i].first, expected_ok ? good_secret : hash()) << "key " << invalid_key << ", index " << i;
			}
		}
	}

	// A zero scalar and the group order both produce the identity, for which Z - Y is zero.
	for (const hash& scalar : { hash(), group_order }) {
		for (size_t invalid_index = 0; invalid_index < 3; ++invalid_index) {
			std::vector<hash> eph_priv_keys(3, one);
			const std::vector<hash> view_public_keys(3, convergence_view_public_key);

			eph_priv_keys[invalid_index] = scalar;
			out.resize(1);

			EXPECT_FALSE(batch_sender_receiver_secrets(eph_priv_keys, view_public_keys, out));
			ASSERT_EQ(out.size(), 3U);

			for (size_t i = 0; i < 3; ++i) {
				const bool expected_ok = (i != invalid_index);

				EXPECT_EQ(out[i].second, expected_ok) << "scalar " << scalar << ", index " << i;
				EXPECT_EQ(out[i].first, expected_ok ? good_secret : hash()) << "scalar " << scalar << ", index " << i;
			}
		}
	}

	// Sharing the point cache with the legacy derivation code must not change its behavior
	hash derivation;
	uint8_t view_tag;

	ASSERT_TRUE(generate_key_derivation(torsion_public_key, one, 0, derivation, view_tag));
	ASSERT_TRUE(batch_sender_receiver_secrets({ one }, { torsion_public_key }, out));
	ASSERT_TRUE(generate_key_derivation(torsion_public_key, two, 0, derivation, view_tag));

	std::vector<hash> eph_priv_keys = { convergence_eph_priv_key };
	std::vector<hash> view_public_keys = { convergence_view_public_key };

	constexpr size_t BOUNDARY_INPUTS = 33 * 34 / 2;
	for (uint64_t i = 1; i < BOUNDARY_INPUTS; ++i) {
		hash pub, sec;
		generate_keys_deterministic(pub, sec, reinterpret_cast<const uint8_t*>(&i), sizeof(i));

		eph_priv_keys.emplace_back(sec);
		view_public_keys.emplace_back(pub);
	}

	std::vector<hash> reference(eph_priv_keys.size());

	for (size_t i = 0; i < reference.size(); ++i) {
		ASSERT_TRUE(gen_sender_receiver_secret(eph_priv_keys[i], view_public_keys[i], reference[i])) << "input index " << i;
	}

	ASSERT_EQ(reference[0], convergence_sender_receiver_secret);

	// Pre-populate an entry with the legacy cache path, which doesn't request a subgroup check.
	ASSERT_TRUE(generate_key_derivation(view_public_keys[0], eph_priv_keys[0], 0, derivation, view_tag));

	// Disjoint ranges with sizes around all possible parallel_run thread-count boundaries exercise segmented inversion.
	size_t range_begin = 0;

	for (size_t n = 1; n <= 33; ++n) {
		const size_t range_end = range_begin + n;

		const std::vector<hash> eph_priv_key_range(eph_priv_keys.begin() + range_begin, eph_priv_keys.begin() + range_end);
		const std::vector<hash> view_public_key_range(view_public_keys.begin() + range_begin, view_public_keys.begin() + range_end);
		const std::vector<hash> range_reference(reference.begin() + range_begin, reference.begin() + range_end);

		out.resize(1);

		ASSERT_TRUE(batch_sender_receiver_secrets(eph_priv_key_range, view_public_key_range, out)) << "batch size " << n;
		EXPECT_EQ(get_last_sender_receiver_secret_batch_size(), n) << "batch size " << n;
		ASSERT_EQ(out.size(), n);
		EXPECT_TRUE(equal_values(out, range_reference)) << "batch size " << n;

		range_begin = range_end;
	}
	ASSERT_EQ(range_begin, BOUNDARY_INPUTS);

	ASSERT_TRUE(batch_sender_receiver_secrets(eph_priv_keys, view_public_keys, out));
	EXPECT_EQ(get_last_sender_receiver_secret_batch_size(), 0U);
	ASSERT_TRUE(equal_values(out, reference));

	// Scatter misses across the original index range and verify that only those compacted entries are processed.
	std::vector<hash> scattered_eph_priv_keys = eph_priv_keys;
	std::vector<hash> scattered_reference = reference;

	const std::array<size_t, 3> scattered_indices = { 0, reference.size() / 2, reference.size() - 1 };

	for (const size_t i : scattered_indices) {
		scattered_eph_priv_keys[i] = eph_priv_keys[(i + 1) % eph_priv_keys.size()];
		ASSERT_TRUE(gen_sender_receiver_secret(scattered_eph_priv_keys[i], view_public_keys[i], scattered_reference[i]));
	}

	ASSERT_TRUE(batch_sender_receiver_secrets(scattered_eph_priv_keys, view_public_keys, out));
	EXPECT_EQ(get_last_sender_receiver_secret_batch_size(), scattered_indices.size());
	ASSERT_TRUE(equal_values(out, scattered_reference));

	// A single failed element doesn't hide the results for a large batch, and it isn't cached either
	std::vector<hash> mixed_view_public_keys = view_public_keys;
	const size_t mixed_index = view_public_keys.size() / 3;
	mixed_view_public_keys[mixed_index] = identity_public_key;

	std::vector<hash> mixed_reference = reference;
	mixed_reference[mixed_index] = hash();

	ASSERT_FALSE(batch_sender_receiver_secrets(eph_priv_keys, mixed_view_public_keys, out));
	EXPECT_EQ(get_last_sender_receiver_secret_batch_size(), 1U);
	ASSERT_EQ(out.size(), reference.size());

	for (size_t i = 0; i < out.size(); ++i) {
		EXPECT_EQ(out[i].second, i != mixed_index) << "input index " << i;
		EXPECT_EQ(out[i].first, mixed_reference[i]) << "input index " << i;
	}

	ASSERT_FALSE(batch_sender_receiver_secrets(eph_priv_keys, mixed_view_public_keys, out));
	EXPECT_EQ(get_last_sender_receiver_secret_batch_size(), 1U);

	// Duplicate elements are valid inputs. Repeated (K_v, d_e) pairs, and one view public key shared by
	// several elements, both have to survive being calculated and cached more than once in the same batch.
	{
		hash dup_view_public_key, dup_eph_priv_key, other_eph_priv_key, other_pub;

		const uint64_t dup_entropy = 0xC4A2300000000000ULL;
		const uint64_t other_entropy = 0xC4A2400000000000ULL;

		generate_keys_deterministic(dup_view_public_key, dup_eph_priv_key, reinterpret_cast<const uint8_t*>(&dup_entropy), sizeof(dup_entropy));
		generate_keys_deterministic(other_pub, other_eph_priv_key, reinterpret_cast<const uint8_t*>(&other_entropy), sizeof(other_entropy));

		ASSERT_TRUE(std::find(view_public_keys.begin(), view_public_keys.end(), dup_view_public_key) == view_public_keys.end());
		ASSERT_NE(dup_eph_priv_key, other_eph_priv_key);

		const std::vector<hash> dup_eph_priv_keys = { dup_eph_priv_key, dup_eph_priv_key, other_eph_priv_key, dup_eph_priv_key };
		const std::vector<hash> dup_view_public_keys(dup_eph_priv_keys.size(), dup_view_public_key);

		std::vector<hash> dup_reference(dup_eph_priv_keys.size());

		for (size_t i = 0; i < dup_reference.size(); ++i) {
			ASSERT_TRUE(gen_sender_receiver_secret(dup_eph_priv_keys[i], dup_view_public_keys[i], dup_reference[i])) << "input index " << i;
		}

		out.resize(1);
		ASSERT_TRUE(batch_sender_receiver_secrets(dup_eph_priv_keys, dup_view_public_keys, out));

		// Only two distinct (K_v, d_e) pairs, but every element is a cache miss and is calculated by the batch
		EXPECT_EQ(get_last_sender_receiver_secret_batch_size(), dup_eph_priv_keys.size());
		ASSERT_TRUE(equal_values(out, dup_reference));

		EXPECT_EQ(out[0].first, out[1].first);
		EXPECT_EQ(out[0].first, out[3].first);
		EXPECT_NE(out[0].first, out[2].first);

		// Both distinct pairs are a single cache entry each now
		ASSERT_TRUE(batch_sender_receiver_secrets(dup_eph_priv_keys, dup_view_public_keys, out));
		EXPECT_EQ(get_last_sender_receiver_secret_batch_size(), 0U);
		ASSERT_TRUE(equal_values(out, dup_reference));
	}
}

static coinbase_output reference_coinbase_output(uint64_t height, const coinbase_output_input& in)
{
	coinbase_output result{};

	const hash sender_extension_g = gen_sender_extension_g(in.contextualized_sender_receiver_secret, in.amount, in.spend_public_key);
	const hash sender_extension_t = gen_sender_extension_t(in.contextualized_sender_receiver_secret, in.amount, in.spend_public_key);

	result.valid = gen_onetime_address(in.spend_public_key, sender_extension_g, sender_extension_t, result.onetime_address);

	if (result.valid) {
		result.vt = gen_view_tag(in.sender_receiver_secret, height, result.onetime_address);
		result.anchor_enc = gen_encrypted_janus_anchor(in.contextualized_sender_receiver_secret, in.anchor, result.onetime_address);
	}
	else {
		result.onetime_address = hash();
	}

	return result;
}

static bool equal_outputs(const coinbase_output& a, const coinbase_output& b)
{
	return (a.valid == b.valid) &&
		(a.onetime_address == b.onetime_address) &&
		(memcmp(&a.vt, &b.vt, sizeof(view_tag)) == 0) &&
		(memcmp(&a.anchor_enc, &b.anchor_enc, sizeof(janus_anchor)) == 0);
}

TEST(carrot, batch_coinbase_outputs)
{
	init_crypto_cache();
	thread_pool_init();

	ON_SCOPE_LEAVE([]() {
		thread_pool_destroy();
		destroy_crypto_cache();
	});

	constexpr uint64_t height = 3812345;
	constexpr uint64_t amount = 600000000000ULL;

	std::vector<coinbase_output> out(1);

	ASSERT_TRUE(batch_coinbase_outputs(height, {}, out));
	ASSERT_TRUE(out.empty());

	// The same enote as in carrot.coinbase_enote, one output at a time
	Wallet w(nullptr);
	ASSERT_TRUE(w.assign(convergence_account_spend_public_key, convergence_account_view_public_key, NetworkType::Mainnet));

	hash eph_priv_key_out;
	ASSERT_TRUE(gen_eph_privkey(convergence_anchor, height, w, eph_priv_key_out));

	hash eph_pub_key_out;
	ASSERT_TRUE(gen_eph_pubkey(eph_priv_key_out, eph_pub_key_out));

	hash sender_receiver_secret;
	ASSERT_TRUE(gen_sender_receiver_secret(eph_priv_key_out, w.view_public_key(), sender_receiver_secret));

	coinbase_output_input known{};
	known.spend_public_key = w.spend_public_key();
	known.sender_receiver_secret = sender_receiver_secret;
	known.contextualized_sender_receiver_secret = gen_contextualized_sender_receiver_secret(sender_receiver_secret, eph_pub_key_out, height);
	known.anchor = convergence_anchor;
	known.amount = amount;

	out.resize(1);

	ASSERT_TRUE(batch_coinbase_outputs(height, { known }, out));
	ASSERT_EQ(out.size(), 1U);
	ASSERT_TRUE(out[0].valid);
	ASSERT_EQ(out[0].onetime_address, hash("79899297f3e205ec2e37db9ff31cf08fa6c5c1112003936490810e06ed1f19ee"));

	{
		char buf[CARROT_JANUS_ANCHOR_BYTES * 2 + 1] = {};

		log::Stream s1(buf);
		s1 << log::hex_buf(&out[0].vt);
		EXPECT_EQ(std::string_view(buf, CARROT_VIEW_TAG_BYTES * 2), "3005d4");

		log::Stream s2(buf);
		s2 << out[0].anchor_enc;
		EXPECT_EQ(std::string_view(buf, CARROT_JANUS_ANCHOR_BYTES * 2), "246b90aaa7e33b9e1c0619d70860c56c");
	}

	EXPECT_TRUE(equal_outputs(out[0], reference_coinbase_output(height, known)));

	// Torsioned and identity spend keys are accepted here for the same reason gen_onetime_address accepts
	// them: K_o has torsion if and only if K_s does, and rejecting that is Wallet's job
	for (const hash& k : { identity_public_key, torsion_public_key }) {
		coinbase_output_input t = known;
		t.spend_public_key = k;

		out.resize(1);

		ASSERT_TRUE(batch_coinbase_outputs(height, { t }, out)) << "spend key " << k;
		ASSERT_EQ(out.size(), 1U);
		EXPECT_TRUE(equal_outputs(out[0], reference_coinbase_output(height, t))) << "spend key " << k;
	}

	// A spend public key which isn't a curve point at all only invalidates its own output.
	// A zero Z there would zero the whole product chain, so this also checks that the dummy point holds.
	for (size_t invalid_index = 0; invalid_index < 3; ++invalid_index) {
		std::vector<coinbase_output_input> in(3, known);
		in[invalid_index].spend_public_key = invalid_public_key;

		// Make the other two differ from each other, so a mixed-up chain can't pass by accident
		in[(invalid_index + 1) % 3].amount = amount + 1;

		out.resize(1);

		EXPECT_FALSE(batch_coinbase_outputs(height, in, out)) << "index " << invalid_index;
		ASSERT_EQ(out.size(), 3U);

		for (size_t i = 0; i < 3; ++i) {
			EXPECT_EQ(out[i].valid, i != invalid_index) << "index " << invalid_index << ", element " << i;
			EXPECT_TRUE(equal_outputs(out[i], reference_coinbase_output(height, in[i]))) << "index " << invalid_index << ", element " << i;
		}

		EXPECT_EQ(out[invalid_index].onetime_address, hash()) << "index " << invalid_index;
	}

	// Identical inputs produce identical K_o. That collision is exactly what the transaction-wide
	// retry_counter has to detect, so the batch must not hide it.
	out.resize(1);
	ASSERT_TRUE(batch_coinbase_outputs(height, { known, known }, out));
	ASSERT_EQ(out.size(), 2U);
	EXPECT_EQ(out[0].onetime_address, out[1].onetime_address);

	// The amount changes K_o, and everything downstream of it
	{
		coinbase_output_input other = known;
		other.amount = amount + 1;

		out.resize(1);
		ASSERT_TRUE(batch_coinbase_outputs(height, { known, other }, out));
		ASSERT_EQ(out.size(), 2U);
		EXPECT_NE(out[0].onetime_address, out[1].onetime_address);
	}

	// The height only reaches the view tag: K_o and the encrypted anchor don't depend on it
	{
		std::vector<coinbase_output> out2;

		ASSERT_TRUE(batch_coinbase_outputs(height, { known }, out));
		ASSERT_TRUE(batch_coinbase_outputs(height + 1, { known }, out2));
		ASSERT_EQ(out.size(), 1U);
		ASSERT_EQ(out2.size(), 1U);

		EXPECT_EQ(out[0].onetime_address, out2[0].onetime_address);
		EXPECT_NE(memcmp(&out[0].vt, &out2[0].vt, sizeof(view_tag)), 0);
		EXPECT_EQ(memcmp(&out[0].anchor_enc, &out2[0].anchor_enc, sizeof(janus_anchor)), 0);
	}

	// Batch sizes around all possible parallel_run thread-count boundaries exercise segmented inversion.
	// Every size is checked against the scalar path, which doesn't depend on the thread count, so this
	// also pins down that the segmented Montgomery chain gives the same bytes however it's split up.
	constexpr size_t BOUNDARY_INPUTS = 33 * 34 / 2;

	std::vector<coinbase_output_input> inputs;
	inputs.reserve(BOUNDARY_INPUTS);
	inputs.emplace_back(known);

	for (uint64_t i = 1; i < BOUNDARY_INPUTS; ++i) {
		hash pub, sec;
		generate_keys_deterministic(pub, sec, reinterpret_cast<const uint8_t*>(&i), sizeof(i));

		coinbase_output_input t{};
		t.spend_public_key = pub;
		t.sender_receiver_secret = sec;
		t.contextualized_sender_receiver_secret = gen_contextualized_sender_receiver_secret(sec, pub, height);
		t.amount = amount + i;
		memcpy(t.anchor.data, sec.h, CARROT_JANUS_ANCHOR_BYTES);

		inputs.emplace_back(t);
	}

	std::vector<coinbase_output> reference(inputs.size());

	for (size_t i = 0; i < reference.size(); ++i) {
		reference[i] = reference_coinbase_output(height, inputs[i]);
		ASSERT_TRUE(reference[i].valid) << "input index " << i;
	}

	size_t range_begin = 0;

	for (size_t n = 1; n <= 33; ++n) {
		const size_t range_end = range_begin + n;

		const std::vector<coinbase_output_input> range(inputs.begin() + range_begin, inputs.begin() + range_end);

		out.resize(1);

		ASSERT_TRUE(batch_coinbase_outputs(height, range, out)) << "batch size " << n;
		ASSERT_EQ(out.size(), n);

		for (size_t i = 0; i < n; ++i) {
			EXPECT_TRUE(equal_outputs(out[i], reference[range_begin + i])) << "batch size " << n << ", element " << i;
		}

		range_begin = range_end;
	}
	ASSERT_EQ(range_begin, BOUNDARY_INPUTS);

	ASSERT_TRUE(batch_coinbase_outputs(height, inputs, out));
	ASSERT_EQ(out.size(), inputs.size());

	for (size_t i = 0; i < inputs.size(); ++i) {
		EXPECT_TRUE(equal_outputs(out[i], reference[i])) << "element " << i;
	}

	// All one-time addresses are distinct, which is what makes the caller's duplicate check meaningful
	{
		std::vector<hash> onetime_addresses;
		onetime_addresses.reserve(out.size());

		for (const coinbase_output& t : out) {
			onetime_addresses.emplace_back(t.onetime_address);
		}

		std::sort(onetime_addresses.begin(), onetime_addresses.end());
		EXPECT_EQ(std::adjacent_find(onetime_addresses.begin(), onetime_addresses.end()), onetime_addresses.end());
	}

	// A single failed element in the middle of a large batch doesn't disturb the rest of it
	{
		std::vector<coinbase_output_input> mixed = inputs;
		const size_t mixed_index = mixed.size() / 3;
		mixed[mixed_index].spend_public_key = invalid_public_key;

		ASSERT_FALSE(batch_coinbase_outputs(height, mixed, out));
		ASSERT_EQ(out.size(), mixed.size());

		for (size_t i = 0; i < mixed.size(); ++i) {
			if (i == mixed_index) {
				EXPECT_FALSE(out[i].valid);
				EXPECT_EQ(out[i].onetime_address, hash());
			}
			else {
				EXPECT_TRUE(equal_outputs(out[i], reference[i])) << "element " << i;
			}
		}
	}
}

static bool equal_anchor(const janus_anchor& a, const janus_anchor& b)
{
	return memcmp(a.data, b.data, CARROT_JANUS_ANCHOR_BYTES) == 0;
}

// 33 wallets is enough to cross every parallel_run thread-count boundary
static std::vector<Wallet> make_test_wallets(size_t n)
{
	std::vector<Wallet> wallets;
	wallets.reserve(n);

	for (uint64_t i = 0; i < n; ++i) {
		const uint64_t si = i * 2, vi = i * 2 + 1;

		hash spend_pub, spend_sec, view_pub, view_sec;
		generate_keys_deterministic(spend_pub, spend_sec, reinterpret_cast<const uint8_t*>(&si), sizeof(si));
		generate_keys_deterministic(view_pub, view_sec, reinterpret_cast<const uint8_t*>(&vi), sizeof(vi));

		Wallet w(nullptr);
		EXPECT_TRUE(w.assign(spend_pub, view_pub, NetworkType::Mainnet));

		wallets.emplace_back(w);
	}

	return wallets;
}

TEST(carrot, batch_eph_privkeys)
{
	thread_pool_init();

	ON_SCOPE_LEAVE([]() { thread_pool_destroy(); });

	constexpr uint64_t height = 3812345;
	constexpr size_t BOUNDARY_INPUTS = 33 * 34 / 2;

	const hash& txkey_sec = gen_janus_anchor_txkey_sec;

	std::vector<janus_anchor> anchors(1);
	std::vector<hash> eph_priv_keys(1);

	ASSERT_TRUE(batch_eph_privkeys(txkey_sec, 0, height, {}, anchors, eph_priv_keys));
	ASSERT_TRUE(anchors.empty());
	ASSERT_TRUE(eph_priv_keys.empty());

	const std::vector<Wallet> wallets = make_test_wallets(BOUNDARY_INPUTS);

	std::vector<const Wallet*> pointers;
	pointers.reserve(BOUNDARY_INPUTS);

	for (const Wallet& w : wallets) {
		pointers.emplace_back(&w);
	}

	// The batch and the scalar path have to agree element for element
	std::vector<janus_anchor> reference_anchors(BOUNDARY_INPUTS);
	std::vector<hash> reference_keys(BOUNDARY_INPUTS);

	for (size_t i = 0; i < BOUNDARY_INPUTS; ++i) {
		reference_anchors[i] = gen_janus_anchor(txkey_sec, 0, wallets[i]);
		ASSERT_TRUE(gen_eph_privkey(reference_anchors[i], height, wallets[i], reference_keys[i])) << "index " << i;
	}

	// Disjoint ranges with sizes around all possible parallel_run thread-count boundaries.
	// Every size is checked against the scalar path, which doesn't depend on the thread count.
	size_t range_begin = 0;

	for (size_t n = 1; n <= 33; ++n) {
		const size_t range_end = range_begin + n;

		const std::vector<const Wallet*> range(pointers.begin() + range_begin, pointers.begin() + range_end);

		anchors.resize(1);
		eph_priv_keys.resize(1);

		ASSERT_TRUE(batch_eph_privkeys(txkey_sec, 0, height, range, anchors, eph_priv_keys)) << "batch size " << n;
		ASSERT_EQ(anchors.size(), n);
		ASSERT_EQ(eph_priv_keys.size(), n);

		for (size_t i = 0; i < n; ++i) {
			EXPECT_TRUE(equal_anchor(anchors[i], reference_anchors[range_begin + i])) << "batch size " << n << ", element " << i;
			EXPECT_EQ(eph_priv_keys[i], reference_keys[range_begin + i]) << "batch size " << n << ", element " << i;
		}

		range_begin = range_end;
	}
	ASSERT_EQ(range_begin, BOUNDARY_INPUTS);

	// Sizes on both sides of the point where the function stops running inline and dispatches
	// parallel_run. The two paths must agree exactly - the split is an optimization, not a behavior.
	for (const size_t n : { 40U, 64U, 78U, 79U, 80U, 81U, 82U, 84U, 96U, 128U }) {
		const std::vector<const Wallet*> range(pointers.begin(), pointers.begin() + n);

		anchors.resize(1);
		eph_priv_keys.resize(1);

		ASSERT_TRUE(batch_eph_privkeys(txkey_sec, 0, height, range, anchors, eph_priv_keys)) << "batch size " << n;
		ASSERT_EQ(anchors.size(), n);

		for (size_t i = 0; i < n; ++i) {
			EXPECT_TRUE(equal_anchor(anchors[i], reference_anchors[i])) << "batch size " << n << ", element " << i;
			EXPECT_EQ(eph_priv_keys[i], reference_keys[i]) << "batch size " << n << ", element " << i;
		}
	}

	ASSERT_TRUE(batch_eph_privkeys(txkey_sec, 0, height, pointers, anchors, eph_priv_keys));
	ASSERT_EQ(anchors.size(), BOUNDARY_INPUTS);

	for (size_t i = 0; i < BOUNDARY_INPUTS; ++i) {
		EXPECT_TRUE(equal_anchor(anchors[i], reference_anchors[i])) << "element " << i;
		EXPECT_EQ(eph_priv_keys[i], reference_keys[i]) << "element " << i;
	}

	// All anchors and all keys are distinct, which is what the Carrot duplicate checks rely on
	{
		std::vector<hash> sorted = eph_priv_keys;
		std::sort(sorted.begin(), sorted.end());
		EXPECT_EQ(std::adjacent_find(sorted.begin(), sorted.end()), sorted.end());
	}

	// retry_counter and txkey_sec both change the anchor, and the key with it
	{
		std::vector<janus_anchor> other_anchors;
		std::vector<hash> other_keys;

		ASSERT_TRUE(batch_eph_privkeys(txkey_sec, 1, height, pointers, other_anchors, other_keys));
		EXPECT_FALSE(equal_anchor(other_anchors[0], anchors[0]));
		EXPECT_NE(other_keys[0], eph_priv_keys[0]);

		ASSERT_TRUE(batch_eph_privkeys(hash(), 0, height, pointers, other_anchors, other_keys));
		EXPECT_FALSE(equal_anchor(other_anchors[0], anchors[0]));
		EXPECT_NE(other_keys[0], eph_priv_keys[0]);
	}

	// The height only reaches d_e: the anchor doesn't depend on it
	{
		std::vector<janus_anchor> other_anchors;
		std::vector<hash> other_keys;

		ASSERT_TRUE(batch_eph_privkeys(txkey_sec, 0, height + 1, pointers, other_anchors, other_keys));
		EXPECT_TRUE(equal_anchor(other_anchors[0], anchors[0]));
		EXPECT_NE(other_keys[0], eph_priv_keys[0]);
	}

	// A null wallet only zeroes its own element
	for (size_t null_index = 0; null_index < 3; ++null_index) {
		std::vector<const Wallet*> mixed(pointers.begin(), pointers.begin() + 3);
		mixed[null_index] = nullptr;

		EXPECT_FALSE(batch_eph_privkeys(txkey_sec, 0, height, mixed, anchors, eph_priv_keys)) << "index " << null_index;
		ASSERT_EQ(anchors.size(), 3U);

		for (size_t i = 0; i < 3; ++i) {
			const bool null_element = (i == null_index);

			EXPECT_TRUE(equal_anchor(anchors[i], null_element ? janus_anchor{} : reference_anchors[i])) << "index " << null_index << ", element " << i;
			EXPECT_EQ(eph_priv_keys[i], null_element ? hash() : reference_keys[i]) << "index " << null_index << ", element " << i;
		}
	}
}

TEST(carrot, batch_contextualized_sender_receiver_secrets)
{
	thread_pool_init();

	ON_SCOPE_LEAVE([]() { thread_pool_destroy(); });

	constexpr uint64_t height = 3812345;
	constexpr size_t BOUNDARY_INPUTS = 33 * 34 / 2;

	std::vector<std::pair<hash, bool>> out(1);

	ASSERT_TRUE(batch_contextualized_sender_receiver_secrets({}, {}, height, out));
	ASSERT_TRUE(out.empty());

	// Size mismatch is rejected outright
	out.resize(1);
	ASSERT_FALSE(batch_contextualized_sender_receiver_secrets({ { one, true } }, {}, height, out));
	ASSERT_TRUE(out.empty());

	std::vector<std::pair<hash, bool>> sender_receiver_secrets, eph_pub_keys;
	std::vector<hash> reference(BOUNDARY_INPUTS);

	sender_receiver_secrets.reserve(BOUNDARY_INPUTS);
	eph_pub_keys.reserve(BOUNDARY_INPUTS);

	for (uint64_t i = 0; i < BOUNDARY_INPUTS; ++i) {
		const uint64_t si = i * 2, ei = i * 2 + 1;

		hash s, e, unused;
		generate_keys_deterministic(s, unused, reinterpret_cast<const uint8_t*>(&si), sizeof(si));
		generate_keys_deterministic(e, unused, reinterpret_cast<const uint8_t*>(&ei), sizeof(ei));

		sender_receiver_secrets.emplace_back(s, true);
		eph_pub_keys.emplace_back(e, true);

		reference[i] = gen_contextualized_sender_receiver_secret(s, e, height);
	}

	// Disjoint ranges around every parallel_run thread-count boundary, all against the scalar path
	size_t range_begin = 0;

	for (size_t n = 1; n <= 33; ++n) {
		const size_t range_end = range_begin + n;

		const std::vector<std::pair<hash, bool>> s_range(sender_receiver_secrets.begin() + range_begin, sender_receiver_secrets.begin() + range_end);
		const std::vector<std::pair<hash, bool>> e_range(eph_pub_keys.begin() + range_begin, eph_pub_keys.begin() + range_end);
		const std::vector<hash> range_reference(reference.begin() + range_begin, reference.begin() + range_end);

		out.resize(1);

		ASSERT_TRUE(batch_contextualized_sender_receiver_secrets(s_range, e_range, height, out)) << "batch size " << n;
		ASSERT_EQ(out.size(), n);
		EXPECT_TRUE(equal_values(out, range_reference)) << "batch size " << n;

		range_begin = range_end;
	}
	ASSERT_EQ(range_begin, BOUNDARY_INPUTS);

	// Sizes on both sides of the inline/parallel_run switch, same reasoning as in batch_eph_privkeys
	for (const size_t n : { 40U, 64U, 78U, 79U, 80U, 81U, 82U, 84U, 96U, 128U }) {
		const std::vector<std::pair<hash, bool>> s_range(sender_receiver_secrets.begin(), sender_receiver_secrets.begin() + n);
		const std::vector<std::pair<hash, bool>> e_range(eph_pub_keys.begin(), eph_pub_keys.begin() + n);
		const std::vector<hash> range_reference(reference.begin(), reference.begin() + n);

		out.resize(1);

		ASSERT_TRUE(batch_contextualized_sender_receiver_secrets(s_range, e_range, height, out)) << "batch size " << n;
		ASSERT_EQ(out.size(), n);
		EXPECT_TRUE(equal_values(out, range_reference)) << "batch size " << n;
	}

	ASSERT_TRUE(batch_contextualized_sender_receiver_secrets(sender_receiver_secrets, eph_pub_keys, height, out));
	EXPECT_TRUE(equal_values(out, reference));

	// The height is part of the input context, so it changes every secret
	{
		std::vector<std::pair<hash, bool>> out2;
		ASSERT_TRUE(batch_contextualized_sender_receiver_secrets(sender_receiver_secrets, eph_pub_keys, height + 1, out2));

		for (size_t i = 0; i < BOUNDARY_INPUTS; ++i) {
			EXPECT_NE(out2[i].first, out[i].first) << "element " << i;
		}
	}

	// An invalid input on either side invalidates only its own element, and leaves it unhashed
	for (int side = 0; side < 2; ++side) {
		for (size_t invalid_index = 0; invalid_index < 3; ++invalid_index) {
			std::vector<std::pair<hash, bool>> s_in(sender_receiver_secrets.begin(), sender_receiver_secrets.begin() + 3);
			std::vector<std::pair<hash, bool>> e_in(eph_pub_keys.begin(), eph_pub_keys.begin() + 3);

			((side == 0) ? s_in : e_in)[invalid_index].second = false;

			out.resize(1);

			EXPECT_FALSE(batch_contextualized_sender_receiver_secrets(s_in, e_in, height, out)) << "side " << side << ", index " << invalid_index;
			ASSERT_EQ(out.size(), 3U);

			for (size_t i = 0; i < 3; ++i) {
				const bool expected_ok = (i != invalid_index);

				EXPECT_EQ(out[i].second, expected_ok) << "side " << side << ", index " << invalid_index << ", element " << i;
				EXPECT_EQ(out[i].first, expected_ok ? reference[i] : hash()) << "side " << side << ", index " << invalid_index << ", element " << i;
			}
		}
	}
}

TEST(carrot, sender_receiver_secret_cache_states)
{
	init_crypto_cache();
	thread_pool_init();

	ON_SCOPE_LEAVE([]() {
		thread_pool_destroy();
		destroy_crypto_cache();
	});

	constexpr uint32_t PRESENT = 1U;
	constexpr uint32_t VALID = 2U;
	constexpr uint32_t HAS_PRECOMP = 4U;
	constexpr uint32_t TORSION_CHECKED = 8U;

	std::vector<std::pair<hash, bool>> out;
	hash derivation;
	uint8_t view_tag;

	// Absent and invalid entries. Invalid entries can't have any of the other state flags.
	ASSERT_EQ(get_from_bytes_cache_state(convergence_view_public_key), 0U);
	ASSERT_FALSE(batch_sender_receiver_secrets({ one }, { invalid_public_key }, out));
	ASSERT_EQ(get_from_bytes_cache_state(invalid_public_key), PRESENT);

	// Valid, no precomputation -> the precomputation is added
	clear_crypto_cache();

	ASSERT_TRUE(derive_public_key(one, 0, convergence_view_public_key, derivation));
	ASSERT_EQ(get_from_bytes_cache_state(convergence_view_public_key), PRESENT | VALID);
	ASSERT_TRUE(batch_sender_receiver_secrets({ one }, { convergence_view_public_key }, out));
	ASSERT_EQ(get_from_bytes_cache_state(convergence_view_public_key), PRESENT | VALID | HAS_PRECOMP);

	// Valid and already precomputed by the legacy path -> the existing precomputation is reused
	clear_crypto_cache();

	ASSERT_TRUE(generate_key_derivation(convergence_view_public_key, one, 0, derivation, view_tag));
	ASSERT_EQ(get_from_bytes_cache_state(convergence_view_public_key), PRESENT | VALID | HAS_PRECOMP);
	ASSERT_TRUE(batch_sender_receiver_secrets({ one }, { convergence_view_public_key }, out));
	ASSERT_EQ(get_from_bytes_cache_state(convergence_view_public_key), PRESENT | VALID | HAS_PRECOMP);

	// A point outside the prime order subgroup is cached like any other valid point: these paths
	// don't do a subgroup or torsion check, they rely on Wallet having done it at parse time.
	// TORSION_CHECKED must stay clear here, or a key that was never checked would look checked.
	clear_crypto_cache();

	ASSERT_TRUE(batch_sender_receiver_secrets({ one }, { torsion_public_key }, out));
	ASSERT_EQ(get_from_bytes_cache_state(torsion_public_key), PRESENT | VALID | HAS_PRECOMP);
	ASSERT_TRUE(generate_key_derivation(torsion_public_key, one, 0, derivation, view_tag));
	ASSERT_EQ(get_from_bytes_cache_state(torsion_public_key), PRESENT | VALID | HAS_PRECOMP);

	// check_public_key() adds the torsion flags to the existing entry, and the answer for this
	// key is "not torsion free", so TORSION_FREE stays clear
	ASSERT_FALSE(check_public_key(torsion_public_key));
	ASSERT_EQ(get_from_bytes_cache_state(torsion_public_key), PRESENT | VALID | HAS_PRECOMP | TORSION_CHECKED);
}

} // namespace carrot

} // namespace p2pool
