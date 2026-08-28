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
	ASSERT_FALSE(gen_sender_receiver_secret(one, torsion_public_key, out));
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

	ASSERT_TRUE(w.assign(convergence_account_spend_public_key, convergence_account_view_public_key, NetworkType::Mainnet, false));

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
	//
	// TODO: replace this with gen_onetime_address() once it's implemented
	ge_p3 T_point, spend_point, sender_extension_g_point, sender_extension_t_point, onetime_address_point;
	ge_cached tmp_cached;
	ge_p1p1 tmp_p1p1;

	ASSERT_EQ(ge_frombytes_vartime(&T_point, T_bytes), 0);
	ASSERT_EQ(ge_frombytes_vartime(&spend_point, w.spend_public_key().h), 0);

	ge_scalarmult_base_vartime(&sender_extension_g_point, sender_extension_g.h);
	ge_scalarmult_p3(&sender_extension_t_point, sender_extension_t.h, &T_point);

	ge_p3_to_cached(&tmp_cached, &sender_extension_g_point);
	ge_add(&tmp_p1p1, &spend_point, &tmp_cached);
	ge_p1p1_to_p3(&onetime_address_point, &tmp_p1p1);

	ge_p3_to_cached(&tmp_cached, &sender_extension_t_point);
	ge_add(&tmp_p1p1, &onetime_address_point, &tmp_cached);
	ge_p1p1_to_p3(&onetime_address_point, &tmp_p1p1);

	hash onetime_address;
	ge_p3_tobytes(onetime_address.h, &onetime_address_point);
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

	// Only the failed element is marked in each of these cases, the rest of the batch is still calculated
	const std::array<hash, 3> invalid_view_public_keys = { identity_public_key, invalid_public_key, torsion_public_key };

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

	// The Carrot subgroup result is cached separately and must not change legacy point-cache behavior.
	hash derivation;
	uint8_t view_tag;

	ASSERT_TRUE(generate_key_derivation(torsion_public_key, one, 0, derivation, view_tag));
	ASSERT_FALSE(batch_sender_receiver_secrets({ one }, { torsion_public_key }, out));
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
	mixed_view_public_keys[mixed_index] = torsion_public_key;

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
	constexpr uint32_t SUBGROUP_CHECKED = 8U;
	constexpr uint32_t MAIN_SUBGROUP = 16U;

	std::vector<std::pair<hash, bool>> out;
	hash derivation;
	uint8_t view_tag;

	// Absent and invalid entries. Invalid entries can't have any of the other state flags.
	ASSERT_EQ(get_from_bytes_cache_state(convergence_view_public_key), 0U);
	ASSERT_FALSE(batch_sender_receiver_secrets({ one }, { invalid_public_key }, out));
	ASSERT_EQ(get_from_bytes_cache_state(invalid_public_key), PRESENT);

	// Valid, no precomputation, subgroup unchecked -> valid main subgroup with precomputation.
	clear_crypto_cache();

	ASSERT_TRUE(derive_public_key(one, 0, convergence_view_public_key, derivation));
	ASSERT_EQ(get_from_bytes_cache_state(convergence_view_public_key), PRESENT | VALID);
	ASSERT_TRUE(batch_sender_receiver_secrets({ one }, { convergence_view_public_key }, out));
	ASSERT_EQ(get_from_bytes_cache_state(convergence_view_public_key), PRESENT | VALID | HAS_PRECOMP | SUBGROUP_CHECKED | MAIN_SUBGROUP);

	// Valid, precomputed, subgroup unchecked -> valid main subgroup with the existing precomputation.
	clear_crypto_cache();

	ASSERT_TRUE(generate_key_derivation(convergence_view_public_key, one, 0, derivation, view_tag));
	ASSERT_EQ(get_from_bytes_cache_state(convergence_view_public_key), PRESENT | VALID | HAS_PRECOMP);
	ASSERT_TRUE(batch_sender_receiver_secrets({ one }, { convergence_view_public_key }, out));
	ASSERT_EQ(get_from_bytes_cache_state(convergence_view_public_key), PRESENT | VALID | HAS_PRECOMP | SUBGROUP_CHECKED | MAIN_SUBGROUP);

	// Valid, non-main-subgroup, without and then with a legacy precomputation.
	clear_crypto_cache();

	ASSERT_FALSE(batch_sender_receiver_secrets({ one }, { torsion_public_key }, out));
	ASSERT_EQ(get_from_bytes_cache_state(torsion_public_key), PRESENT | VALID | SUBGROUP_CHECKED);
	ASSERT_TRUE(generate_key_derivation(torsion_public_key, one, 0, derivation, view_tag));
	ASSERT_EQ(get_from_bytes_cache_state(torsion_public_key), PRESENT | VALID | HAS_PRECOMP | SUBGROUP_CHECKED);
	ASSERT_FALSE(batch_sender_receiver_secrets({ one }, { torsion_public_key }, out));
	ASSERT_EQ(get_from_bytes_cache_state(torsion_public_key), PRESENT | VALID | HAS_PRECOMP | SUBGROUP_CHECKED);

	// Valid, precomputed, subgroup unchecked -> checked and rejected as non-main-subgroup.
	clear_crypto_cache();

	ASSERT_TRUE(generate_key_derivation(torsion_public_key, one, 0, derivation, view_tag));
	ASSERT_EQ(get_from_bytes_cache_state(torsion_public_key), PRESENT | VALID | HAS_PRECOMP);
	ASSERT_FALSE(batch_sender_receiver_secrets({ one }, { torsion_public_key }, out));
	ASSERT_EQ(get_from_bytes_cache_state(torsion_public_key), PRESENT | VALID | HAS_PRECOMP | SUBGROUP_CHECKED);
}

} // namespace carrot

} // namespace p2pool
