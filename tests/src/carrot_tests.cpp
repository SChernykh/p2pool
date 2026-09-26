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
#include "pool_block.h"
#include "quantize_rewards.h"
#include "blake2/blake2.h"

#include "gtest/gtest.h"
#include <random>
#include <fstream>
#include <numeric>
#include <sstream>
#include <thread>

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
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static constexpr hash hash_to_bytes_key = keccak("hash_to_bytes key");
static constexpr hash hash_to_scalar_key = keccak("hash_to_scalar key");
static constexpr hash gen_janus_anchor_txkey_sec = keccak("gen_janus_anchor test");

static constexpr char test_wallet_address[] = "44MnN1f3Eto8DZYUWuE5XZNUtE3vcRzt2j6PzqWpPau34e6Cf4fAxt6X2MBmrm6F9YMEiMNjN6W4Shn4pLcfNAja621jwyg";

static constexpr hash eph_priv_key("794486278f8c0a9781fa54400df74be554a0949edb04ae2a68c33e7ad2f63e0e");
static constexpr hash eph_priv_key_negated("748f6f358bd607c154a2a262d102932fab5f6b6124fb51d5973cc1852d09c101");
static constexpr hash eph_pub_key("5cd04e8b809d25b57ef45c5d7441e2b111ffc123cea579580a0d69e923ea480f");

static constexpr janus_anchor convergence_anchor = {
	0xca, 0xee, 0x13, 0x81, 0x77, 0x54, 0x87, 0xa0, 0x98, 0x25, 0x57, 0xf0, 0xd2, 0x68, 0x0b, 0x55
};

static constexpr hash convergence_eph_priv_key("ae5802c6757d77bd7032e071f72fc99c31a01b9f1bc3af2671c482c8e458140e");
static constexpr hash convergence_eph_pub_key_cryptonote("f2296f8bd12d705b63d4d827011dd2b2834f2c3396e3546969110173fd14c11a");
static constexpr hash convergence_eph_pub_key_subaddress("09b26146c8e458ea0822958af12d5f99de17600849388d9f85eabda24934c346");
static constexpr hash convergence_view_public_key("99a684cd429d88815cb1f90b794522b32812388a9f35120cfc08c7435f7bd51f");
static constexpr hash convergence_spend_public_key("97d227d0ff67e521b805d05d3a51390fd889181e334bf68156cb1e2d5aee6dd4");
static constexpr hash convergence_sender_receiver_secret("1ab57d1f23d12d3f67bb52587dd0c74123cbba6e1c4fd10d0a93067caff19647");
static constexpr hash convergence_contextualized_secret("911a15979c3d448aca2b81cd91d16ba2bf2ca4fa4f6dd16ad596c6304eb52227");
static constexpr hash convergence_onetime_address("cd9610e64abdae97e2f8d8580550dbdd0ed543c99740c9c90f9f2cc854841bfa");
static constexpr hash convergence_onetime_address_coinbase("4f01c472b41a0d85f3c9bc88ad38b7fd47a24029508f84aea84f55d221a48d29");
static constexpr uint64_t convergence_amount = 67000000000000ULL;

static constexpr hash convergence_account_spend_public_key("905f67e69c39948e03dacbcfaeb2e766bfb407cdae53f1b11a813df99d9444e5");
static constexpr hash convergence_account_view_public_key("34e4a36c249e3e0d22a4ee4d6a4da5ee89b12dc42223a12195af8dd727eb35fc");

// unbiased_hash_to_ec(keccak("Monero Generator T")), the FCMP++ generator
static constexpr uint8_t T_bytes[HASH_SIZE] = {
	220, 66, 225, 211, 48, 123, 45, 75, 59, 2, 114, 154, 190, 87, 126, 35,
	29, 121, 71, 129, 65, 203, 91, 49, 12, 169, 250, 110, 18, 118, 22, 163
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
	ASSERT_EQ(out, hash("63d0402a4f705488f40a6782b3bdaa3b848ecb16373b32c3f8955ef8de74200e"));

	ASSERT_TRUE(gen_eph_privkey(convergence_anchor, 1, w, out));
	ASSERT_EQ(out, hash("0800e395933abc0dbcc92834a4fa6ac07c2246d6a20bff92aa8690e2c0162b01"));

	ASSERT_TRUE(gen_eph_privkey(convergence_anchor, 0x100000000ULL, w, out));
	ASSERT_EQ(out, hash("434ed6931891ec31da92d47446ba55e6706e61bfb1ff635490215f4ef00c7a0e"));

	ASSERT_TRUE(gen_eph_privkey(convergence_anchor, 0x100000000000000ULL, w, out));
	ASSERT_EQ(out, hash("2a1af4200084b8ca2229f8f7b41e55311af3d4c2fc38cb153d5b9c8b9f3ba606"));

	ASSERT_TRUE(gen_eph_privkey(convergence_anchor, std::numeric_limits<uint64_t>::max(), w, out));
	ASSERT_EQ(out, hash("18759c1967c497f48f066ef56711db806e8f23d36294abe16c93969014c8e208"));

	ASSERT_TRUE(gen_eph_privkey(all_ones_anchor, 3812345, w, out));
	ASSERT_EQ(out, hash("d387fc79d564146b989c149fd7c2507ac3e44be7d0ac51cfef19c8caac589b0d"));

	ASSERT_EQ(sc_check(out.h), 0);
	ASSERT_FALSE(out.empty());
}

TEST(carrot, gen_eph_pubkey)
{
	init_crypto_cache();

	ON_SCOPE_LEAVE([]() { destroy_crypto_cache(); });

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
	init_crypto_cache();

	ON_SCOPE_LEAVE([]() { destroy_crypto_cache(); });

	ASSERT_EQ(gen_contextualized_sender_receiver_secret(convergence_sender_receiver_secret, convergence_eph_pub_key_subaddress, 3812345),                              hash("3132fe87647496d9516e4c0254ecfb49719d869aaf9aa0fe2e1bc462fb4f6a0d"));
	ASSERT_EQ(gen_contextualized_sender_receiver_secret(convergence_sender_receiver_secret, convergence_eph_pub_key_subaddress, 0),                                    hash("551a7f34d59c4b857c9ad4bb6d15bcb4e288aff8637910a1f0bec030a3b2c870"));
	ASSERT_EQ(gen_contextualized_sender_receiver_secret(convergence_sender_receiver_secret, convergence_eph_pub_key_subaddress, 1),                                    hash("17457cba6a862b067b3bc0ccfcf3145876cc9d035b075f241174cd3f1314f760"));
	ASSERT_EQ(gen_contextualized_sender_receiver_secret(convergence_sender_receiver_secret, convergence_eph_pub_key_subaddress, 0xff),                                 hash("b081565f62a79be3240e55efe22e1d2e7a521a2be93c21cd62feac9cf743107e"));
	ASSERT_EQ(gen_contextualized_sender_receiver_secret(convergence_sender_receiver_secret, convergence_eph_pub_key_subaddress, 0x100),                                hash("ebb6721cd51b17e85e6f260ff65b73501866dac69fbbb0228030f23542061ad7"));
	ASSERT_EQ(gen_contextualized_sender_receiver_secret(convergence_sender_receiver_secret, convergence_eph_pub_key_subaddress, 0xffffffffUL),                         hash("9be38da7057281e5d2cb2d4dd25f772e5ed6630290215a25d458189d44d04e7f"));
	ASSERT_EQ(gen_contextualized_sender_receiver_secret(convergence_sender_receiver_secret, convergence_eph_pub_key_subaddress, 0x100000000ULL),                       hash("6060204b96bebf0e75f85ff6b70efa2bb06438b71b6c96b76804c7527ba6fb20"));
	ASSERT_EQ(gen_contextualized_sender_receiver_secret(convergence_sender_receiver_secret, convergence_eph_pub_key_subaddress, 0x100000000000000ULL),                 hash("d0a18efad226efbfbd4a23ab96e71ee8df228b64aa41593a9d4817b3dd1b03ca"));
	ASSERT_EQ(gen_contextualized_sender_receiver_secret(convergence_sender_receiver_secret, convergence_eph_pub_key_subaddress, std::numeric_limits<uint64_t>::max()), hash("97113f24d89c96dfe4bf296121ccf12cd3c5ecf4ddc439a9d56fbe5d12c51629"));

	ASSERT_NE(gen_contextualized_sender_receiver_secret(convergence_sender_receiver_secret, convergence_eph_pub_key_subaddress, 1),
	          gen_contextualized_sender_receiver_secret(convergence_sender_receiver_secret, convergence_eph_pub_key_subaddress, 0x100000000000000ULL));

	// D_e is hashed as data while s_sr is the hash key, so swapping them must not give the same secret
	ASSERT_NE(gen_contextualized_sender_receiver_secret(convergence_sender_receiver_secret, convergence_eph_pub_key_cryptonote, 3812345),
	          gen_contextualized_sender_receiver_secret(convergence_eph_pub_key_cryptonote, convergence_sender_receiver_secret, 3812345));

	ASSERT_EQ(gen_contextualized_sender_receiver_secret(convergence_eph_pub_key_cryptonote, convergence_sender_receiver_secret, 3812345), hash("90f3218de832a77906a84da743f2b8251362cae531293606d84d5825331e80cc"));
	ASSERT_EQ(gen_contextualized_sender_receiver_secret(hash(), convergence_eph_pub_key_subaddress, 0), hash("1e46592cf9b89d2bd8e1bd46ff011b678dca7772d5fc5cf3f7eab9168b167fb5"));
	ASSERT_EQ(gen_contextualized_sender_receiver_secret(convergence_sender_receiver_secret, hash(), 0), hash("6381634570576ee8f049c080d0e5b372fec2ab0061310bb86d5a6270c0a6f123"));
	ASSERT_EQ(gen_contextualized_sender_receiver_secret(hash(), hash(), 0), hash("2fc1bf02347d71f095d7a1fb678234efe6e80eef7d2a7da49b9d2bdec942ce99"));

	// The whole P2Pool coinbase derivation chain, checked against Monero's vectors at every step
	hash eph_pub_key_out, sender_receiver_secret_out;

	ASSERT_TRUE(gen_eph_pubkey(convergence_eph_priv_key, eph_pub_key_out));
	ASSERT_EQ(eph_pub_key_out, convergence_eph_pub_key_cryptonote);

	ASSERT_TRUE(gen_sender_receiver_secret(convergence_eph_priv_key, convergence_view_public_key, sender_receiver_secret_out));
	ASSERT_EQ(sender_receiver_secret_out, convergence_sender_receiver_secret);

	ASSERT_EQ(gen_contextualized_sender_receiver_secret(sender_receiver_secret_out, eph_pub_key_out, 3812345), hash("511222a5c105101125cd869cb6ececa35a9203c08587042aa504ee7f59d58cce"));
}

TEST(carrot, gen_sender_extension)
{
	const hash& s = convergence_contextualized_secret;
	const hash& k = convergence_spend_public_key;

	ASSERT_EQ(gen_sender_extension_g(s, convergence_amount, k), hash("4c9193ad4544275bdb5d4d13c4e862a92a66e363cb93a6e105c2f43115be3e05"));
	ASSERT_EQ(gen_sender_extension_t(s, convergence_amount, k), hash("dc9bff346a7e6d2e05bce5623eb931749d42874b5dde0057db31b0ebaf69a10a"));

	ASSERT_NE(gen_sender_extension_g(s, convergence_amount, k), gen_sender_extension_t(s, convergence_amount, k));

	ASSERT_EQ(gen_sender_extension_g(s, 0, k), hash("86e4cca6a133d70cdfe290cc94e976e2b46800846e70e32e66ee4e99f96b5108"));
	ASSERT_EQ(gen_sender_extension_t(s, 0, k), hash("1c7be908ff264cf08953f00525fa8909e5d598cb6b45737538425446e15b390f"));

	ASSERT_EQ(gen_sender_extension_g(s, 1, k), hash("86e89bf4140ada7577c146de7eb211d7024b1a1da6b64ac2e78e3ebac3ad7704"));
	ASSERT_EQ(gen_sender_extension_t(s, 1, k), hash("8310030112a3ac927facb7ecdde425de91d04ab429a0a415ff1583f590f4af0e"));

	ASSERT_EQ(gen_sender_extension_g(s, 0xff, k), hash("f877b55cf3211581a5d2443dbb9f5dca855b22bb21dfd928d7bf0f171d60b700"));
	ASSERT_EQ(gen_sender_extension_t(s, 0xff, k), hash("dcee82520cc169245848481e9f6a63c6485d5b0e9f90224b7b176aad949b440b"));

	ASSERT_EQ(gen_sender_extension_g(s, 0x100, k), hash("b20db32638eff88a994b26fb0be69ccb0f6c0eeba74e3bdbde23f948492c9c0a"));
	ASSERT_EQ(gen_sender_extension_t(s, 0x100, k), hash("68937eb893b721ae97c9ef7c4fc0b267dc8a5874823789e7533d8514ca2f1902"));

	ASSERT_EQ(gen_sender_extension_g(s, 0xffffffffUL, k), hash("587b919ea4d2f25e268287dbcf82e7b4154a64595284b5012d30d74f31a90106"));
	ASSERT_EQ(gen_sender_extension_t(s, 0xffffffffUL, k), hash("7e24723a2af8def5672b48a4e0761a9014e135eff00afd1e601a47bda0b2d20a"));

	ASSERT_EQ(gen_sender_extension_g(s, 0x100000000ULL, k), hash("80cb739c46a8339935aafdb52a82ba0603e14d67732b96c1709c1f9b0251a40b"));
	ASSERT_EQ(gen_sender_extension_t(s, 0x100000000ULL, k), hash("152fa59e403ec5ea52b02e4defd3e2763e7e62743046bd65ce6e4b14836bb409"));

	ASSERT_EQ(gen_sender_extension_g(s, 0x100000000000000ULL, k), hash("38bc191755a37688a901d9f94a9ef7fd18bca06941a884bc6e850a983cf87a0c"));
	ASSERT_EQ(gen_sender_extension_t(s, 0x100000000000000ULL, k), hash("2f171a9a0cb3ac2fcf466549e779949ed403fe4e5fb6e5c569f91a267c8d7000"));

	ASSERT_NE(gen_sender_extension_g(s, 1, k), gen_sender_extension_g(s, 0x100000000000000ULL, k));

	ASSERT_EQ(gen_sender_extension_g(s, std::numeric_limits<uint64_t>::max(), k), hash("64ff01e6dc990e380b28344b103721c29f3908e015ffa34f9ff22e1e50b60909"));
	ASSERT_EQ(gen_sender_extension_t(s, std::numeric_limits<uint64_t>::max(), k), hash("bf277cc3dad6a38c2b215c4724227c137d135642277ed255b3fb763f43962b04"));

	ASSERT_EQ(gen_sender_extension_g(hash(), convergence_amount, k), hash("405733f8222720a72fa80246bc4af2f4ec27557bc52b93c76c5b00f3437d510d"));
	ASSERT_EQ(gen_sender_extension_t(hash(), convergence_amount, k), hash("80293ea5d0ac9b68552da753a64b707a756581d96d974226bf85def04e1ac801"));

	ASSERT_EQ(gen_sender_extension_g(s, convergence_amount, hash()), hash("eea0b9c7f57ef79a4c591375a26305c2c831650133a58506dd50f35ced522306"));
	ASSERT_EQ(gen_sender_extension_t(s, convergence_amount, hash()), hash("5b30544f396aeb0def2398070599e6dd4be5c9ac79fea58ccd38f368717f600d"));

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
	ge_p3 G, T, spend_point;
	EXPECT_EQ(ge_frombytes_vartime(&G, hash("5866666666666666666666666666666666666666666666666666666666666666").h), 0);
	EXPECT_EQ(ge_frombytes_vartime(&T, T_bytes), 0);
	EXPECT_EQ(ge_frombytes_vartime(&spend_point, spend_public_key.h), 0);

	ge_p3 extension_g_point, extension_t_point;
	ge_scalarmult_p3(&extension_g_point, sender_extension_g.h, &G);
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
	init_crypto_cache();

	ON_SCOPE_LEAVE([]() { destroy_crypto_cache(); });

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

	check(gen_view_tag(s_sr, 0, k), "724499");
	check(gen_view_tag(s_sr, 1, k), "314b67");
	check(gen_view_tag(s_sr, 3812345, k), "0c22ec");
	check(gen_view_tag(s_sr, 0x100000000ULL, k), "db1f5e");
	check(gen_view_tag(s_sr, std::numeric_limits<uint64_t>::max(), k), "daa025");

	check(gen_view_tag(s_sr, 0x100000000000000ULL, k), "0b6e97");

	check(gen_view_tag(s_sr, 3812345, convergence_onetime_address_coinbase), "84c5a3");

	check(gen_view_tag(convergence_contextualized_secret, 3812345, k), "8c7532");

	check(gen_view_tag(hash(), 0, k), "bb075f");
	check(gen_view_tag(s_sr, 0, hash()), "147b94");
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

	check(gen_encrypted_janus_anchor(s_ctx, convergence_anchor, k), "2783bff2477209c30e3c02efb44312e0");

	check(gen_encrypted_janus_anchor(s_ctx, convergence_anchor, convergence_onetime_address_coinbase), "84310bb5a369f769307eee82d8904367");

	check(gen_encrypted_janus_anchor(s_ctx, janus_anchor{}, k), "ed6dac7330268e639619551f662b19b5");

	check(gen_encrypted_janus_anchor(s_ctx, all_ones_anchor, k), "1292538ccfd9719c69e6aae099d4e64a");

	check(gen_encrypted_janus_anchor(hash(), convergence_anchor, k), "17289de1a10a1f459470ef3a2a87ca55");
	check(gen_encrypted_janus_anchor(s_ctx, convergence_anchor, hash()), "c80bc5de7ae14e3119ae2cd2f47a967c");

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
	init_crypto_cache();

	ON_SCOPE_LEAVE([]() { destroy_crypto_cache(); });

	constexpr uint64_t amount = 600000000000ULL;
	constexpr uint64_t height = 3812345;

	Wallet w(nullptr);

	ASSERT_TRUE(w.assign(convergence_account_spend_public_key, convergence_account_view_public_key, NetworkType::Mainnet));

	// d_e = H_n(anchor_norm, input_context, K_s, K_v, pid)
	hash eph_priv_key_out;
	ASSERT_TRUE(gen_eph_privkey(convergence_anchor, height, w, eph_priv_key_out));

	// D_e = ConvertPointE(d_e G)
	hash eph_pub_key_out;
	ASSERT_TRUE(gen_eph_pubkey(eph_priv_key_out, eph_pub_key_out));
	ASSERT_EQ(eph_pub_key_out, hash("5e1ccb90a305060825ca6ce2df32685fac8d2fff26c1d2f299c4d7a1415f0a33"));

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
	ASSERT_EQ(onetime_address, hash("45bf7a2bd2050e4ff329f6e577ad03e59157c356dea673319bc1851b4294a075"));

	char buf[CARROT_JANUS_ANCHOR_BYTES * 2 + 1] = {};

	// vt = H_3[s_sr](input_context, K_o)
	{
		const view_tag v = gen_view_tag(sender_receiver_secret, height, onetime_address);

		log::Stream s(buf);
		s << log::hex_buf(&v);

		ASSERT_EQ(std::string_view(buf, CARROT_VIEW_TAG_BYTES * 2), "4b5dd4");
	}

	// anchor_enc = anchor_norm XOR H_16[s^ctx_sr](K_o)
	{
		const janus_anchor anchor_enc = gen_encrypted_janus_anchor(contextualized_secret, convergence_anchor, onetime_address);

		log::Stream s(buf);
		s << anchor_enc;

		ASSERT_EQ(std::string_view(buf, CARROT_JANUS_ANCHOR_BYTES * 2), "303a38aae1b9885d08947cb66fb04736");
	}
}

TEST(carrot, coinbase_enote_vectors)
{
	init_crypto_cache();
	thread_pool_init();

	ON_SCOPE_LEAVE([]() {
		thread_pool_destroy();
		destroy_crypto_cache();
	});

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
		{ hash("905f67e69c39948e03dacbcfaeb2e766bfb407cdae53f1b11a813df99d9444e5"),
		  hash("34e4a36c249e3e0d22a4ee4d6a4da5ee89b12dc42223a12195af8dd727eb35fc"),
		  { { 0xca, 0xee, 0x13, 0x81, 0x77, 0x54, 0x87, 0xa0, 0x98, 0x25, 0x57, 0xf0, 0xd2, 0x68, 0x0b, 0x55 } },
		  3812345ULL, 600000000000ULL,
		  hash("6395d55ba3bc7ec5e0e2ef7e5b640b193a129deca0c00cb67a307b628d877b06"),
		  hash("5e1ccb90a305060825ca6ce2df32685fac8d2fff26c1d2f299c4d7a1415f0a33"),
		  hash("63127dd4aaeb8a2adfaf4a8cadb6783091a0f600889c22c40b7cabb57e36ca61"),
		  hash("d5ce1a892e38d55c30d21a12e8494caad1a1c4b3ad40ba96ec7d043e8b5b60cd"),
		  hash("45bf7a2bd2050e4ff329f6e577ad03e59157c356dea673319bc1851b4294a075"),
		  "4b5dd4", "303a38aae1b9885d08947cb66fb04736" },
		// height 0, amount 0
		{ hash("905f67e69c39948e03dacbcfaeb2e766bfb407cdae53f1b11a813df99d9444e5"),
		  hash("34e4a36c249e3e0d22a4ee4d6a4da5ee89b12dc42223a12195af8dd727eb35fc"),
		  { { 0xca, 0xee, 0x13, 0x81, 0x77, 0x54, 0x87, 0xa0, 0x98, 0x25, 0x57, 0xf0, 0xd2, 0x68, 0x0b, 0x55 } },
		  0ULL, 0ULL,
		  hash("cb0fb803c2937543164f991e4a6a9f69671c09e83e574ce361384a3fe6343509"),
		  hash("0224a90e26b42b9001d20aa5858970129b45607ef55d03957d32932d0732955f"),
		  hash("ac452de669a6449331fad34b4c42b5591c75165e0c68561710da50af7c06fd26"),
		  hash("12317c9b207a2e575721dae4b2cd857855b7c4f0e12d4ce385827c92a079dbcb"),
		  hash("d80d1000e8a79c81594e3aff1ee60c33eec19832475589972c34e62d3cbd6f80"),
		  "7cf31c", "8f020891c123264ab32c5fae9c975893" },
		// maximum amount
		{ hash("905f67e69c39948e03dacbcfaeb2e766bfb407cdae53f1b11a813df99d9444e5"),
		  hash("34e4a36c249e3e0d22a4ee4d6a4da5ee89b12dc42223a12195af8dd727eb35fc"),
		  { { 0xca, 0xee, 0x13, 0x81, 0x77, 0x54, 0x87, 0xa0, 0x98, 0x25, 0x57, 0xf0, 0xd2, 0x68, 0x0b, 0x55 } },
		  1ULL, 18446744073709551615ULL,
		  hash("b0de47cc46a71310542945817b8c1a8b561868135619d559e4b6278745482709"),
		  hash("c173b48039bf617fd12b622b59cfe86f14b3e69a52e0586846ee48f7d2c2ff79"),
		  hash("6423eee040be0d0f9b63d1b95aea10f668170199b34b9b48669d0827c1801370"),
		  hash("850b37d4302847c01453841dc6ba4a5b321028f8015104507399764a83262243"),
		  hash("dcb4b3f94657c65df05775bf12865b806e1408ff1e6224a1aa6ae1cd28dafed1"),
		  "acc257", "7d0a24df00139a43fc627915d830d62c" },
		// test wallet, height 2^32, zero anchor
		{ hash("48313a5b1865002b25225520212c24806ccb92347089a3fba869a8c7e6586e15"),
		  hash("c24e9aa0f7aef7b37f4ad0a906210f78fc5794b4fa9f73f3ca2bf5a09423b12c"),
		  { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } },
		  4294967296ULL, 67000000000000ULL,
		  hash("ef2e6bfaf7cd21a8b3d4c2e951e52ddc6953d7f5eb8131b017ed716a1b69e40b"),
		  hash("492d1b32a704dfed8dbf34090af83efe642f4e0d09c38b51f85fefe1a6836e56"),
		  hash("41f51e03e7ae9e951f20116cd280e2455df3a5fdb8af57ca18fc7c6050fd7f51"),
		  hash("ed3829e31e9acc1459dccb4e8ad432033c79f3ae8f1fb339f8c875e8318173a9"),
		  hash("ee3ce12705203e30a9a68c8f3a74fe7f288543154a19f70999eb3d37afcda888"),
		  "73d50f", "78d4d510d8c329d748be4ab702ad6c31" },
		// test wallet, maximum height, all-ones anchor
		{ hash("48313a5b1865002b25225520212c24806ccb92347089a3fba869a8c7e6586e15"),
		  hash("c24e9aa0f7aef7b37f4ad0a906210f78fc5794b4fa9f73f3ca2bf5a09423b12c"),
		  { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } },
		  18446744073709551615ULL, 1ULL,
		  hash("8462ab6ddabb12133e8019b029f789b1f0da452dc22e77520e6cc3710beeba09"),
		  hash("49785a2eae04bf254291ea0d753bca20ed106c1deeb4c721660a2c63adc67a7d"),
		  hash("e6e2fe3c577ff9f49a2c1b540da9848a6d8648d0c9cf3dc58bc2e11350cbda7e"),
		  hash("ef7226980986221c23cf93eddc3872cf47ba3e4a9c4c13e248b4ebdc5ce13720"),
		  hash("bf1b6148fb514176b7c1ab686e0b5ab07978584ddbd8f520ebdc877cb8f08ff9"),
		  "b926ac", "12d36007b1178c47b98c011fdf35e650" },
		// convergence main address (K_s, k_v G)
		{ hash("905f67e69c39948e03dacbcfaeb2e766bfb407cdae53f1b11a813df99d9444e5"),
		  hash("19925849a0ededef6ea6604f707f45567056205f9d32511a57ecf63081b3a106"),
		  { { 0xca, 0xee, 0x13, 0x81, 0x77, 0x54, 0x87, 0xa0, 0x98, 0x25, 0x57, 0xf0, 0xd2, 0x68, 0x0b, 0x55 } },
		  3812345ULL, 600000000000ULL,
		  hash("95c5aea280cb6fd67c62de8bc4be1d7b268ace61ea66f9682789feb4bfe8240e"),
		  hash("5769be98d5c4d3005d1d7ddf4cbdaac3182275ac5039760f19d45a33003ae640"),
		  hash("da6f686d655e0c35ce8dcb011e3f1ef8af23e526e1c3694f8a10a8c849b5475f"),
		  hash("5f01a99782fb263d9a651e5a30e9f5e3b4a0d08c9d34ce11d750e7a06ee3cb1e"),
		  hash("e2efd74a233fd8488d6bbf88e474d9d73cb22588627907611c84dc9012cec64f"),
		  "c13696", "a326f5c233637c18f7c803b8028f5c9b" },
	};

	char buf[CARROT_JANUS_ANCHOR_BYTES * 2 + 1] = {};

	for (const Vector& v : vectors) {
		SCOPED_TRACE(testing::Message() << "height " << v.height << ", amount " << v.amount);

		Wallet w(nullptr);
		ASSERT_TRUE(w.assign(v.spend_public_key, v.view_public_key, NetworkType::Mainnet));

		// d_e = H_n(anchor_norm, input_context, K_s, K_v, pid)
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

		std::vector<coinbase_tx_output> out;
		ASSERT_TRUE(batch_coinbase_outputs(v.height, { in }, out));
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

	// A repeated batch gives the same results
	ASSERT_TRUE(batch_eph_pubkeys(in, out));
	ASSERT_TRUE(equal_values(out, reference));

	// Scatter new scalars across the original index range
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
	ASSERT_TRUE(equal_values(out, scattered_reference));

	// A single failed element doesn't hide the results for a large batch
	std::vector<hash> mixed_in = in;
	mixed_in[in.size() / 3] = group_order;

	ASSERT_FALSE(batch_eph_pubkeys(mixed_in, out));
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
		ASSERT_EQ(out.size(), n);
		EXPECT_TRUE(equal_values(out, range_reference)) << "batch size " << n;

		range_begin = range_end;
	}
	ASSERT_EQ(range_begin, BOUNDARY_INPUTS);

	// Every view public key has a comb table now, and the whole batch uses them
	ASSERT_TRUE(batch_sender_receiver_secrets(eph_priv_keys, view_public_keys, out));
	ASSERT_TRUE(equal_values(out, reference));

	// Different scalars for some of the same view public keys
	std::vector<hash> scattered_eph_priv_keys = eph_priv_keys;
	std::vector<hash> scattered_reference = reference;

	const std::array<size_t, 3> scattered_indices = { 0, reference.size() / 2, reference.size() - 1 };

	for (const size_t i : scattered_indices) {
		scattered_eph_priv_keys[i] = eph_priv_keys[(i + 1) % eph_priv_keys.size()];
		ASSERT_TRUE(gen_sender_receiver_secret(scattered_eph_priv_keys[i], view_public_keys[i], scattered_reference[i]));
	}

	ASSERT_TRUE(batch_sender_receiver_secrets(scattered_eph_priv_keys, view_public_keys, out));
	ASSERT_TRUE(equal_values(out, scattered_reference));

	// A single failed element doesn't hide the results for a large batch
	std::vector<hash> mixed_view_public_keys = view_public_keys;
	const size_t mixed_index = view_public_keys.size() / 3;
	mixed_view_public_keys[mixed_index] = identity_public_key;

	std::vector<hash> mixed_reference = reference;
	mixed_reference[mixed_index] = hash();

	ASSERT_FALSE(batch_sender_receiver_secrets(eph_priv_keys, mixed_view_public_keys, out));
	ASSERT_EQ(out.size(), reference.size());

	for (size_t i = 0; i < out.size(); ++i) {
		EXPECT_EQ(out[i].second, i != mixed_index) << "input index " << i;
		EXPECT_EQ(out[i].first, mixed_reference[i]) << "input index " << i;
	}

	ASSERT_FALSE(batch_sender_receiver_secrets(eph_priv_keys, mixed_view_public_keys, out));

	// Duplicate elements are valid inputs. Repeated (K_v, d_e) pairs, and one view public key shared by
	// several elements, both have to survive their comb table being built and cached more than once in the same batch.
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
		ASSERT_TRUE(equal_values(out, dup_reference));

		EXPECT_EQ(out[0].first, out[1].first);
		EXPECT_EQ(out[0].first, out[3].first);
		EXPECT_NE(out[0].first, out[2].first);

		// The shared view public key has a single cache entry with a comb table now
		EXPECT_EQ(get_from_bytes_cache_state(dup_view_public_key), 7U);

		ASSERT_TRUE(batch_sender_receiver_secrets(dup_eph_priv_keys, dup_view_public_keys, out));
		ASSERT_TRUE(equal_values(out, dup_reference));
	}

	// Scalars with a[31] > 127 are too big for ge_scalarmult_comb_vartime(), so they go through a sliding window instead.
	// P2Pool never uses such scalars, but the result must still be right. gen_sender_receiver_secret() can't be the
	// reference here, it has the same a[31] <= 127 pre-condition.
	{
		hash big_scalar = convergence_eph_priv_key;
		big_scalar.h[HASH_SIZE - 1] |= 0x80;

		// G + a point of order 8: reducing the scalar mod l would change the result for this one
		const hash order_8l_public_key("da99e28ba529cdde35a25fba9059e78ecaee239f99755b9b1aa4f65df00803e2");

		for (const hash& k : { convergence_view_public_key, order_8l_public_key }) {
			ge_p3 point;
			ASSERT_EQ(ge_frombytes_vartime(&point, k.h), 0);

			ge_p2 product;
			ge_scalarmult_vartime(&product, big_scalar.h, &point);

			ge_p3 product_p3 = {};
			memcpy(product_p3.Y, product.Y, sizeof(fe));
			memcpy(product_p3.Z, product.Z, sizeof(fe));

			hash expected;
			ASSERT_EQ(ge_p3_to_x25519(expected.h, &product_p3), 0);

			// Without a cached comb table, then with the one the first pass cached
			clear_crypto_cache();

			for (int pass = 0; pass < 2; ++pass) {
				EXPECT_EQ(get_from_bytes_cache_state(k) & 4U, pass ? 4U : 0U) << "key " << k << ", pass " << pass;

				ASSERT_TRUE(batch_sender_receiver_secrets({ big_scalar, convergence_eph_priv_key }, { k, k }, out));
				ASSERT_EQ(out.size(), 2U);
				EXPECT_EQ(out[0].first, expected) << "key " << k << ", pass " << pass;
			}
		}
	}
}

static coinbase_tx_output reference_coinbase_output(uint64_t height, const coinbase_output_input& in)
{
	coinbase_tx_output result{};

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

static bool equal_outputs(const coinbase_tx_output& a, const coinbase_tx_output& b)
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

	std::vector<coinbase_tx_output> out(1);

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
	ASSERT_EQ(out[0].onetime_address, hash("45bf7a2bd2050e4ff329f6e577ad03e59157c356dea673319bc1851b4294a075"));

	{
		char buf[CARROT_JANUS_ANCHOR_BYTES * 2 + 1] = {};

		log::Stream s1(buf);
		s1 << log::hex_buf(&out[0].vt);
		EXPECT_EQ(std::string_view(buf, CARROT_VIEW_TAG_BYTES * 2), "4b5dd4");

		log::Stream s2(buf);
		s2 << out[0].anchor_enc;
		EXPECT_EQ(std::string_view(buf, CARROT_JANUS_ANCHOR_BYTES * 2), "303a38aae1b9885d08947cb66fb04736");
	}

	EXPECT_TRUE(equal_outputs(out[0], reference_coinbase_output(height, known)));

	// Each independently supplied secret/anchor goes into the output
	for (size_t field = 0; field < 3; ++field) {
		coinbase_output_input changed = known;

		if (field == 0) changed.sender_receiver_secret.h[0] ^= 1;
		if (field == 1) changed.contextualized_sender_receiver_secret.h[0] ^= 1;
		if (field == 2) changed.anchor.data[0] ^= 1;

		ASSERT_TRUE(batch_coinbase_outputs(height, { known, changed }, out));
		EXPECT_TRUE(equal_outputs(out[0], reference_coinbase_output(height, known)));
		EXPECT_TRUE(equal_outputs(out[1], reference_coinbase_output(height, changed)));
		EXPECT_FALSE(equal_outputs(out[0], out[1]));
		ASSERT_TRUE(batch_coinbase_outputs(height, { changed, known }, out));
		EXPECT_TRUE(equal_outputs(out[0], reference_coinbase_output(height, changed)));
	}

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
		std::vector<coinbase_tx_output> out2;

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

	std::vector<coinbase_tx_output> reference(inputs.size());

	for (size_t i = 0; i < reference.size(); ++i) {
		reference[i] = reference_coinbase_output(height, inputs[i]);
		ASSERT_TRUE(reference[i].valid) << "input index " << i;
	}

	clear_crypto_cache();

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

		for (const coinbase_tx_output& t : out) {
			onetime_addresses.emplace_back(t.onetime_address);
		}

		std::sort(onetime_addresses.begin(), onetime_addresses.end());
		EXPECT_EQ(std::adjacent_find(onetime_addresses.begin(), onetime_addresses.end()), onetime_addresses.end());
	}

	// Changed elements scattered through the batch stay at their own positions
	{
		auto changed = inputs;

		for (const size_t i : { size_t(0), changed.size() / 2, changed.size() - 1 }) {
			changed[i].amount += 1234567;
		}

		ASSERT_TRUE(batch_coinbase_outputs(height, changed, out));

		for (size_t i = 0; i < changed.size(); ++i) {
			EXPECT_TRUE(equal_outputs(out[i], reference_coinbase_output(height, changed[i]))) << i;
		}
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

	// Construction, verification and cleanup of the spend public key cache can run concurrently.
	std::thread workers[2];

	for (auto& worker : workers) {
		worker = std::thread([&]() {
			for (size_t pass = 0; pass < 3; ++pass) {
				std::vector<coinbase_tx_output> outputs;
				EXPECT_TRUE(batch_coinbase_outputs(height, inputs, outputs));
				for (size_t i = 0; i < inputs.size(); ++i) {
					EXPECT_TRUE(equal_outputs(outputs[i], reference[i])) << i;
				}
			}
		});
	}

	clear_crypto_cache();

	for (auto& worker : workers) {
		worker.join();
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

TEST(carrot, prewarm_coinbase_outputs)
{
	init_crypto_cache();
	thread_pool_init();

	ON_SCOPE_LEAVE([]() {
		thread_pool_destroy();
		destroy_crypto_cache();
	});

	const auto wallets = make_test_wallets(3);
	const hash txkey_sec = keccak("Carrot pre-warmup");

	constexpr uint64_t height = 3812345;
	constexpr uint64_t T = PAYOUT_GRID_STEP;

	PPLNSWindow window;

	// Exact payouts: 10.2 T, 2.7 T, 0.1 T. The last wallet normally gets no output.
	window.m_shares.emplace_back(difficulty_type(102), &wallets[0]);
	window.m_shares.emplace_back(difficulty_type(27), &wallets[1]);
	window.m_shares.emplace_back(difficulty_type(1), &wallets[2]);

	for (bool truncated : { false, true }) {
		clear_crypto_cache();

		window.m_weightTruncated = truncated;

		prewarm_coinbase_outputs(txkey_sec, height, window, 13 * T);
		EXPECT_EQ(get_last_coinbase_output_batch_size(), truncated ? 8U : 6U);

		prewarm_coinbase_outputs(txkey_sec, height, window, 13 * T);
		EXPECT_EQ(get_last_coinbase_output_batch_size(), 0U);

		std::vector<const Wallet*> pair_wallets;
		std::vector<uint64_t> amounts;
		std::vector<coinbase_output_input> inputs;

		for (size_t i = 0; i < wallets.size(); ++i) {
			coinbase_output_input input{};

			input.spend_public_key = wallets[i].spend_public_key();
			input.anchor = gen_janus_anchor(txkey_sec, 0, wallets[i]);

			hash priv, pub;

			ASSERT_TRUE(gen_eph_privkey(input.anchor, height, wallets[i], priv));
			ASSERT_TRUE(gen_eph_pubkey(priv, pub));
			ASSERT_TRUE(gen_sender_receiver_secret(priv, wallets[i].view_public_key(), input.sender_receiver_secret));

			input.contextualized_sender_receiver_secret = gen_contextualized_sender_receiver_secret(input.sender_receiver_secret, pub, height);

			const uint64_t lo[] = { truncated ? 9U : 10U, truncated ? 1U : 2U, 1U };
			const uint64_t hi[] = { 12, 3, 1 };

			for (uint64_t k = lo[i]; k <= hi[i]; ++k) {
				input.amount = k * T;
				inputs.emplace_back(input);

				pair_wallets.emplace_back(&wallets[i]);
				amounts.emplace_back(k * T);
			}
		}

		std::vector<coinbase_secrets> secrets;
		std::vector<coinbase_tx_output> out;

		// Everything is in the cache already
		ASSERT_TRUE(batch_coinbase_secrets(txkey_sec, 0, height, pair_wallets, amounts, secrets, out));
		EXPECT_EQ(get_last_coinbase_secrets_batch_size(), 0U);
		ASSERT_TRUE(complete_coinbase_outputs(txkey_sec, 0, height, pair_wallets, amounts, secrets, out));
		EXPECT_EQ(get_last_coinbase_output_batch_size(), 0U);

		for (size_t i = 0; i < inputs.size(); ++i) {
			EXPECT_TRUE(equal_outputs(out[i], reference_coinbase_output(height, inputs[i]))) << i;
		}

		// The range is bounded on both sides; off-grid amounts remain on demand.
		const std::vector<const Wallet*> wallet0(3, &wallets[0]);
		const std::vector<uint64_t> off_grid = { (truncated ? 8 : 9) * T, 13 * T, 10 * T + 1 };

		ASSERT_TRUE(batch_coinbase_secrets(txkey_sec, 0, height, wallet0, off_grid, secrets, out));
		ASSERT_TRUE(complete_coinbase_outputs(txkey_sec, 0, height, wallet0, off_grid, secrets, out));
		EXPECT_EQ(get_last_coinbase_output_batch_size(), 3U);
	}

	// Same-height reorgs change txkey_sec; a new height changes the input context.
	for (const auto& epoch : { std::make_pair(keccak("alternate tx key"), height), std::make_pair(txkey_sec, height + 1) }) {
		prewarm_coinbase_outputs(epoch.first, epoch.second, window, 13 * T);
		EXPECT_EQ(get_last_coinbase_output_batch_size(), 8U);
	}

	// A large payout (1000 T, so 1000 T...1100 T) gets only as many amounts as the cache keeps for one wallet, the lowest ones
	{
		PPLNSWindow solo;
		solo.m_shares.emplace_back(difficulty_type(1), &wallets[0]);

		clear_crypto_cache();

		prewarm_coinbase_outputs(txkey_sec, height, solo, 1000 * T);
		EXPECT_EQ(get_last_coinbase_output_batch_size(), MAX_COINBASE_OUTPUTS_PER_WALLET);

		std::vector<uint64_t> a;

		for (uint64_t k = 999; k <= 1000 + MAX_COINBASE_OUTPUTS_PER_WALLET; ++k) {
			a.emplace_back(k * T);
		}

		std::vector<coinbase_secrets> secrets;
		std::vector<coinbase_tx_output> out;

		ASSERT_TRUE(batch_coinbase_secrets(txkey_sec, 0, height, std::vector<const Wallet*>(a.size(), &wallets[0]), a, secrets, out));

		for (size_t i = 0; i < a.size(); ++i) {
			const uint64_t k = a[i] / T;
			EXPECT_EQ(out[i].valid, (k >= 1000) && (k < 1000 + MAX_COINBASE_OUTPUTS_PER_WALLET)) << k;
		}
	}
}

// The scalar chain for everything batch_coinbase_secrets() returns
static coinbase_secrets reference_coinbase_secrets(const hash& txkey_sec, uint8_t retry_counter, uint64_t height, const Wallet& w)
{
	coinbase_secrets s{};

	s.anchor = gen_janus_anchor(txkey_sec, retry_counter, w);

	hash eph_priv_key;
	EXPECT_TRUE(gen_eph_privkey(s.anchor, height, w, eph_priv_key));
	EXPECT_TRUE(gen_eph_pubkey(eph_priv_key, s.eph_pub_key));
	EXPECT_TRUE(gen_sender_receiver_secret(eph_priv_key, w.view_public_key(), s.sender_receiver_secret));

	s.contextualized_sender_receiver_secret = gen_contextualized_sender_receiver_secret(s.sender_receiver_secret, s.eph_pub_key, height);

	return s;
}

static bool equal_secrets(const coinbase_secrets& a, const coinbase_secrets& b)
{
	return (a.valid() == b.valid()) &&
		equal_anchor(a.anchor, b.anchor) &&
		(a.eph_pub_key == b.eph_pub_key) &&
		(a.sender_receiver_secret == b.sender_receiver_secret) &&
		(a.contextualized_sender_receiver_secret == b.contextualized_sender_receiver_secret);
}

TEST(carrot, batch_coinbase_secrets)
{
	init_crypto_cache();
	thread_pool_init();

	ON_SCOPE_LEAVE([]() {
		thread_pool_destroy();
		destroy_crypto_cache();
	});

	constexpr uint64_t height = 3812345;
	constexpr size_t BOUNDARY_INPUTS = 33 * 34 / 2;

	const hash& txkey_sec = gen_janus_anchor_txkey_sec;

	std::vector<coinbase_secrets> secrets(1);

	ASSERT_TRUE(batch_coinbase_secrets(txkey_sec, 0, height, {}, secrets));
	ASSERT_TRUE(secrets.empty());
	EXPECT_EQ(get_last_coinbase_secrets_batch_size(), 0U);

	const std::vector<Wallet> wallets = make_test_wallets(BOUNDARY_INPUTS);

	std::vector<const Wallet*> pointers;
	std::vector<coinbase_secrets> reference;

	for (const Wallet& w : wallets) {
		pointers.emplace_back(&w);
		reference.emplace_back(reference_coinbase_secrets(txkey_sec, 0, height, w));
	}

	// Disjoint ranges with sizes around all possible parallel_run thread-count boundaries. Every element is a cache miss.
	size_t range_begin = 0;

	for (size_t n = 1; n <= 33; ++n) {
		const size_t range_end = range_begin + n;
		const std::vector<const Wallet*> range(pointers.begin() + range_begin, pointers.begin() + range_end);

		secrets.resize(1);

		ASSERT_TRUE(batch_coinbase_secrets(txkey_sec, 0, height, range, secrets)) << "batch size " << n;
		EXPECT_EQ(get_last_coinbase_secrets_batch_size(), n);
		ASSERT_EQ(secrets.size(), n);

		for (size_t i = 0; i < n; ++i) {
			EXPECT_TRUE(equal_secrets(secrets[i], reference[range_begin + i])) << "batch size " << n << ", element " << i;
		}

		range_begin = range_end;
	}
	ASSERT_EQ(range_begin, BOUNDARY_INPUTS);

	// Everything is cached now, in any order
	for (int reversed = 0; reversed < 2; ++reversed) {
		std::vector<const Wallet*> w = pointers;
		std::vector<coinbase_secrets> r = reference;

		if (reversed) {
			std::reverse(w.begin(), w.end());
			std::reverse(r.begin(), r.end());
		}

		ASSERT_TRUE(batch_coinbase_secrets(txkey_sec, 0, height, w, secrets));
		EXPECT_EQ(get_last_coinbase_secrets_batch_size(), 0U);

		for (size_t i = 0; i < w.size(); ++i) {
			EXPECT_TRUE(equal_secrets(secrets[i], r[i])) << "reversed " << reversed << ", element " << i;
		}
	}

	// txkey_sec, retry_counter and height are all part of the cache key
	{
		const std::vector<const Wallet*> w(pointers.begin(), pointers.begin() + 5);
		const hash other_txkey_sec = keccak("batch_coinbase_secrets test");

		const struct { hash key; uint8_t rc; uint64_t h; } variants[] = {
			{ other_txkey_sec, 0, height },
			{ txkey_sec, 1, height },
			{ txkey_sec, 0, height + 1 },
		};

		for (const auto& v : variants) {
			for (int pass = 0; pass < 2; ++pass) {
				ASSERT_TRUE(batch_coinbase_secrets(v.key, v.rc, v.h, w, secrets));
				EXPECT_EQ(get_last_coinbase_secrets_batch_size(), pass ? 0U : w.size());

				for (size_t i = 0; i < w.size(); ++i) {
					EXPECT_TRUE(equal_secrets(secrets[i], reference_coinbase_secrets(v.key, v.rc, v.h, *w[i]))) << i;
					EXPECT_FALSE(equal_secrets(secrets[i], reference[i])) << i;
				}
			}
		}
	}

	// A new wallet among cached ones is the only element that has to be calculated
	{
		const std::vector<Wallet> more = make_test_wallets(BOUNDARY_INPUTS + 1);

		std::vector<const Wallet*> w = pointers;
		w.insert(w.begin() + BOUNDARY_INPUTS / 2, &more.back());

		ASSERT_TRUE(batch_coinbase_secrets(txkey_sec, 0, height, w, secrets));
		EXPECT_EQ(get_last_coinbase_secrets_batch_size(), 1U);
		EXPECT_TRUE(equal_secrets(secrets[BOUNDARY_INPUTS / 2], reference_coinbase_secrets(txkey_sec, 0, height, more.back())));
		EXPECT_TRUE(equal_secrets(secrets.back(), reference.back()));
	}

	// Duplicate wallets get the same secrets. Duplicates that aren't cached yet are calculated more than once.
	{
		const std::vector<Wallet> more = make_test_wallets(BOUNDARY_INPUTS + 2);
		const std::vector<const Wallet*> w = { &more.back(), pointers[0], &more.back() };
		const coinbase_secrets r = reference_coinbase_secrets(txkey_sec, 0, height, more.back());

		ASSERT_TRUE(batch_coinbase_secrets(txkey_sec, 0, height, w, secrets));
		EXPECT_EQ(get_last_coinbase_secrets_batch_size(), 2U);
		EXPECT_TRUE(equal_secrets(secrets[0], r));
		EXPECT_TRUE(equal_secrets(secrets[1], reference[0]));
		EXPECT_TRUE(equal_secrets(secrets[2], r));

		ASSERT_TRUE(batch_coinbase_secrets(txkey_sec, 0, height, w, secrets));
		EXPECT_EQ(get_last_coinbase_secrets_batch_size(), 0U);
	}

	// A null wallet, or one with a view public key that isn't a valid point, only invalidates its own element, and isn't cached
	{
		Wallet bad(nullptr);
		bad.assign_unchecked(wallets[0].spend_public_key(), invalid_public_key, NetworkType::Mainnet);

		for (const Wallet* invalid : { static_cast<const Wallet*>(nullptr), static_cast<const Wallet*>(&bad) }) {
			for (int pass = 0; pass < 2; ++pass) {
				const std::vector<const Wallet*> w = { pointers[0], invalid, pointers[1] };

				EXPECT_FALSE(batch_coinbase_secrets(txkey_sec, 0, height, w, secrets));
				EXPECT_EQ(get_last_coinbase_secrets_batch_size(), invalid ? 1U : 0U);
				ASSERT_EQ(secrets.size(), 3U);

				EXPECT_TRUE(equal_secrets(secrets[0], reference[0]));
				EXPECT_TRUE(equal_secrets(secrets[1], coinbase_secrets{}));
				EXPECT_TRUE(equal_secrets(secrets[2], reference[1]));
			}
		}
	}

	// Both cleanup modes discard the cache
	for (uint64_t timestamp : { seconds_since_epoch() + 1, uint64_t(0) }) {
		clear_crypto_cache(timestamp);

		ASSERT_TRUE(batch_coinbase_secrets(txkey_sec, 0, height, pointers, secrets));
		EXPECT_EQ(get_last_coinbase_secrets_batch_size(), BOUNDARY_INPUTS);
		ASSERT_TRUE(batch_coinbase_secrets(txkey_sec, 0, height, pointers, secrets));
		EXPECT_EQ(get_last_coinbase_secrets_batch_size(), 0U);
	}
}

TEST(carrot, complete_coinbase_outputs)
{
	init_crypto_cache();
	thread_pool_init();

	ON_SCOPE_LEAVE([]() {
		thread_pool_destroy();
		destroy_crypto_cache();
	});

	constexpr uint64_t height = 3812345;
	constexpr uint64_t amount = 600000000000ULL;
	constexpr size_t BOUNDARY_INPUTS = 33 * 34 / 2;

	const hash& txkey_sec = gen_janus_anchor_txkey_sec;

	const std::vector<Wallet> wallets = make_test_wallets(BOUNDARY_INPUTS);

	std::vector<const Wallet*> pointers;
	std::vector<uint64_t> amounts;
	std::vector<coinbase_secrets> reference_secrets;

	for (size_t i = 0; i < wallets.size(); ++i) {
		pointers.emplace_back(&wallets[i]);
		amounts.emplace_back(amount + i);
		reference_secrets.emplace_back(reference_coinbase_secrets(txkey_sec, 0, height, wallets[i]));
	}

	auto reference_output = [&](size_t i, uint64_t a) {
		coinbase_output_input in{};

		in.spend_public_key = wallets[i].spend_public_key();
		in.sender_receiver_secret = reference_secrets[i].sender_receiver_secret;
		in.contextualized_sender_receiver_secret = reference_secrets[i].contextualized_sender_receiver_secret;
		in.anchor = reference_secrets[i].anchor;
		in.amount = a;

		return reference_coinbase_output(height, in);
	};

	auto check_outputs = [&](const std::vector<size_t>& indices, const std::vector<uint64_t>& a, const std::vector<coinbase_tx_output>& out) {
		ASSERT_EQ(out.size(), indices.size());

		for (size_t k = 0; k < indices.size(); ++k) {
			EXPECT_TRUE(equal_outputs(out[k], reference_output(indices[k], a[k]))) << "element " << k;
			EXPECT_EQ(out[k].eph_pub_key, reference_secrets[indices[k]].eph_pub_key) << "element " << k;
			EXPECT_EQ(out[k].amount, a[k]) << "element " << k;
		}
	};

	std::vector<coinbase_secrets> secrets;
	std::vector<coinbase_tx_output> out;

	// Size mismatches
	ASSERT_FALSE(batch_coinbase_secrets(txkey_sec, 0, height, pointers, { amount }, secrets, out));
	ASSERT_TRUE(batch_coinbase_secrets(txkey_sec, 0, height, { pointers[0] }, { amount }, secrets, out));
	ASSERT_FALSE(complete_coinbase_outputs(txkey_sec, 0, height, { pointers[0] }, { amount, amount }, secrets, out));
	ASSERT_FALSE(complete_coinbase_outputs(txkey_sec, 0, height, { pointers[0], pointers[1] }, { amount, amount }, secrets, out));

	clear_crypto_cache();

	// Disjoint ranges with sizes around all possible parallel_run thread-count boundaries.
	// Nothing is cached, so batch_coinbase_secrets finds no outputs and complete_coinbase_outputs calculates all of them.
	size_t range_begin = 0;

	for (size_t n = 1; n <= 33; ++n) {
		const size_t range_end = range_begin + n;

		const std::vector<const Wallet*> w(pointers.begin() + range_begin, pointers.begin() + range_end);
		const std::vector<uint64_t> a(amounts.begin() + range_begin, amounts.begin() + range_end);

		std::vector<size_t> indices(n);
		std::iota(indices.begin(), indices.end(), range_begin);

		ASSERT_TRUE(batch_coinbase_secrets(txkey_sec, 0, height, w, a, secrets, out)) << "batch size " << n;
		ASSERT_EQ(out.size(), n);

		for (const coinbase_tx_output& o : out) {
			EXPECT_FALSE(o.valid);
		}

		ASSERT_TRUE(complete_coinbase_outputs(txkey_sec, 0, height, w, a, secrets, out)) << "batch size " << n;
		EXPECT_EQ(get_last_coinbase_output_batch_size(), n);

		check_outputs(indices, a, out);

		range_begin = range_end;
	}
	ASSERT_EQ(range_begin, BOUNDARY_INPUTS);

	std::vector<size_t> all_indices(BOUNDARY_INPUTS);
	std::iota(all_indices.begin(), all_indices.end(), 0);

	// All outputs are cached now, and complete_coinbase_outputs only fills in eph_pub_key and amount
	ASSERT_TRUE(batch_coinbase_secrets(txkey_sec, 0, height, pointers, amounts, secrets, out));
	EXPECT_EQ(get_last_coinbase_secrets_batch_size(), 0U);

	for (const coinbase_tx_output& o : out) {
		EXPECT_TRUE(o.valid);
	}

	ASSERT_TRUE(complete_coinbase_outputs(txkey_sec, 0, height, pointers, amounts, secrets, out));
	EXPECT_EQ(get_last_coinbase_output_batch_size(), 0U);
	check_outputs(all_indices, amounts, out);

	// New amounts scattered through the batch are the only outputs that have to be calculated, and the old ones stay cached
	{
		std::vector<uint64_t> changed = amounts;

		for (const size_t i : { size_t(0), changed.size() / 2, changed.size() - 1 }) {
			changed[i] += 1234567;
		}

		for (int pass = 0; pass < 2; ++pass) {
			ASSERT_TRUE(batch_coinbase_secrets(txkey_sec, 0, height, pointers, changed, secrets, out));
			ASSERT_TRUE(complete_coinbase_outputs(txkey_sec, 0, height, pointers, changed, secrets, out));
			EXPECT_EQ(get_last_coinbase_output_batch_size(), pass ? 0U : 3U);
			check_outputs(all_indices, changed, out);
		}

		ASSERT_TRUE(batch_coinbase_secrets(txkey_sec, 0, height, pointers, amounts, secrets, out));
		ASSERT_TRUE(complete_coinbase_outputs(txkey_sec, 0, height, pointers, amounts, secrets, out));
		EXPECT_EQ(get_last_coinbase_output_batch_size(), 0U);
	}

	// A wallet can be repeated with different amounts, like prewarm_coinbase_outputs does
	{
		const std::vector<const Wallet*> w(5, pointers[1]);
		const std::vector<uint64_t> a = { amount * 2, amount * 3, amount * 2, amount * 4, amounts[1] };
		const std::vector<size_t> indices(5, 1);

		ASSERT_TRUE(batch_coinbase_secrets(txkey_sec, 0, height, w, a, secrets, out));
		EXPECT_EQ(get_last_coinbase_secrets_batch_size(), 0U);
		ASSERT_TRUE(complete_coinbase_outputs(txkey_sec, 0, height, w, a, secrets, out));

		// amount * 2 appears twice: it's calculated twice, but cached once. amounts[1] is cached already.
		EXPECT_EQ(get_last_coinbase_output_batch_size(), 4U);
		check_outputs(indices, a, out);

		ASSERT_TRUE(batch_coinbase_secrets(txkey_sec, 0, height, w, a, secrets, out));
		ASSERT_TRUE(complete_coinbase_outputs(txkey_sec, 0, height, w, a, secrets, out));
		EXPECT_EQ(get_last_coinbase_output_batch_size(), 0U);
		check_outputs(indices, a, out);
	}

	// There is a limit on how many amounts are cached for one wallet. When it's reached, a new amount replaces the oldest one.
	{
		constexpr size_t n = 100;

		const std::vector<const Wallet*> w(n, pointers[2]);
		const std::vector<size_t> indices(n, 2);

		std::vector<uint64_t> a(n);

		for (size_t i = 0; i < n; ++i) {
			a[i] = amount * 10 + i;
		}

		// Which of these amounts are cached for pointers[2]. batch_coinbase_secrets() only looks them up, it doesn't change the cache.
		auto cached = [&](const std::vector<uint64_t>& amounts_to_check) {
			std::vector<coinbase_secrets> s;
			std::vector<coinbase_tx_output> o;

			EXPECT_TRUE(batch_coinbase_secrets(txkey_sec, 0, height, std::vector<const Wallet*>(amounts_to_check.size(), pointers[2]), amounts_to_check, s, o));

			std::vector<bool> result;

			for (const coinbase_tx_output& t : o) {
				result.emplace_back(t.valid);
			}

			return result;
		};

		ASSERT_TRUE(cached({ amounts[2] })[0]);

		ASSERT_TRUE(batch_coinbase_secrets(txkey_sec, 0, height, w, a, secrets, out));
		ASSERT_TRUE(complete_coinbase_outputs(txkey_sec, 0, height, w, a, secrets, out));
		EXPECT_EQ(get_last_coinbase_output_batch_size(), n);
		check_outputs(indices, a, out);

		// Only the newest amounts are left, and the one that was cached before all of them is gone
		const std::vector<bool> c = cached(a);
		const size_t limit = static_cast<size_t>(std::count(c.begin(), c.end(), true));

		ASSERT_GT(limit, 1U);
		ASSERT_LT(limit, n);

		for (size_t i = 0; i < n; ++i) {
			EXPECT_EQ(c[i], i >= n - limit) << i;
		}

		EXPECT_FALSE(cached({ amounts[2] })[0]);

		// One more amount replaces the oldest one that's left
		const uint64_t extra = amount * 11;

		ASSERT_TRUE(batch_coinbase_secrets(txkey_sec, 0, height, { pointers[2] }, { extra }, secrets, out));
		ASSERT_TRUE(complete_coinbase_outputs(txkey_sec, 0, height, { pointers[2] }, { extra }, secrets, out));
		EXPECT_EQ(get_last_coinbase_output_batch_size(), 1U);
		check_outputs({ 2 }, { extra }, out);

		EXPECT_TRUE(cached({ extra })[0]);
		EXPECT_FALSE(cached({ a[n - limit] })[0]);
		EXPECT_TRUE(cached({ a[n - limit + 1] })[0]);

		// A new amount repeated in one batch is cached once, so it replaces only one old amount
		const uint64_t extra2 = amount * 12;
		const std::vector<const Wallet*> w2(2, pointers[2]);

		ASSERT_TRUE(batch_coinbase_secrets(txkey_sec, 0, height, w2, { extra2, extra2 }, secrets, out));
		ASSERT_TRUE(complete_coinbase_outputs(txkey_sec, 0, height, w2, { extra2, extra2 }, secrets, out));
		EXPECT_EQ(get_last_coinbase_output_batch_size(), 2U);
		check_outputs({ 2, 2 }, { extra2, extra2 }, out);

		EXPECT_EQ(cached({ extra, extra2 }), std::vector<bool>({ true, true }));
		EXPECT_FALSE(cached({ a[n - limit + 1] })[0]);
		EXPECT_TRUE(cached({ a[n - limit + 2] })[0]);
	}

	// Outputs calculated from secrets that don't belong to the cache entry for the given arguments are returned, but not cached
	{
		const std::vector<const Wallet*> w = { pointers[3] };
		const std::vector<uint64_t> a = { amount * 20 };

		std::vector<coinbase_secrets> other_secrets;
		std::vector<coinbase_tx_output> other_out;

		ASSERT_TRUE(batch_coinbase_secrets(txkey_sec, 0, height + 1, w, a, other_secrets, other_out));
		ASSERT_FALSE(equal_secrets(other_secrets[0], reference_secrets[3]));

		ASSERT_TRUE(complete_coinbase_outputs(txkey_sec, 0, height, w, a, other_secrets, other_out));
		EXPECT_EQ(get_last_coinbase_output_batch_size(), 1U);

		ASSERT_TRUE(batch_coinbase_secrets(txkey_sec, 0, height, w, a, secrets, out));
		EXPECT_FALSE(out[0].valid);
		ASSERT_TRUE(complete_coinbase_outputs(txkey_sec, 0, height, w, a, secrets, out));
		EXPECT_EQ(get_last_coinbase_output_batch_size(), 1U);
		check_outputs({ 3 }, a, out);
	}

	// Invalid secrets leave their output invalid
	{
		const std::vector<const Wallet*> w = { pointers[0], nullptr, pointers[1] };
		const std::vector<uint64_t> a = { amounts[0], amount, amounts[1] };

		EXPECT_FALSE(batch_coinbase_secrets(txkey_sec, 0, height, w, a, secrets, out));
		EXPECT_FALSE(complete_coinbase_outputs(txkey_sec, 0, height, w, a, secrets, out));
		EXPECT_EQ(get_last_coinbase_output_batch_size(), 0U);

		EXPECT_TRUE(out[0].valid);
		EXPECT_FALSE(out[1].valid);
		EXPECT_TRUE(out[2].valid);
	}

	// Both cleanup modes discard the cached outputs too
	for (uint64_t timestamp : { seconds_since_epoch() + 1, uint64_t(0) }) {
		clear_crypto_cache(timestamp);

		for (int pass = 0; pass < 2; ++pass) {
			ASSERT_TRUE(batch_coinbase_secrets(txkey_sec, 0, height, pointers, amounts, secrets, out));
			ASSERT_TRUE(complete_coinbase_outputs(txkey_sec, 0, height, pointers, amounts, secrets, out));
			EXPECT_EQ(get_last_coinbase_output_batch_size(), pass ? 0U : BOUNDARY_INPUTS);
			check_outputs(all_indices, amounts, out);
		}
	}

	// Construction, verification and cache cleanup can run concurrently
	std::thread workers[2];

	for (auto& worker : workers) {
		worker = std::thread([&]() {
			for (size_t pass = 0; pass < 3; ++pass) {
				std::vector<coinbase_secrets> s;
				std::vector<coinbase_tx_output> o;

				EXPECT_TRUE(batch_coinbase_secrets(txkey_sec, 0, height, pointers, amounts, s, o));
				EXPECT_TRUE(complete_coinbase_outputs(txkey_sec, 0, height, pointers, amounts, s, o));

				for (size_t i = 0; i < o.size(); ++i) {
					EXPECT_TRUE(equal_outputs(o[i], reference_output(i, amounts[i]))) << i;
				}
			}
		});
	}

	for (int i = 0; i < 3; ++i) {
		clear_crypto_cache(i ? 0 : (seconds_since_epoch() + 1));
	}

	for (auto& worker : workers) {
		worker.join();
	}
}

TEST(carrot, batch_eph_privkeys)
{
	init_crypto_cache();
	thread_pool_init();

	ON_SCOPE_LEAVE([]() {
		thread_pool_destroy();
		destroy_crypto_cache();
	});

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
	init_crypto_cache();
	thread_pool_init();

	ON_SCOPE_LEAVE([]() {
		thread_pool_destroy();
		destroy_crypto_cache();
	});

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

TEST(carrot, build_coinbase_outputs)
{
	init_crypto_cache();
	thread_pool_init();

	ON_SCOPE_LEAVE([]() {
		thread_pool_destroy();
		destroy_crypto_cache();
	});

	std::ifstream file("carrot_coinbase_vectors.txt");
	ASSERT_TRUE(file.is_open());

	std::string line;

	size_t line_number = 0;
	size_t test_count = 0;

	while (std::getline(file, line)) {
		++line_number;

		if (line.empty()) {
			continue;
		}

		SCOPED_TRACE(testing::Message() << "line " << line_number);

		std::istringstream input(line);

		hash txkey_sec;
		uint64_t height;
		size_t output_count;

		ASSERT_TRUE(input >> txkey_sec >> height >> output_count);
		ASSERT_GT(output_count, 0U);

		std::vector<Wallet> wallets;
		wallets.reserve(output_count);

		std::vector<coinbase_tx_output> expected_outputs(output_count);

		for (auto& expected : expected_outputs) {
			hash spend_public_key, view_public_key;
			std::string view_tag_hex, anchor_enc_hex;

			ASSERT_TRUE(input >> spend_public_key >> view_public_key >> expected.amount >> expected.onetime_address >> expected.eph_pub_key >> view_tag_hex >> anchor_enc_hex);

			std::vector<uint8_t> bytes;

			ASSERT_EQ(view_tag_hex.size(), CARROT_VIEW_TAG_BYTES * 2);
			ASSERT_TRUE(from_hex(view_tag_hex.data(), view_tag_hex.size(), bytes));

			memcpy(expected.vt.data, bytes.data(), CARROT_VIEW_TAG_BYTES);

			ASSERT_EQ(anchor_enc_hex.size(), CARROT_JANUS_ANCHOR_BYTES * 2);
			ASSERT_TRUE(from_hex(anchor_enc_hex.data(), anchor_enc_hex.size(), bytes));

			memcpy(expected.anchor_enc.data, bytes.data(), CARROT_JANUS_ANCHOR_BYTES);

			expected.valid = true;
			wallets.emplace_back(nullptr);

			ASSERT_TRUE(wallets.back().assign(spend_public_key, view_public_key, NetworkType::Mainnet));
		}

		ASSERT_TRUE((input >> std::ws).eof());

		std::vector<const Wallet*> pointers;
		std::vector<uint64_t> amounts;

		for (size_t i = 0; i < wallets.size(); ++i) {
			pointers.emplace_back(&wallets[i]);
			amounts.emplace_back(expected_outputs[i].amount);
		}

		// Keep caches across fixtures to test changes in amounts, height and
		// txkey_sec. Also repeat each set in reverse and rotated input order.
		for (size_t pass = 0; pass < 3; ++pass) {
			SCOPED_TRACE(testing::Message() << "pass " << pass);

			if (pass == 1) {
				std::reverse(pointers.begin(), pointers.end());
				std::reverse(amounts.begin(), amounts.end());
			}
			else if (pass == 2) {
				std::rotate(pointers.begin(), pointers.begin() + 1, pointers.end());
				std::rotate(amounts.begin(), amounts.begin() + 1, amounts.end());
			}

			std::vector<coinbase_tx_output> outputs(output_count + 1);

			ASSERT_TRUE(build_coinbase_outputs(txkey_sec, height, pointers, amounts, outputs));
			ASSERT_EQ(outputs.size(), output_count);

			for (size_t i = 0; i < outputs.size(); ++i) {
				SCOPED_TRACE(testing::Message() << "output " << i);

				const auto& actual = outputs[i];
				const auto& expected = expected_outputs[i];

				EXPECT_TRUE(actual.valid);
				EXPECT_EQ(actual.onetime_address, expected.onetime_address);
				EXPECT_EQ(actual.eph_pub_key, expected.eph_pub_key);
				EXPECT_EQ(actual.amount, expected.amount);
				EXPECT_EQ(actual.anchor_enc, expected.anchor_enc);
				EXPECT_EQ(memcmp(actual.vt.data, expected.vt.data, CARROT_VIEW_TAG_BYTES), 0);

				if (i) {
					// Monero orders serialized bytes, unlike p2pool::hash::operator<.
					EXPECT_LT(memcmp(outputs[i - 1].onetime_address.h, actual.onetime_address.h, HASH_SIZE), 0);
				}
			}
		}

		++test_count;
	}

	ASSERT_TRUE(file.eof());
	EXPECT_EQ(test_count, 10U);
}

TEST(carrot, build_coinbase_outputs_invalid_inputs)
{
	init_crypto_cache();
	thread_pool_init();

	ON_SCOPE_LEAVE([]() {
		thread_pool_destroy();
		destroy_crypto_cache();
	});

	constexpr uint64_t height = 3812345;
	constexpr uint64_t amount = 600000000000ULL;

	const hash& txkey_sec = gen_janus_anchor_txkey_sec;

	Wallet w(test_wallet_address);

	ASSERT_TRUE(w.valid());

	Wallet copy(w);
	Wallet invalid(nullptr);

	ASSERT_FALSE(invalid.valid());

	std::vector<coinbase_tx_output> baseline;

	ASSERT_TRUE(build_coinbase_outputs(txkey_sec, height, { &w }, { amount }, baseline));
	ASSERT_EQ(baseline.size(), 1U);

	auto check_empty = [&](const std::vector<const Wallet*>& wallets, const std::vector<uint64_t>& amounts, bool expected)
	{
		std::vector<coinbase_tx_output> outputs = baseline;

		EXPECT_EQ(build_coinbase_outputs(txkey_sec, height, wallets, amounts, outputs), expected);
		EXPECT_TRUE(outputs.empty());
	};

	check_empty({}, {}, true);
	check_empty({}, { 1 }, false);
	check_empty({ &w }, {}, false);
	check_empty({ &w }, { 1, 2 }, false);

	for (size_t i = 0; i < 3; ++i) {
		std::vector<const Wallet*> wallets(3, &w);

		wallets[i] = nullptr;
		check_empty(wallets, { 1, 2, 3 }, false);

		wallets[i] = &invalid;
		check_empty(wallets, { 1, 2, 3 }, false);
	}

	check_empty({ &w, &w }, { 1, 1 }, false);
	check_empty({ &w, &copy }, { 1, 2 }, false);

	std::vector<coinbase_tx_output> outputs;

	ASSERT_TRUE(build_coinbase_outputs(txkey_sec, height, { &w }, { amount }, outputs));
	ASSERT_EQ(outputs.size(), 1U);

	EXPECT_TRUE(equal_outputs(outputs[0], baseline[0]));
	EXPECT_EQ(outputs[0].eph_pub_key, baseline[0].eph_pub_key);
	EXPECT_EQ(outputs[0].amount, baseline[0].amount);
}

} // namespace carrot

} // namespace p2pool
