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
	const hash group_order("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
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

	// d_e * G is the point at infinity for these scalars, so ConvertPointE (and therefore D_e) is not defined
	ASSERT_FALSE(gen_eph_pubkey(hash(), out));
	ASSERT_FALSE(gen_eph_pubkey(group_order, out));
}

TEST(carrot, gen_sender_receiver_secret)
{
	const hash eph_priv_key("6aea0ed0c34ad3483415377658841a75e0da8b462e637d8bf783b9bcd320b303");
	const hash view_public_key("369bdcf4f434f42eb09f4372cb6be30de7b17d21e4f98e244459a90b58cd0610");
	const hash expected("1f848f8384e7a9f217dc9dc2691703cf392eaf6c92931acd0fc840c900d3ed49");
	const hash group_order("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
	const hash identity_public_key{ 1 };
	const hash invalid_public_key("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
	const hash torsion_public_key("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");

	// Vector from Monero's carrot_convergence.try_make_carrot_shared_key_sender test.
	hash out;
	ASSERT_TRUE(gen_sender_receiver_secret(eph_priv_key, view_public_key, out));
	ASSERT_EQ(out, expected);

	out = eph_priv_key;
	ASSERT_TRUE(gen_sender_receiver_secret(out, view_public_key, out));
	ASSERT_EQ(out, expected);

	out = view_public_key;
	ASSERT_TRUE(gen_sender_receiver_secret(eph_priv_key, out, out));
	ASSERT_EQ(out, expected);

	ASSERT_FALSE(gen_sender_receiver_secret(hash(), view_public_key, out));
	ASSERT_FALSE(gen_sender_receiver_secret(group_order, view_public_key, out));
	ASSERT_FALSE(gen_sender_receiver_secret(eph_priv_key, identity_public_key, out));
	ASSERT_FALSE(gen_sender_receiver_secret(eph_priv_key, invalid_public_key, out));
	ASSERT_FALSE(gen_sender_receiver_secret(eph_priv_key, torsion_public_key, out));
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

	const hash one{ 1 };
	const hash group_order("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
	const hash group_order_minus_one("ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
	const hash known_scalar("46a29e25fb6caafe8d5f40e279ff4830fdcca68232237461b0884520e2dea507");
	const hash known_scalar_negated("a73157371ff66759483db7c064fa95e40233597dcddc8b9e4f77badf1d215a08");
	const hash monero_convergence_eph_priv_key("6aea0ed0c34ad3483415377658841a75e0da8b462e637d8bf783b9bcd320b303");
	const hash monero_convergence_expected("8df2a40a42ecc10348a461310c1afc2c2b1be7b29fd27a3921a1aefba5efa27b");

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

	const size_t known_scalar_index = in.size();

	in.emplace_back(known_scalar);
	in.emplace_back(known_scalar_negated);

	const size_t monero_convergence_index = in.size();

	in.emplace_back(monero_convergence_eph_priv_key);
	in.emplace_back(one);
	in.emplace_back(one);

	std::vector<hash> reference(in.size());

	for (size_t i = 0; i < in.size(); ++i) {
		ASSERT_TRUE(gen_eph_pubkey(in[i], reference[i])) << "scalar index " << i;
	}

	ASSERT_EQ(reference[monero_convergence_index], monero_convergence_expected);

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
	ASSERT_EQ(out[known_scalar_index].first, out[known_scalar_index + 1].first);

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

	const hash one{ 1 };
	const hash two{ 2 };
	const hash group_order("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010");
	const hash convergence_eph_priv_key("6aea0ed0c34ad3483415377658841a75e0da8b462e637d8bf783b9bcd320b303");
	const hash convergence_view_public_key("369bdcf4f434f42eb09f4372cb6be30de7b17d21e4f98e244459a90b58cd0610");
	const hash convergence_expected("1f848f8384e7a9f217dc9dc2691703cf392eaf6c92931acd0fc840c900d3ed49");
	const hash identity_public_key{ 1 };
	const hash invalid_public_key("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
	const hash torsion_public_key("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");

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

	ASSERT_EQ(reference[0], convergence_expected);

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

	const hash one{ 1 };
	const hash invalid_public_key("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
	const hash torsion_public_key("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
	const hash valid_public_key("369bdcf4f434f42eb09f4372cb6be30de7b17d21e4f98e244459a90b58cd0610");

	std::vector<std::pair<hash, bool>> out;
	hash derivation;
	uint8_t view_tag;

	// Absent and invalid entries. Invalid entries can't have any of the other state flags.
	ASSERT_EQ(get_from_bytes_cache_state(valid_public_key), 0U);
	ASSERT_FALSE(batch_sender_receiver_secrets({ one }, { invalid_public_key }, out));
	ASSERT_EQ(get_from_bytes_cache_state(invalid_public_key), PRESENT);

	// Valid, no precomputation, subgroup unchecked -> valid main subgroup with precomputation.
	clear_crypto_cache();

	ASSERT_TRUE(derive_public_key(one, 0, valid_public_key, derivation));
	ASSERT_EQ(get_from_bytes_cache_state(valid_public_key), PRESENT | VALID);
	ASSERT_TRUE(batch_sender_receiver_secrets({ one }, { valid_public_key }, out));
	ASSERT_EQ(get_from_bytes_cache_state(valid_public_key), PRESENT | VALID | HAS_PRECOMP | SUBGROUP_CHECKED | MAIN_SUBGROUP);

	// Valid, precomputed, subgroup unchecked -> valid main subgroup with the existing precomputation.
	clear_crypto_cache();

	ASSERT_TRUE(generate_key_derivation(valid_public_key, one, 0, derivation, view_tag));
	ASSERT_EQ(get_from_bytes_cache_state(valid_public_key), PRESENT | VALID | HAS_PRECOMP);
	ASSERT_TRUE(batch_sender_receiver_secrets({ one }, { valid_public_key }, out));
	ASSERT_EQ(get_from_bytes_cache_state(valid_public_key), PRESENT | VALID | HAS_PRECOMP | SUBGROUP_CHECKED | MAIN_SUBGROUP);

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
