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
#include "crypto.h"
#include "util.h"
#include "fcmp_pp_crypto.h"
#include "thread_pool.h"
#include "keccak.h"

#include "gtest/gtest.h"
#include <fstream>
#include <random>
#include <string>

namespace p2pool {

TEST(crypto, ops)
{
	init_crypto_cache();
	{
	constexpr uint8_t entropy[] = "Test entropy";
	hash pub, sec;
	generate_keys_deterministic(pub, sec, entropy, sizeof(entropy) - 1);
	ASSERT_TRUE(check_keys(pub, sec));

	sec.h[HASH_SIZE - 1] = 0xff;
	ASSERT_FALSE(check_keys(pub, sec));

	// Run the tests several times to check how crypto cache works
	for (int i = 0; i < 4; ++i) {
		if (i == 2) {
			clear_crypto_cache(seconds_since_epoch() - 1);
		}
		else if (i == 3) {
			clear_crypto_cache(seconds_since_epoch() + 1);
		}

		std::ifstream f("crypto_tests.txt");
		ASSERT_EQ(f.good() && f.is_open(), true);
		do {
			std::string name;
			f >> name;
			if (name == "generate_key_derivation") {
				hash key1, key2, derivation, expected_derivation;
				std::string result_str;
				f >> key1 >> key2 >> result_str;
				const bool result = (result_str == "true");
				if (result) {
					f >> expected_derivation;
				}
				uint8_t view_tag;
				ASSERT_EQ(p2pool::generate_key_derivation(key1, key2, 0, derivation, view_tag), result);
				ASSERT_EQ(p2pool::generate_key_derivation(key1, key2, 1, derivation, view_tag), result);
				ASSERT_EQ(p2pool::generate_key_derivation(key1, key2, 2, derivation, view_tag), result);
				ASSERT_EQ(p2pool::generate_key_derivation(key1, key2, 3, derivation, view_tag), result);
				if (result) {
					ASSERT_EQ(derivation, expected_derivation);
				}
			}
			else if (name == "derive_public_key") {
				hash derivation, base, derived_key, expected_derived_key;
				std::string result_str;
				size_t output_index;
				f >> derivation >> output_index >> base >> result_str;
				const bool result = (result_str == "true");
				if (result) {
					f >> expected_derived_key;
				}
				ASSERT_EQ(derive_public_key(derivation, output_index, base, derived_key), result);
				if (result) {
					ASSERT_EQ(derived_key, expected_derived_key);
				}
			}
			else if (name == "derive_view_tag") {
				hash derivation;
				uint64_t output_index;
				std::string result_str;
				f >> derivation >> output_index >> result_str;
				uint8_t view_tag;
				p2pool::derive_view_tag(derivation, output_index, view_tag);

				char buf[log::Stream::BUF_SIZE + 1];
				log::Stream s(buf);
				s << log::hex_buf(&view_tag, 1) << '\0';

				ASSERT_EQ(buf, result_str);
			}
			else if (name == "get_tx_keys") {
				hash wallet_spend_key, monero_block_id, pub_check, sec_check;
				f >> wallet_spend_key >> monero_block_id >> pub_check >> sec_check;

				hash pub, sec;
				p2pool::get_tx_keys(pub, sec, wallet_spend_key, monero_block_id);

				ASSERT_EQ(pub, pub_check);
				ASSERT_EQ(sec, sec_check);
			}
			else if (name == "check_key") {
				hash pub_key;
				std::string result_str;

				f >> pub_key >> result_str;				

				ge_p3 p;
				ASSERT_EQ(ge_frombytes_vartime(&p, pub_key.h) == 0, result_str == "true");
			}
			else if (name == "check_torsion") {
				hash pub_key;
				std::string result_str;

				f >> pub_key >> result_str;				

				ge_p3 p;
				const bool expected =
					(ge_frombytes_vartime(&p, pub_key.h) == 0)
					&& !fcmp_pp::mul8_is_identity(p)
					&& fcmp_pp::torsion_check_vartime(p);

				ASSERT_EQ(expected, result_str == "true");

				// check_public_key() must agree on every vector, both when it has to compute
				// the answer and when it reads it back out of the cache
				ASSERT_EQ(check_public_key(pub_key), expected) << pub_key;
				ASSERT_EQ(check_public_key(pub_key), expected) << pub_key;
			}
		} while (!f.eof());
	}
	}
	clear_crypto_cache(0);
	destroy_crypto_cache();

#ifdef WITH_INDEXED_HASHES
	indexed_hash::cleanup_storage();
#endif
}

TEST(crypto, is_in_main_subgroup)
{
	// -1 = doesn't decode to a curve point at all, 0 = valid point outside the main subgroup, 1 = main subgroup
	auto check = [](const char (&public_key)[HASH_SIZE * 2 + 1]) -> int
	{
		ge_p3 point;
		if (ge_frombytes_vartime(&point, hash(public_key).h) != 0) {
			return -1;
		}
		return is_in_main_subgroup(point) ? 1 : 0;
	};

	// Ed25519 base point
	ASSERT_EQ(check("5866666666666666666666666666666666666666666666666666666666666666"), 1);

	// l*O = O, so the identity is in the main subgroup.
	// Callers that need a usable key must reject it separately, just like Monero's verify_point_is_in_main_subgroup does.
	ASSERT_EQ(check("0100000000000000000000000000000000000000000000000000000000000000"), 1);

	// All points of order 2, 4 and 8
	ASSERT_EQ(check("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), 0);
	ASSERT_EQ(check("0000000000000000000000000000000000000000000000000000000000000000"), 0);
	ASSERT_EQ(check("0000000000000000000000000000000000000000000000000000000000000080"), 0);
	ASSERT_EQ(check("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"), 0);
	ASSERT_EQ(check("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"), 0);
	ASSERT_EQ(check("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"), 0);
	ASSERT_EQ(check("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"), 0);

	// Large order, but not l: G + (order 2 point) has order 2*l, G + (order 8 point) has order 8*l
	ASSERT_EQ(check("9599999999999999999999999999999999999999999999999999999999999999"), 0);
	ASSERT_EQ(check("da99e28ba529cdde35a25fba9059e78ecaee239f99755b9b1aa4f65df00803e2"), 0);

	// Not a curve point
	ASSERT_EQ(check("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), -1);

	// Deterministically generated public keys are always sec*G, so they are always in the main subgroup,
	// and so are their negations
	for (uint64_t i = 0; i < 32; ++i) {
		hash pub, sec;
		generate_keys_deterministic(pub, sec, reinterpret_cast<const uint8_t*>(&i), sizeof(i));

		for (int negated = 0; negated < 2; ++negated) {
			if (negated) {
				pub.h[HASH_SIZE - 1] ^= 0x80;
			}

			ge_p3 point;
			ASSERT_EQ(ge_frombytes_vartime(&point, pub.h), 0) << "i = " << i << ", negated = " << negated;
			ASSERT_TRUE(is_in_main_subgroup(point)) << "i = " << i << ", negated = " << negated;
		}
	}
}

TEST(crypto, check_public_key)
{
	constexpr uint32_t PRESENT = 1U;
	constexpr uint32_t VALID = 2U;
	constexpr uint32_t HAS_PRECOMP = 4U;
	constexpr uint32_t TORSION_CHECKED = 8U;
	constexpr uint32_t TORSION_FREE = 16U;

	// k*G, so in the prime order subgroup
	hash good, sec;
	constexpr uint64_t seed = 42;
	generate_keys_deterministic(good, sec, reinterpret_cast<const uint8_t*>(&seed), sizeof(seed));

	// A valid curve point carrying torsion, a small order point, and 32 bytes that aren't a point
	const hash torsioned("bd5886e258615b51bdff73f8ae3b9947cf021162325ee8a7f0c787f6f6889836");
	const hash identity("0100000000000000000000000000000000000000000000000000000000000000");
	const hash not_a_point("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

	// Wallet::decode() runs before init_crypto_cache(), so the uncached fallback has to give
	// the same answers as the cached path below
	destroy_crypto_cache();

	ASSERT_TRUE(check_public_key(good));
	ASSERT_FALSE(check_public_key(torsioned));
	ASSERT_FALSE(check_public_key(identity));
	ASSERT_FALSE(check_public_key(not_a_point));

	init_crypto_cache();

	ON_SCOPE_LEAVE([]() {
		clear_crypto_cache(0);
		destroy_crypto_cache();
	});

	ASSERT_EQ(get_from_bytes_cache_state(good), 0U);

	// The result is cached, and reading it back gives the same answer
	ASSERT_TRUE(check_public_key(good));
	ASSERT_EQ(get_from_bytes_cache_state(good), PRESENT | VALID | TORSION_CHECKED | TORSION_FREE);
	ASSERT_TRUE(check_public_key(good));
	ASSERT_EQ(get_from_bytes_cache_state(good), PRESENT | VALID | TORSION_CHECKED | TORSION_FREE);

	// A torsioned point is a valid point, so it is cached as checked but not torsion free
	ASSERT_FALSE(check_public_key(torsioned));
	ASSERT_EQ(get_from_bytes_cache_state(torsioned), PRESENT | VALID | TORSION_CHECKED);
	ASSERT_FALSE(check_public_key(torsioned));

	ASSERT_FALSE(check_public_key(identity));
	ASSERT_EQ(get_from_bytes_cache_state(identity), PRESENT | VALID | TORSION_CHECKED);

	// Something which isn't a curve point can't carry any of the other flags
	ASSERT_FALSE(check_public_key(not_a_point));
	ASSERT_EQ(get_from_bytes_cache_state(not_a_point), PRESENT);
	ASSERT_FALSE(check_public_key(not_a_point));
	ASSERT_EQ(get_from_bytes_cache_state(not_a_point), PRESENT);

	// An entry another path put in the cache gets the torsion flags added, keeping what was there
	clear_crypto_cache(0);
	{
		hash derivation;
		uint8_t view_tag;

		ASSERT_TRUE(generate_key_derivation(good, sec, 0, derivation, view_tag));
		ASSERT_EQ(get_from_bytes_cache_state(good), PRESENT | VALID | HAS_PRECOMP);

		ASSERT_TRUE(check_public_key(good));
		ASSERT_EQ(get_from_bytes_cache_state(good), PRESENT | VALID | HAS_PRECOMP | TORSION_CHECKED | TORSION_FREE);
	}

	// And the other way round: a later path adding the precomputation must not drop the torsion flags
	clear_crypto_cache(0);
	{
		hash derivation;
		uint8_t view_tag;

		ASSERT_TRUE(check_public_key(good));
		ASSERT_EQ(get_from_bytes_cache_state(good), PRESENT | VALID | TORSION_CHECKED | TORSION_FREE);

		ASSERT_TRUE(generate_key_derivation(good, sec, 0, derivation, view_tag));
		ASSERT_EQ(get_from_bytes_cache_state(good), PRESENT | VALID | HAS_PRECOMP | TORSION_CHECKED | TORSION_FREE);
		ASSERT_TRUE(check_public_key(good));
	}
}

TEST(crypto, batch)
{
	init_crypto_cache();
	thread_pool_init();

	constexpr size_t N = 1000;

	std::vector<std::pair<hash, size_t>> in;
	std::vector<std::pair<hash, int32_t>> reference_out;

	std::vector<batch_public_key_input> in2;
	std::vector<std::pair<hash, bool>> reference_out2;

	size_t i = 0;

	hash txkey_pub, txkey_sec;
	p2pool::generate_keys_deterministic(txkey_pub, txkey_sec, reinterpret_cast<uint8_t*>(&i), sizeof(i));

	i = N + 1;

	hash pub2, sec2;
	p2pool::generate_keys_deterministic(pub2, sec2, reinterpret_cast<uint8_t*>(&i), sizeof(i));

	for (i = 1; i <= N; ++i) {
		// Generate a valid pubkey
		hash pub, sec;
		p2pool::generate_keys_deterministic(pub, sec, reinterpret_cast<uint8_t*>(&i), sizeof(i));

		in.emplace_back(pub, i);

		hash derivation;
		uint8_t view_tag;
		ASSERT_TRUE(p2pool::generate_key_derivation(pub, txkey_sec, i, derivation, view_tag));

		reference_out.emplace_back(derivation, view_tag);

		hash derived_key;
		bool result = p2pool::derive_public_key(derivation, i, pub2, derived_key);

		in2.emplace_back(derivation, i, pub2);
		reference_out2.emplace_back(derived_key, result);

		// Now make it random (use keccak as a deterministic random number generator)
		p2pool::keccak(pub.h, HASH_SIZE, pub.h);
		in.emplace_back(pub, i);

		result = p2pool::generate_key_derivation(pub, txkey_sec, i, derivation, view_tag);
		reference_out.emplace_back(derivation, result ? view_tag : -1);

		result = p2pool::derive_public_key(derivation, i, pub, derived_key);

		in2.emplace_back(derivation, i, pub);
		reference_out2.emplace_back(derived_key, result);
	}

	clear_crypto_cache(0);

#ifdef WITH_INDEXED_HASHES
	indexed_hash::cleanup_storage();
#endif

	std::vector<std::pair<hash, int32_t>> out;
	p2pool::batch_derivations(in, txkey_sec, out);

	ASSERT_EQ(out.size(), reference_out.size());

	for (size_t i = 0; i < out.size(); ++i) {
		if (reference_out[i].second >= 0) {
			ASSERT_EQ(out[i], reference_out[i]);
		}
		else {
			ASSERT_EQ(out[i].second, reference_out[i].second);
		}
	}

	std::vector<std::pair<hash, bool>> out2;
	p2pool::batch_public_keys(in2, out2);

	ASSERT_EQ(out2.size(), reference_out2.size());

	for (size_t i = 0; i < out2.size(); ++i) {
		if (reference_out2[i].second) {
			ASSERT_EQ(out2[i].first, reference_out2[i].first);
		}
		else {
			ASSERT_FALSE(out2[i].second);
		}
	}

	thread_pool_destroy();
	destroy_crypto_cache();

#ifdef WITH_INDEXED_HASHES
	indexed_hash::cleanup_storage();
#endif
}

// unbiased_hash_to_ec(keccak("Monero Generator T")), the FCMP++ generator
static constexpr uint8_t T_bytes[HASH_SIZE] = {
	97, 183, 54, 206, 147, 182, 42, 61, 55, 120, 171, 32, 77, 168, 93, 59,
	76, 220, 7, 37, 15, 93, 167, 227, 223, 38, 41, 146, 129, 52, 213, 38
};

TEST(crypto, t_base_table)
{
	ge_p3 T;
	ASSERT_EQ(ge_frombytes_vartime(&T, T_bytes), 0);

	for (size_t i = 0; i < 32; ++i) {
		for (size_t j = 0; j < 8; ++j) {
			uint8_t scalar[32] = {};
			scalar[i] = static_cast<uint8_t>(j + 1);

			ge_p2 expected;
			ge_scalarmult(&expected, scalar, &T);

			const ge_precomp& entry = ge_T_base[i][j];
			ge_p3 actual;
			fe_add(actual.Y, entry.yplusx, entry.yminusx);
			fe_mul(actual.Y, actual.Y, fe_inv2);
			fe_sub(actual.X, entry.yplusx, entry.yminusx);
			fe_mul(actual.X, actual.X, fe_inv2);
			fe_1(actual.Z);
			fe_mul(actual.T, actual.X, actual.Y);

			uint8_t expected_bytes[32];
			uint8_t actual_bytes[32];
			ge_tobytes(expected_bytes, &expected);
			ge_p3_tobytes(actual_bytes, &actual);
			ASSERT_EQ(memcmp(actual_bytes, expected_bytes, sizeof(actual_bytes)), 0) << "i = " << i << ", j = " << j;

			fe expected_xy2d;
			fe_mul(expected_xy2d, actual.T, fe_d2);
			fe_tobytes(expected_bytes, expected_xy2d);
			fe_tobytes(actual_bytes, entry.xy2d);
			ASSERT_EQ(memcmp(actual_bytes, expected_bytes, sizeof(actual_bytes)), 0) << "i = " << i << ", j = " << j;
		}
	}
}


// a * G + b * T, computed with the generic scalar multiplication routines instead of the combs
static hash reference_double_scalarmult_base_T(const hash& a, const hash& b)
{
	ge_p3 T;
	EXPECT_EQ(ge_frombytes_vartime(&T, T_bytes), 0);

	ge_p3 aG, bT;
	ge_scalarmult_base(&aG, a.h);
	ge_scalarmult_p3(&bT, b.h, &T);

	ge_cached bT_cached;
	ge_p3_to_cached(&bT_cached, &bT);

	ge_p1p1 sum;
	ge_add(&sum, &aG, &bT_cached);

	ge_p2 result;
	ge_p1p1_to_p2(&result, &sum);

	hash out;
	ge_tobytes(out.h, &result);

	return out;
}

TEST(crypto, double_scalarmult_base_T)
{
	// "expected" values come from an independent Python implementation of Ed25519 point arithmetic
	auto check = [](const hash& a, const hash& b, const char* expected)
	{
		ge_p3 point;
		ge_double_scalarmult_base_T_vartime(&point, a.h, b.h);

		hash actual;
		ge_p3_tobytes(actual.h, &point);

		if (expected) {
			hash h;
			ASSERT_TRUE(from_hex(expected, strlen(expected), h));
			ASSERT_EQ(actual, h);
		}

		ASSERT_EQ(actual, reference_double_scalarmult_base_T(a, b));
	};

	{
		SCOPED_TRACE("known values");

		check(hash("0000000000000000000000000000000000000000000000000000000000000000"), hash("0000000000000000000000000000000000000000000000000000000000000000"), "0100000000000000000000000000000000000000000000000000000000000000"); // both zero: the point at infinity
		check(hash("0100000000000000000000000000000000000000000000000000000000000000"), hash("0000000000000000000000000000000000000000000000000000000000000000"), "5866666666666666666666666666666666666666666666666666666666666666"); // G
		check(hash("0000000000000000000000000000000000000000000000000000000000000000"), hash("0100000000000000000000000000000000000000000000000000000000000000"), "61b736ce93b62a3d3778ab204da85d3b4cdc07250f5da7e3df2629928134d526"); // T
		check(hash("0100000000000000000000000000000000000000000000000000000000000000"), hash("0100000000000000000000000000000000000000000000000000000000000000"), "a5a9e8332d4e85b0410da7a675cc568422af989cbcca9300530a080d1d0feaaa"); // G + T
		check(hash("1000000000000000000000000000000000000000000000000000000000000000"), hash("0000000000000000000000000000000000000000000000000000000000000000"), "eb2767c137ab7ad8279c078eff116ab0786ead3a2e0f989f72c37f82f2969670"); // a single odd digit
		check(hash("0000000000000000000000000000000000000000000000000000000000000000"), hash("1000000000000000000000000000000000000000000000000000000000000000"), "9c7941ba6eb932be0a8fd3bae14e3c41602494cf9d96963be8139461fcfe9ccc"); // a single odd digit, on T
		check(hash("0800000000000000000000000000000000000000000000000000000000000000"), hash("0800000000000000000000000000000000000000000000000000000000000000"), "cb23c143bc70bac727a488ae3fa70be7dcfc3783ee8ff886e76c077bd7400762"); // digit 8 recodes to -8 with a carry
		check(hash("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"), hash("0000000000000000000000000000000000000000000000000000000000000000"), "0100000000000000000000000000000000000000000000000000000000000000"); // group order: infinity, reached through real additions
		check(hash("0000000000000000000000000000000000000000000000000000000000000000"), hash("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"), "0100000000000000000000000000000000000000000000000000000000000000"); // group order on T
		check(hash("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"), hash("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"), "0100000000000000000000000000000000000000000000000000000000000000"); // group order on both
		check(hash("ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"), hash("ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"), "a5a9e8332d4e85b0410da7a675cc568422af989cbcca9300530a080d1d0fea2a"); // -G - T
		check(hash("0101010101010101010101010101010101010101010101010101010101010101"), hash("0000000000000000000000000000000000000000000000000000000000000000"), "130ae82201d7072e6fbfc0a1884fb54636554d14945b799125cf7ce38d477f51"); // every odd digit is zero, so the 16x doubling is skipped
		check(hash("0000000000000000000000000000000000000000000000000000000000000000"), hash("0101010101010101010101010101010101010101010101010101010101010101"), "44b83c987b97bae4714b74efd734ad8e1e0585d18d13700d2cfce5bd748f4cb8"); // same, on T
		check(hash("0101010101010101010101010101010101010101010101010101010101010101"), hash("0101010101010101010101010101010101010101010101010101010101010101"), "a6532550e9df6736cf4fb3bef54b5396c38b4b19b85d1fe55d88448c9db97c24"); // same, on both
		check(hash("1010101010101010101010101010101010101010101010101010101010101010"), hash("1010101010101010101010101010101010101010101010101010101010101010"), "15b22ef6a1f19039cec47421ecc9e2eacf8150412df993664ffefd60fd3c785b"); // every even digit is zero
		check(hash("8888888888888888888888888888888888888888888888888888888888888808"), hash("8888888888888888888888888888888888888888888888888888888888888808"), "6566e0a56387e383de56faf18d8f586f8a174e558e8d00182e40c24efdd44117"); // maximal carry propagation
		check(hash("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0f"), hash("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0f"), "a7990481c4d96ef5ce83e266a872d5e8f4ccfcfcc1595b8e8da1a4f9227861a5"); // every nibble is 15
		check(hash("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), hash("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), "9084740cb16b9569b306bfcb5d2169101c2a6f2280021958def0402a07ffcb94"); // the largest top byte the preconditions allow
		check(hash("939ba1f2646cf90241a22d5e85a21519330cb37009f3a4a597bf11f59e75c803"), hash("1126f934686d20106f4b8b2a993acbc18daf171f04d3e847d2adb476c590c603"), "05d8616b4c02b6c797645da04ea3fa3258e0fea577937af3540f18a1488ce493"); // random reduced scalars
		check(hash("d8d164ea14f5d20564ee1e39182b61c100bd36be474369a0c5f368e8a5660f0b"), hash("e4a1e4262841ce06a6951b4d6d966dfce9de75edf283517bba84a68de3a97003"), "8147842778f305ff3b041f4afe5fcab454ece13e9ec8f1b79f24ad6a5eef8ef6"); // random reduced scalars
		check(hash("be7281fec8f7949e1bbb4e031cc44fb8b5418d2f60a56b8f23776af55396d007"), hash("6f4f44d1a6f2bf9dfb8ed56c0c21ed15477294a61f4ecd73560427a894e74d01"), "6b6c6abe33f92c3bed36e567d8463fc512fbf348e9bdbe5f983c40ddad311bf4"); // random reduced scalars
		check(hash("8d704ab810331d10dc68d0f124d792a685c8668ba88054aa2a799183a624c80f"), hash("17f7781eeb25b400313dd9cda507108816fad1084df2d090e38818e38b941a09"), "c8f627159e10b6a4abb08c10c5ad4aedc9837306a4eb7aab5cbccb661891e065"); // random reduced scalars
	}

	// Every single digit of every position, on each generator separately and on both at once
	{
		SCOPED_TRACE("single digits");

		for (int i = 0; i < 64; ++i) {
			for (int j = 1; j <= 8; ++j) {
				hash d;
				d.h[i / 2] = static_cast<uint8_t>((i & 1) ? (j << 4) : j);

				// The top nibble must stay within the a[31] <= 127 pre-condition
				if (d.h[HASH_SIZE - 1] > 127) {
					continue;
				}

				check(d, hash(), nullptr);
				check(hash(), d, nullptr);
				check(d, d, nullptr);
			}
		}
	}

	{
		SCOPED_TRACE("random scalars");

		std::mt19937_64 rng(123);

		for (int i = 0; i < 500; ++i) {
			hash a, b;

			for (size_t k = 0; k < HASH_SIZE / sizeof(uint64_t); ++k) {
				a.u64()[k] = rng();
				b.u64()[k] = rng();
			}

			sc_reduce32(a.h);
			sc_reduce32(b.h);

			// Make one of the scalars zero every now and then
			if (i % 7 == 0) {
				a = {};
			}
			else if (i % 7 == 1) {
				b = {};
			}

			check(a, b, nullptr);
		}
	}
}


// ---------------------------------------------------------------------------
// Field arithmetic. These run against whichever representation is compiled in
// (radix 2^51 or radix 2^25.5), so they pin down the behaviour both must share:
// the same canonical byte encodings for the same values.
// ---------------------------------------------------------------------------

static const unsigned char big_bytes_for_bounds[32] = {
	0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
};

static void fe_from_hex(fe f, const char* s)
{
	hash h;
	ASSERT_TRUE(from_hex(s, strlen(s), h));
	ASSERT_EQ(fe_frombytes_vartime(f, h.h), 0);
}

static std::string fe_to_hex(const fe f)
{
	uint8_t b[HASH_SIZE];
	fe_tobytes(b, f);

	std::string s;
	for (uint8_t v : b) {
		s += "0123456789abcdef"[v >> 4];
		s += "0123456789abcdef"[v & 15];
	}
	return s;
}

TEST(crypto, fe_constants)
{
	// Canonical encodings of every field constant. The expected values were taken from the
	// radix 2^25.5 implementation, and the ones with a simple closed form were also checked
	// against it: d = -121665/121666, sqrt(-1), 2d, a-d, 2(a+d), -A, -A^2, A/3, 1, -1, 1/2.
	auto check = [](const char* name, const fe f, const char* expected)
	{
		ASSERT_EQ(fe_to_hex(f), expected) << name;
	};

		check("fe_d", fe_d, "a3785913ca4deb75abd841414d0a700098e879777940c78c73fe6f2bee6c0352");
		check("fe_sqrtm1", fe_sqrtm1, "b0a00e4a271beec478e42fad0618432fa7d7fb3d99004d2b0bdfc14f8024832b");
		check("fe_d2", fe_d2, "59f1b226949bd6eb56b183829a14e00030d1f3eef2808e19e7fcdf56dcd90624");
		check("fe_a_sub_d", fe_a_sub_d, "4987a6ec35b2148a5427bebeb2f58fff6717868886bf38738c0190d41193fc2d");
		check("fe_a0", fe_a0, "57f1b226949bd6eb56b183829a14e00030d1f3eef2808e19e7fcdf56dcd90624");
		check("fe_ap", fe_ap, "3f1d9ab2d7c85228529df8facad63ffe9f5d18221afee2cc31064052474cf237");
		check("fe_msqrt2b", fe_msqrt2b, "4c40eb97c83e9f1a09e458feee48bedc8d4b8660e4a7cfecdf760a985b374e18");
		check("fe_ma2", fe_ma2, "c9e33ddbc8ffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
		check("fe_ma", fe_ma, "e792f8ffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
		check("fe_fffb1", fe_fffb1, "ee411c327569a7228d732ab9a80494d1e319fb4137c5a920171bd6daeffb717e");
		check("fe_fffb2", fe_fffb2, "e09a7c608364ded2dff756044603de51be5f16c0b751d491f62c5a040a1e064d");
		check("fe_fffb3", fe_fffb3, "662c3017877d1b58294296a54eff2440eda20d3f404695b8ef08c2140d114a67");
		check("fe_fffb4", fe_fffb4, "8691b3b603193d85494a3fa108fc46ee2e43f77e88f4c026f9db671003f3431a");
		check("fe_a_inv_3", fe_a_inv_3, "5124adaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2a");
		check("fe_c", fe_c, "067e45ffaa046ecc821a7d4bd1d3a1c57e4ffc03dc087bd2bb06a060f4ed260f");
		check("fe_one", fe_one, "0100000000000000000000000000000000000000000000000000000000000000");
		check("fe_m1", fe_m1, "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
		check("fe_inv2", fe_inv2, "f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f");
}

TEST(crypto, fe_arithmetic)
{
	// Expected values come from an independent Python implementation of arithmetic mod 2^255-19
	auto check2 = [](const char* a_, const char* b_, const char* mul_, const char* add_, const char* sub_)
	{
		fe a, b, r, t;
		fe_from_hex(a, a_);
		fe_from_hex(b, b_);

		fe_mul(r, a, b); ASSERT_EQ(fe_to_hex(r), mul_) << a_ << " * " << b_;
		fe_add(r, a, b); ASSERT_EQ(fe_to_hex(r), add_) << a_ << " + " << b_;
		fe_sub(r, a, b); ASSERT_EQ(fe_to_hex(r), sub_) << a_ << " - " << b_;

		// The output is allowed to alias either input
		fe_copy(t, a); fe_mul(t, t, b); ASSERT_EQ(fe_to_hex(t), mul_);
		fe_copy(t, b); fe_mul(t, a, t); ASSERT_EQ(fe_to_hex(t), mul_);
		fe_copy(t, a); fe_add(t, t, b); ASSERT_EQ(fe_to_hex(t), add_);
		fe_copy(t, b); fe_sub(t, a, t); ASSERT_EQ(fe_to_hex(t), sub_);
	};

	auto check1 = [](const char* a_, const char* sq_, const char* neg_, const char* inv_)
	{
		fe a, r, t;
		fe_from_hex(a, a_);

		fe_sq(r, a);     ASSERT_EQ(fe_to_hex(r), sq_) << a_ << "^2";
		fe_mul(t, a, a); ASSERT_EQ(fe_to_hex(t), sq_) << "fe_sq disagrees with fe_mul for " << a_;
		fe_neg(r, a);    ASSERT_EQ(fe_to_hex(r), neg_) << "-" << a_;
		fe_invert(r, a); ASSERT_EQ(fe_to_hex(r), inv_) << "1/" << a_;

		fe_copy(t, a); fe_sq(t, t);  ASSERT_EQ(fe_to_hex(t), sq_);
		fe_copy(t, a); fe_neg(t, t); ASSERT_EQ(fe_to_hex(t), neg_);
	};

		// a, b, a*b, a+b, a-b
		check2("0000000000000000000000000000000000000000000000000000000000000000", "1300000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000", "1300000000000000000000000000000000000000000000000000000000000000", "daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
		check2("0000000000000000000000000000000000000000000000000000000000000000", "0000000000000800000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000", "0000000000000800000000000000000000000000000000000000000000000000", "edfffffffffff7ffffffffffffffffffffffffffffffffffffffffffffffff7f");
		check2("0100000000000000000000000000000000000000000000000000000000000000", "ffffffffffff0700000000000000000000000000000000000000000000000000", "ffffffffffff0700000000000000000000000000000000000000000000000000", "0000000000000800000000000000000000000000000000000000000000000000", "effffffffffff7ffffffffffffffffffffffffffffffffffffffffffffffff7f");
		check2("0100000000000000000000000000000000000000000000000000000000000000", "6143e8c46a758b0930884bddbe4f9d8916f9dcc5c35eeb2995290e24d8186f73", "6143e8c46a758b0930884bddbe4f9d8916f9dcc5c35eeb2995290e24d8186f73", "6243e8c46a758b0930884bddbe4f9d8916f9dcc5c35eeb2995290e24d8186f73", "8dbc173b958a74f6cf77b42241b06276e906233a3ca114d66ad6f1db27e7900c");
		check2("0200000000000000000000000000000000000000000000000000000000000000", "066d070000000000000000000000000000000000000000000000000000000000", "0cda0e0000000000000000000000000000000000000000000000000000000000", "086d070000000000000000000000000000000000000000000000000000000000", "e992f8ffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
		check2("0200000000000000000000000000000000000000000000000000000000000000", "f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f", "0100000000000000000000000000000000000000000000000000000000000000", "f9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f", "f8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f");
		check2("1300000000000000000000000000000000000000000000000000000000000000", "6143e8c46a758b0930884bddbe4f9d8916f9dcc5c35eeb2995290e24d8186f73", "76013d9decb659b5901b9b6c2aebac36ac7c66af8708781c12160dad0ad83e11", "7443e8c46a758b0930884bddbe4f9d8916f9dcc5c35eeb2995290e24d8186f73", "9fbc173b958a74f6cf77b42241b06276e906233a3ca114d66ad6f1db27e7900c");
		check2("1300000000000000000000000000000000000000000000000000000000000000", "e017ba58ab831832adeb93811790bf08c9a6077a9f03b44d7a040a1ae3d6cf4d", "71c6cf95b7c5d1b7da7dfa9dbeb137a6eb60910ed6445cc41355beeedaf26c46", "f317ba58ab831832adeb93811790bf08c9a6077a9f03b44d7a040a1ae3d6cf4d", "20e845a7547ce7cd52146c7ee86f40f73659f88560fc4bb285fbf5e51c293032");
		check2("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "0200000000000000000000000000000000000000000000000000000000000000", "ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "0100000000000000000000000000000000000000000000000000000000000000", "eaffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
		check2("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "0200000000000000000000000000000000000000000000000000000000000000", "eaffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "0100000000000000000000000000000000000000000000000000000000000000");
		check2("ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "b0a00e4a271beec478e42fad0618432fa7d7fb3d99004d2b0bdfc14f8024832b", "8dbee26bb1c923760e37a0a5f2cf79a1b1500884cdfe65a9e9417c60ffb6f928", "aea00e4a271beec478e42fad0618432fa7d7fb3d99004d2b0bdfc14f8024832b", "3b5ff1b5d8e4113b871bd052f9e7bcd0582804c266ffb2d4f4203eb07fdb7c54");
		check2("ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "e792f8ffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "0cda0e0000000000000000000000000000000000000000000000000000000000", "e592f8ffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "046d070000000000000000000000000000000000000000000000000000000000");
		check2("daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "1200000000000000000000000000000000000000000000000000000000000000", "97feffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "c8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
		check2("daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "0200000000000000000000000000000000000000000000000000000000000000", "c7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "dcffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "d8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
		check2("f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f", "d4e48d2b69d7593b4dfdb61252fe8e149f7cc05ffcef948bf5b49d283990ec33", "830d396a4b1453625981a4f6d680b875b0c11fd00188353a8525b16be3b70966", "cae48d2b69d7593b4dfdb61252fe8e149f7cc05ffcef948bf5b49d283990ec73", "221b72d49628a6c4b20249edad0171eb60833fa003106b740a4b62d7c66f130c");
		check2("f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f", "0000000000000000000000000000000000000000000000000000000000000008", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7b", "f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff47", "f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff37");
		check2("f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f", "0100000000000000000000000000000000000000000000000000000000000000", "f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f", "f8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f", "f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f");
		check2("f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f", "960d049deb27c059ad0fe700d7c0000a4338950099e559e0b32aa5a6b84f692c", "cb0682cef513e0acd68773806b600085219c4a80ccf22cf059955253dca73416", "8d0d049deb27c059ad0fe700d7c0000a4338950099e559e0b32aa5a6b84f696c", "61f2fb6214d83fa652f018ff283ffff5bcc76aff661aa61f4cd55a5947b09613");
		check2("b0a00e4a271beec478e42fad0618432fa7d7fb3d99004d2b0bdfc14f8024832b", "f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f", "585007a5930d77623cf29756038ca197d3ebfd9e4c80a69585efe0274092c115", "a7a00e4a271beec478e42fad0618432fa7d7fb3d99004d2b0bdfc14f8024836b", "a6a00e4a271beec478e42fad0618432fa7d7fb3d99004d2b0bdfc14f8024836b");
		check2("b0a00e4a271beec478e42fad0618432fa7d7fb3d99004d2b0bdfc14f8024832b", "0000000000000000000000004000000000000000000000000000000000000000", "baaf855b1beac6b1f5c2da5d9d2da883d2c9863b311ef94bab01c6d0cbe9f57e", "b0a00e4a271beec478e42fad4618432fa7d7fb3d99004d2b0bdfc14f8024832b", "b0a00e4a271beec478e42fadc617432fa7d7fb3d99004d2b0bdfc14f8024832b");
		check2("ffffffffffff0700000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000008", "edffffffff7f0900000000000000000000000000000000000000000000000078", "ffffffffffff0700000000000000000000000000000000000000000000000008", "ecffffffffff0700000000000000000000000000000000000000000000000078");
		check2("ffffffffffff0700000000000000000000000000000000000000000000000000", "8d7d6ce26f3c64d2061d69e4cf2c4588514ab08a96c1c36017494e26e9f1c479", "4cff70626f5d941a5df615ff5166f15ff7d8cedb9280c8f16a0c66e63414f64e", "8c7d6ce26f3c6cd2061d69e4cf2c4588514ab08a96c1c36017494e26e9f1c479", "5f82931d90c3a32df9e2961b30d3ba77aeb54f75693e3c9fe8b6b1d9160e3b06");
		check2("0000000000000800000000000000000000000000000000000000000000000000", "74b18473ef143004922676d9050faf026fbc295e9150f99f4cd6f8e9b8761124", "77d795fbbcd4ca8b259c7ba780219034b1cb2e78781578e34df18a84caff6432", "74b18473ef143804922676d9050faf026fbc295e9150f99f4cd6f8e9b8761124", "794e7b8c10ebd7fb6dd98926faf050fd9043d6a16eaf0660b32907164789ee5b");
		check2("0000000000000800000000000000000000000000000000000000000000000000", "b0a00e4a271beec478e42fad0618432fa7d7fb3d99004d2b0bdfc14f8024832b", "27b65e58bbabb30575503ad97027c6237f6935c0187a39bddeefc904685a5978", "b0a00e4a271bf6c478e42fad0618432fa7d7fb3d99004d2b0bdfc14f8024832b", "3d5ff1b5d8e4193b871bd052f9e7bcd0582804c266ffb2d4f4203eb07fdb7c54");
		check2("0000000000000000000000004000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000004000000000000000000000000000000000000000", "0000000000000000000000004000000000000000000000000000000000000000");
		check2("0000000000000000000000004000000000000000000000000000000000000000", "74b18473ef143004922676d9050faf026fbc295e9150f99f4cd6f8e9b8761124", "fd647dc0efd7f3bbaedce7a5565e2ce1dc3b050c81a4895d76c1c3abc01b6f0a", "74b18473ef143004922676d9450faf026fbc295e9150f99f4cd6f8e9b8761124", "794e7b8c10ebcffb6dd989263af150fd9043d6a16eaf0660b32907164789ee5b");
		check2("0000000000000000000000000000000000000000000000000010000000000000", "f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f", "edfffffffffffffffffffffffffffffffffffffffffffffffff7ffffffffff7f", "f6ffffffffffffffffffffffffffffffffffffffffffffffff0f000000000040", "f7ffffffffffffffffffffffffffffffffffffffffffffffff0f000000000040");
		check2("0000000000000000000000000000000000000000000000000010000000000000", "daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "edffffffffffffffffffffffffffffffffffffffffffffffffcffeffffffff7f", "edffffffffffffffffffffffffffffffffffffffffffffffff0f000000000000", "1300000000000000000000000000000000000000000000000010000000000000");
		check2("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "0100000000000000000000000000000000000000000000000000000000000000", "ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "0000000000000000000000000000000000000000000000000000000000000000");
		check2("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "cad9d91deb23237a665c7018be26646ef837225f05202c6fbcebb44f4b14935a", "232626e214dcdc8599a38fe741d99b9107c8dda0fadfd39043144bb0b4eb6c25", "c9d9d91deb23237a665c7018be26646ef837225f05202c6fbcebb44f4b14935a", "222626e214dcdc8599a38fe741d99b9107c8dda0fadfd39043144bb0b4eb6c25");
		check2("0000000000000000000000000000000000000000000000000000000000000008", "e017ba58ab831832adeb93811790bf08c9a6077a9f03b44d7a040a1ae3d6cf4d", "5afc5c795b1c7dabdda7dfe91b7b63ba0e16e9604dc4453c51e5ebae2dcf665c", "e017ba58ab831832adeb93811790bf08c9a6077a9f03b44d7a040a1ae3d6cf55", "0de845a7547ce7cd52146c7ee86f40f73659f88560fc4bb285fbf5e51c29303a");
		check2("0000000000000000000000000000000000000000000000000000000000000008", "1300000000000000000000000000000000000000000000000000000000000000", "1300000000000000000000000000000000000000000000000000000000000018", "1300000000000000000000000000000000000000000000000000000000000008", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff07");
		check2("1200000000000000000000000000000000000000000000000000000000000000", "960d049deb27c059ad0fe700d7c0000a4338950099e559e0b32aa5a6b84f692c", "fef4480a91ce824f301a3f101e8f0db4b6f47d0ac22452c6a5009db7fb9a671f", "a80d049deb27c059ad0fe700d7c0000a4338950099e559e0b32aa5a6b84f692c", "69f2fb6214d83fa652f018ff283ffff5bcc76aff661aa61f4cd55a5947b09653");
		check2("1200000000000000000000000000000000000000000000000000000000000000", "1200000000000000000000000000000000000000000000000000000000000000", "4401000000000000000000000000000000000000000000000000000000000000", "2400000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000");
		check2("066d070000000000000000000000000000000000000000000000000000000000", "daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "7be872ffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "f36c070000000000000000000000000000000000000000000000000000000000", "196d070000000000000000000000000000000000000000000000000000000000");
		check2("066d070000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000", "066d070000000000000000000000000000000000000000000000000000000000", "066d070000000000000000000000000000000000000000000000000000000000");
		check2("e792f8ffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "0000000000000000000000000000000000000000000000000010000000000000", "edffffffffffffffffffffffffffffffffffffffffffffffff9f2f89ffffff7f", "fa92f8ffffffffffffffffffffffffffffffffffffffffffff0f000000000000", "e792f8ffffffffffffffffffffffffffffffffffffffffffffefffffffffff7f");
		check2("e792f8ffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "0000000000000000000000000000000000000000000000000010000000000000", "edffffffffffffffffffffffffffffffffffffffffffffffff9f2f89ffffff7f", "fa92f8ffffffffffffffffffffffffffffffffffffffffffff0f000000000000", "e792f8ffffffffffffffffffffffffffffffffffffffffffffefffffffffff7f");
		check2("cad9d91deb23237a665c7018be26646ef837225f05202c6fbcebb44f4b14935a", "a07082be0ed0d90ef53744e109f2e9c7c03d1bf57f04992b4e7f880fb17dac0a", "593b47f4279f950308f8cde3fd53ede67405a3f14211e4fb520c9048f7efb946", "6a4a5cdcf9f3fc885b94b4f9c7184e36b9753d548524c59a0a6b3d5ffc913f65", "2a69575fdc53496b71242c37b4347aa637fa066a851b93436e6c2c409a96e64f");
		check2("cad9d91deb23237a665c7018be26646ef837225f05202c6fbcebb44f4b14935a", "795fa32bdd481a32dec9f7d716ec0e6132761a5252c87278a8983b9e0f775d0a", "d4907ce45e70f03569d04783d713d8e78ff065e1cb8e10552c3e188524b28517", "43397d49c86c3dac442668f0d41273cf2aae3cb157e89ee76484f0ed5a8bf064", "517a36f20ddb084888927840a73a550dc6c1070db357b9f6135379b13b9d3550");
		check2("a07082be0ed0d90ef53744e109f2e9c7c03d1bf57f04992b4e7f880fb17dac0a", "ab8b127e82f7ff93c4f3537c0b4087b98a2c889bc2d7cdaa72ba2ef8f6c22a53", "f700eedbd671aedd31a5a5b0e6b08e8db12075687121d56bf455d2a8addc333f", "4bfc943c91c7d9a2b92b985d153271814b6aa39042dc66d6c039b707a840d75d", "e2e46f408cd8d97a3044f064feb1620e36119359bd2ccb80dbc45917baba8137");
		check2("a07082be0ed0d90ef53744e109f2e9c7c03d1bf57f04992b4e7f880fb17dac0a", "ffffffffffff0700000000000000000000000000000000000000000000000000", "6501c083c6dc32761ebc319fc484bef760cc339bcf3a6dc28b29771417dfc46f", "9f7082be0ed0e10ef53744e109f2e9c7c03d1bf57f04992b4e7f880fb17dac0a", "a17082be0ed0d10ef53744e109f2e9c7c03d1bf57f04992b4e7f880fb17dac0a");
		check2("e017ba58ab831832adeb93811790bf08c9a6077a9f03b44d7a040a1ae3d6cf4d", "ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "1ad08b4ea9f8ce9ba528d8fcd0df80ee6db2f00bc1f897640bf7ebcb39526064", "de17ba58ab831832adeb93811790bf08c9a6077a9f03b44d7a040a1ae3d6cf4d", "e217ba58ab831832adeb93811790bf08c9a6077a9f03b44d7a040a1ae3d6cf4d");
		check2("e017ba58ab831832adeb93811790bf08c9a6077a9f03b44d7a040a1ae3d6cf4d", "d4e48d2b69d7593b4dfdb61252fe8e149f7cc05ffcef948bf5b49d283990ec33", "ff912e9fb2a81fbcb8752bc83f1273acf7233bfe819fc06c48fbffd7ecf79a6a", "c7fc4784145b726dfae84a94698e4e1d6823c8d99bf348d96fb9a7421c67bc01", "0c332c2d42acbef65feedc6ec59130f4292a471aa3131fc2844f6cf1a946e319");
		check2("74b18473ef143004922676d9050faf026fbc295e9150f99f4cd6f8e9b8761124", "0000000000000000000000004000000000000000000000000000000000000000", "fd647dc0efd7f3bbaedce7a5565e2ce1dc3b050c81a4895d76c1c3abc01b6f0a", "74b18473ef143004922676d9450faf026fbc295e9150f99f4cd6f8e9b8761124", "74b18473ef143004922676d9c50eaf026fbc295e9150f99f4cd6f8e9b8761124");
		check2("74b18473ef143004922676d9050faf026fbc295e9150f99f4cd6f8e9b8761124", "f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f", "33a73d4688f5e7fdb6ec44137d78a87ec821eb50b75703b0d994038ba344f76d", "6ab18473ef143004922676d9050faf026fbc295e9150f99f4cd6f8e9b8761164", "6bb18473ef143004922676d9050faf026fbc295e9150f99f4cd6f8e9b8761164");
		check2("d4e48d2b69d7593b4dfdb61252fe8e149f7cc05ffcef948bf5b49d283990ec33", "cad9d91deb23237a665c7018be26646ef837225f05202c6fbcebb44f4b14935a", "e7bab709b81d23ef8f3735d97d7770d0a4ea428f0d71c7d4deff4f0b64fa8566", "b1be674954fb7cb5b359272b1025f38297b4e2be0110c1fab1a0527884a47f0e", "f70ab40d7eb336c1e6a046fa93d72aa6a6449e00f7cf681c39c9e8d8ed7b5959");
		check2("d4e48d2b69d7593b4dfdb61252fe8e149f7cc05ffcef948bf5b49d283990ec33", "a07082be0ed0d90ef53744e109f2e9c7c03d1bf57f04992b4e7f880fb17dac0a", "e5894f16c91ddf0c77407e2234388817b21c1f1d849ed11cd3bc0bbc3241a933", "745510ea77a7334a4235fbf35bf078dc5fbadb547cf42db743342638ea0d993e", "34740b6d5a07802c58c57231480ca54cde3ea56a7cebfb5fa735151988124029");
		check2("6143e8c46a758b0930884bddbe4f9d8916f9dcc5c35eeb2995290e24d8186f73", "795fa32bdd481a32dec9f7d716ec0e6132761a5252c87278a8983b9e0f775d0a", "e98ac066bc12156463a18fe4b25753fe5fb5780ed927f7ad1afe9de89dae966d", "daa28bf047bea53b0e5243b5d53bacea486ff71716275ea23dc249c2e78fcc7d", "e8e344998d2c71d751be5305a8638e28e482c273719678b1ec90d285c8a11169");
		check2("6143e8c46a758b0930884bddbe4f9d8916f9dcc5c35eeb2995290e24d8186f73", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "8cbc173b958a74f6cf77b42241b06276e906233a3ca114d66ad6f1db27e7900c", "6043e8c46a758b0930884bddbe4f9d8916f9dcc5c35eeb2995290e24d8186f73", "6243e8c46a758b0930884bddbe4f9d8916f9dcc5c35eeb2995290e24d8186f73");
		check2("8d7d6ce26f3c64d2061d69e4cf2c4588514ab08a96c1c36017494e26e9f1c479", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "6082931d90c39b2df9e2961b30d3ba77aeb54f75693e3c9fe8b6b1d9160e3b06", "8c7d6ce26f3c64d2061d69e4cf2c4588514ab08a96c1c36017494e26e9f1c479", "8e7d6ce26f3c64d2061d69e4cf2c4588514ab08a96c1c36017494e26e9f1c479");
		check2("8d7d6ce26f3c64d2061d69e4cf2c4588514ab08a96c1c36017494e26e9f1c479", "066d070000000000000000000000000000000000000000000000000000000000", "823361effe3e24437b5602e7ffcf62dfd22e0158666d21e91950983aeafcfd52", "93ea73e26f3c64d2061d69e4cf2c4588514ab08a96c1c36017494e26e9f1c479", "871065e26f3c64d2061d69e4cf2c4588514ab08a96c1c36017494e26e9f1c479");
		check2("795fa32bdd481a32dec9f7d716ec0e6132761a5252c87278a8983b9e0f775d0a", "0000000000000800000000000000000000000000000000000000000000000000", "bbe68b62fd4ed4fb1a5de946d290f14ebebfb660770893b1d390924296c34345", "795fa32bdd482232dec9f7d716ec0e6132761a5252c87278a8983b9e0f775d0a", "795fa32bdd481232dec9f7d716ec0e6132761a5252c87278a8983b9e0f775d0a");
		check2("795fa32bdd481a32dec9f7d716ec0e6132761a5252c87278a8983b9e0f775d0a", "0100000000000000000000000000000000000000000000000000000000000000", "795fa32bdd481a32dec9f7d716ec0e6132761a5252c87278a8983b9e0f775d0a", "7a5fa32bdd481a32dec9f7d716ec0e6132761a5252c87278a8983b9e0f775d0a", "785fa32bdd481a32dec9f7d716ec0e6132761a5252c87278a8983b9e0f775d0a");
		check2("ab8b127e82f7ff93c4f3537c0b4087b98a2c889bc2d7cdaa72ba2ef8f6c22a53", "e792f8ffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "a73e1054c1300cc7608addac7f353f500ed10c287ed4fc73f5226230437d3b03", "a51e0b7e82f7ff93c4f3537c0b4087b98a2c889bc2d7cdaa72ba2ef8f6c22a53", "b1f8197e82f7ff93c4f3537c0b4087b98a2c889bc2d7cdaa72ba2ef8f6c22a53");
		check2("ab8b127e82f7ff93c4f3537c0b4087b98a2c889bc2d7cdaa72ba2ef8f6c22a53", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "4274ed817d08006c3b0cac83f4bf784675d377643d2832558d45d107093dd52c", "aa8b127e82f7ff93c4f3537c0b4087b98a2c889bc2d7cdaa72ba2ef8f6c22a53", "ac8b127e82f7ff93c4f3537c0b4087b98a2c889bc2d7cdaa72ba2ef8f6c22a53");
		check2("960d049deb27c059ad0fe700d7c0000a4338950099e559e0b32aa5a6b84f692c", "8d7d6ce26f3c64d2061d69e4cf2c4588514ab08a96c1c36017494e26e9f1c479", "14dd90c74fa397f5b37d86fe329b6c955ee9791c9053af6ff64975556f73f832", "368b707f5b64242cb42c50e5a6ed45929482458b2fa71d41cb73f3cca1412e26", "f68f97ba7beb5b87a6f27d1c0794bb81f1ede4750224967f9ce15680cf5da432");
		check2("960d049deb27c059ad0fe700d7c0000a4338950099e559e0b32aa5a6b84f692c", "ab8b127e82f7ff93c4f3537c0b4087b98a2c889bc2d7cdaa72ba2ef8f6c22a53", "8dc398d9b3ec61fa0a18cffe1f4f08c15877508818f86f937d770be194c38141", "4199161b6e1fc0ed71033b7de20088c3cd641d9c5bbd278b26e5d39eaf12947f", "d881f11e6930c0c5e81b9384cb807950b80b0d65d60d8c35417076aec18c3e59");

		// a, a*a, -a, 1/a
		check1("0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000");
		check1("0100000000000000000000000000000000000000000000000000000000000000", "0100000000000000000000000000000000000000000000000000000000000000", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "0100000000000000000000000000000000000000000000000000000000000000");
		check1("0200000000000000000000000000000000000000000000000000000000000000", "0400000000000000000000000000000000000000000000000000000000000000", "ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f");
		check1("1300000000000000000000000000000000000000000000000000000000000000", "6901000000000000000000000000000000000000000000000000000000000000", "daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "14ca6b28afa1bc86f21aca6b28afa1bc86f21aca6b28afa1bc86f21aca6b282f");
		check1("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "0100000000000000000000000000000000000000000000000000000000000000", "0100000000000000000000000000000000000000000000000000000000000000", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
		check1("ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "0400000000000000000000000000000000000000000000000000000000000000", "0200000000000000000000000000000000000000000000000000000000000000", "f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f");
		check1("daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "6901000000000000000000000000000000000000000000000000000000000000", "1300000000000000000000000000000000000000000000000000000000000000", "d93594d7505e43790de53594d7505e43790de53594d7505e43790de53594d750");
		check1("f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f", "f2ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff5f", "f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f", "ebffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
		check1("f7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f", "f2ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff5f", "f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f", "0200000000000000000000000000000000000000000000000000000000000000");
		check1("b0a00e4a271beec478e42fad0618432fa7d7fb3d99004d2b0bdfc14f8024832b", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "3d5ff1b5d8e4113b871bd052f9e7bcd0582804c266ffb2d4f4203eb07fdb7c54", "3d5ff1b5d8e4113b871bd052f9e7bcd0582804c266ffb2d4f4203eb07fdb7c54");
		check1("ffffffffffff0700000000000000000000000000000000000000000000000000", "010000000000f0ffffffffff3f00000000000000000000000000000000000000", "eefffffffffff7ffffffffffffffffffffffffffffffffffffffffffffffff7f", "89e3388ee338721cc7711cc791e3388ee3388e1cc7711cc771e4388ee3388e23");
		check1("0000000000000800000000000000000000000000000000000000000000000000", "0000000000000000000000004000000000000000000000000000000000000000", "edfffffffffff7ffffffffffffffffffffffffffffffffffffffffffffffff7f", "f5ffffffffffffffffffffffffffffffffffffffffffffffffafa1bc86f21a4a");
		check1("0000000000000000000000004000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000010000000000000", "edffffffffffffffffffffffbfffffffffffffffffffffffffffffffffffff7f", "f4ffffffffffffffffffffffffffffffffffff3594d7505e43790de53594d750");
		check1("0000000000000000000000000000000000000000000000000010000000000000", "0000000000000000000000000000000000000026000000000000000000000000", "edffffffffffffffffffffffffffffffffffffffffffffffffefffffffffff7f", "f8ffffffffffd7505e43790de53594d7505e43790de53594d7505e43790de535");
		check1("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "0100000000000000000000000000000000000000000000000000000000000000", "0100000000000000000000000000000000000000000000000000000000000000", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
		check1("0000000000000000000000000000000000000000000000000000000000000008", "0000000000000000000000000000000000000000000000000000000000008009", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff77", "9fa1bc86f21aca6b28afa1bc86f21aca6b28afa1bc86f21aca6b28afa1bc8672");
		check1("1200000000000000000000000000000000000000000000000000000000000000", "4401000000000000000000000000000000000000000000000000000000000000", "dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "89e3388ee3388ee3388ee3388ee3388ee3388ee3388ee3388ee3388ee3388e23");
		check1("066d070000000000000000000000000000000000000000000000000000000000", "241cc22437000000000000000000000000000000000000000000000000000000", "e792f8ffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "57223f32d02940ec1bf16d19078cb2dbed73303350938328b1930bace71bcc78");
		check1("e792f8ffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", "241cc22437000000000000000000000000000000000000000000000000000000", "066d070000000000000000000000000000000000000000000000000000000000", "96ddc0cd2fd6bf13e40e92e6f8734d24128ccfccaf6c7cd74e6cf45318e43307");
		check1("cad9d91deb23237a665c7018be26646ef837225f05202c6fbcebb44f4b14935a", "7ce9ee3c8bdaf36e39b50368386e3148b4fdf63f7413ea5cf232058904e0921d", "232626e214dcdc8599a38fe741d99b9107c8dda0fadfd39043144bb0b4eb6c25", "cb1b647eebf662c9120f0a46d5eb2b31f666b0fa473dbee76a19bda1a0019904");
		check1("a07082be0ed0d90ef53744e109f2e9c7c03d1bf57f04992b4e7f880fb17dac0a", "3270d122228c71a045d61d0ff3958cb2f03651625f155961f98bf82949f26776", "4d8f7d41f12f26f10ac8bb1ef60d16383fc2e40a80fb66d4b18077f04e825375", "f7107f66f6dc9064c7781a249fc294bdfd8404721a0a0882149d75eb656f5a79");
		check1("e017ba58ab831832adeb93811790bf08c9a6077a9f03b44d7a040a1ae3d6cf4d", "d867c28962f0c87d418c9e84e1ed15a54c1fb2ccfe572de3990b938605eb8d71", "0de845a7547ce7cd52146c7ee86f40f73659f88560fc4bb285fbf5e51c293032", "3a1ed3bc444fb0dc9a07360e5d91807ec4cec3d3a508e94e8655ce1843e15668");
		check1("74b18473ef143004922676d9050faf026fbc295e9150f99f4cd6f8e9b8761124", "77666630b247dcf1a6cba6d6b563c2a09a0932b37d25a7fa3e7e57526f0a494b", "794e7b8c10ebcffb6dd98926faf050fd9043d6a16eaf0660b32907164789ee5b", "d8092f762749d5fe0a47da84a5037ca24594fc36e86f62ce194a22a691232672");
		check1("d4e48d2b69d7593b4dfdb61252fe8e149f7cc05ffcef948bf5b49d283990ec33", "170ba6a201ee68f61a69a3da39183be8394c9f414dfbbcfe4963cd8fdf93cf36", "191b72d49628a6c4b20249edad0171eb60833fa003106b740a4b62d7c66f134c", "aa56e482fa6bc6736fae169422f66131510c9dc6961b56df280c9184e18f8102");
		check1("6143e8c46a758b0930884bddbe4f9d8916f9dcc5c35eeb2995290e24d8186f73", "8cddf45d20c50b9f59f130e0a88ff176c5506e09ebc0ed387bf664644500be14", "8cbc173b958a74f6cf77b42241b06276e906233a3ca114d66ad6f1db27e7900c", "995b164bbde87b1887fae6d355e3b1791a7de531ea2f32ce4ce2b6b47268785d");
		check1("8d7d6ce26f3c64d2061d69e4cf2c4588514ab08a96c1c36017494e26e9f1c479", "e547b8ef7d7d4d2f1bb3413b8e7359463e7a8c6b222f3f5d6d231389a87f1d56", "6082931d90c39b2df9e2961b30d3ba77aeb54f75693e3c9fe8b6b1d9160e3b06", "ac1a1c2b6469b3386b5d165cb1b4a7422a84cea6973f17c506324af4845c1a16");
		check1("795fa32bdd481a32dec9f7d716ec0e6132761a5252c87278a8983b9e0f775d0a", "ef20fd07ee42da51fda86b6a4216aefa47563de5195527a7e60b4df7693de478", "74a05cd422b7e5cd21360828e913f19ecd89e5adad378d875767c461f088a275", "1e62ab118b1c5b264c627ee5a396dae450c9a70f6286da23c3a9a66d75c10c4a");
		check1("ab8b127e82f7ff93c4f3537c0b4087b98a2c889bc2d7cdaa72ba2ef8f6c22a53", "40d51179305e97fafd3dc882909a23e1f99a0b0a40d4edfb74bf545a8ac7111a", "4274ed817d08006c3b0cac83f4bf784675d377643d2832558d45d107093dd52c", "893b6c682b4dbee9eec72cdf6f20c60127c0b3d48db81fd0db09080ae32e1242");
		check1("960d049deb27c059ad0fe700d7c0000a4338950099e559e0b32aa5a6b84f692c", "4231d8b254696c842d528794fffa149ce44de2f130000694920f3c044ea1766a", "57f2fb6214d83fa652f018ff283ffff5bcc76aff661aa61f4cd55a5947b09653", "961e3ca6dac152dacfe2b182774e07816190d5020a7d1b3b5f63efb5b180923f");
}

TEST(crypto, fe_bounds)
{
	// The group operations chain up to two fe_add before feeding the result to fe_mul or
	// fe_sub (ge_madd computes t0 = Z + Z and then r->Z = t0 + r->T, and ge_p2_dbl does the
	// same shape). Limbs are widest there, so that is where an overflow would show up.
	// fe_reduce brings a value back into the domain fe_tobytes expects.
	std::mt19937_64 rng(12345);

	auto random_fe = [&rng](fe f)
	{
		hash h;
		for (size_t i = 0; i < HASH_SIZE / sizeof(uint64_t); ++i) {
			h.u64()[i] = rng();
		}
		// Clear the top bits so the encoding is always canonical
		h.h[HASH_SIZE - 1] &= 0x0f;
		ASSERT_EQ(fe_frombytes_vartime(f, h.h), 0);
	};

	for (int i = 0; i < 2000; ++i) {
		fe a, b, c, t0, t1, lhs, rhs, x, y, z;

		random_fe(a);
		random_fe(b);
		random_fe(c);

		// (2a + b) * c == 2(a * c) + b * c, with the left side going through two chained adds
		fe_add(t0, a, a);
		fe_add(t1, t0, b);
		fe_mul(lhs, t1, c);

		fe_mul(x, a, c);
		fe_add(y, x, x);
		fe_mul(z, b, c);
		fe_add(rhs, y, z);
		fe_reduce(rhs, rhs);

		ASSERT_EQ(fe_to_hex(lhs), fe_to_hex(rhs)) << "distributivity failed at " << i;

		// (2a + b) - b == 2a, subtracting a value that has itself been through an add
		fe_sub(lhs, t1, b);
		fe_reduce(rhs, t0);
		ASSERT_EQ(fe_to_hex(lhs), fe_to_hex(rhs)) << "add/sub round-trip failed at " << i;

		// a + (-a) == 0, and a * (1/a) == 1
		fe_neg(x, a);
		fe_add(y, a, x);
		fe_reduce(y, y);
		ASSERT_EQ(fe_to_hex(y), std::string(64, '0'));

		fe_invert(x, a);
		fe_mul(y, a, x);
		ASSERT_EQ(fe_to_hex(y), "0100000000000000000000000000000000000000000000000000000000000000");

		// fe_sq of a doubled value still agrees with fe_mul
		fe_sq(x, t0);
		fe_mul(y, t0, t0);
		ASSERT_EQ(fe_to_hex(x), fe_to_hex(y));
	}

	// The widest subtrahend the group code can produce is a sum of two values whose limbs are
	// already at the top of their range, which is what ge_p2_dbl feeds to fe_sub. Random inputs
	// essentially never reach that corner, so build it explicitly: p - 1 has maximal limbs in
	// both representations.
	{
		fe a, big, dbl, two, lhs, rhs;

		fe_from_hex(big, "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
		fe_from_hex(two, "0200000000000000000000000000000000000000000000000000000000000000");
		fe_add(dbl, big, big);

		for (int i = 0; i < 256; ++i) {
			random_fe(a);

			// a - 2(p - 1) == a + 2 (mod p)
			fe_sub(lhs, a, dbl);
			fe_add(rhs, a, two);
			fe_reduce(rhs, rhs);
			ASSERT_EQ(fe_to_hex(lhs), fe_to_hex(rhs)) << "fe_sub underflowed on a maximal subtrahend";

			// and the result must still be usable as a multiplicand
			fe_mul(lhs, lhs, a);
			fe_mul(rhs, rhs, a);
			ASSERT_EQ(fe_to_hex(lhs), fe_to_hex(rhs));
		}
	}
}

TEST(crypto, fe_limb_bounds)
{
#if FE_RADIX_51
	// The bounds contract in crypto-ops.c rests on "reduced" meaning every limb <= 2^51: that is
	// what fixes the widest subtrahend fe_sub can take, because its 8p bias sits just below 2^54.
	//
	// Worth asserting directly rather than inferring from results, because the group code carries
	// enough slack that a limb could drift past 2^51 and every value would still come out correct.
	// Only a gross violation is detectable this way - the worst case for fe_mul lands exactly on
	// 2^51 - but that is the failure mode a future change to the field layer would produce.
	constexpr uint64_t MAX_LIMB = 1ULL << 51;
	constexpr uint64_t MAX_LOOSE_LIMB = 1ULL << 54;

	const auto check = [MAX_LIMB](const char* what, const fe f) {
		for (int i = 0; i < 5; ++i) {
			EXPECT_LE(f[i], MAX_LIMB) << what << ", limb " << i << " = 0x" << std::hex << f[i];
		}
	};

	// p - 1 has maximal limbs in both representations, so doubling it gives the widest values
	// the contract allows: x8 is a sum of eight reduced values, the top of the "loose" range
	fe big, x2, x4, x7, x8;
	fe_from_hex(big, "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
	fe_add(x2, big, big);
	fe_add(x4, x2, x2);
	fe_add(x8, x4, x4);
	fe_add(x7, x4, x2);
	fe_add(x7, x7, big);

	fe h, h2;

	fe_mul(h, x8, x8);   check("fe_mul(loose, loose)", h);
	fe_mul(h2, h, h);    check("fe_mul(reduced, reduced)", h2);
	fe_mul(h2, x8, h);   check("fe_mul(loose, reduced)", h2);
	fe_sq(h, x8);        check("fe_sq(loose)", h);
	fe_sq(h2, h);        check("fe_sq(reduced)", h2);

	// fe_sub and fe_neg carry their result, and take a subtrahend of at most seven reduced values
	fe_sub(h, x8, x7);   check("fe_sub(loose, 7x)", h);
	fe_sub(h, big, x7);  check("fe_sub(reduced, 7x)", h);
	fe_neg(h, x7);       check("fe_neg(7x)", h);
	fe_neg(h, big);      check("fe_neg(reduced)", h);

	fe_reduce(h, x8);    check("fe_reduce(loose)", h);
	fe_dbl(h, x8);       check("fe_dbl(loose)", h);
	fe_invert(h, big);   check("fe_invert", h);

	fe_1(h);             check("fe_1", h);
	fe_0(h);             check("fe_0", h);
	ASSERT_EQ(fe_frombytes_vartime(h, big_bytes_for_bounds), 0);
	check("fe_frombytes_vartime", h);

	// Random values through the same shapes, to catch a limb that only grows for some inputs
	std::mt19937_64 rng(999);

	for (int i = 0; i < 2000; ++i) {
		hash bytes;
		for (size_t k = 0; k < HASH_SIZE / sizeof(uint64_t); ++k) {
			bytes.u64()[k] = rng();
		}
		bytes.h[HASH_SIZE - 1] &= 0x0f;

		fe a, b, la, lb;
		ASSERT_EQ(fe_frombytes_vartime(a, bytes.h), 0);
		check("random fe_frombytes_vartime", a);

		fe_add(la, a, a);
		fe_add(la, la, la);
		fe_add(la, la, la);   // 8x
		fe_copy(b, a);
		fe_add(lb, b, b);
		fe_add(lb, lb, lb);
		fe_add(lb, lb, b);
		fe_add(lb, lb, b);
		fe_add(lb, lb, b);    // 7x

		fe_mul(h, la, la);  check("random fe_mul", h);
		fe_sq(h, la);       check("random fe_sq", h);
		fe_sub(h, la, lb);  check("random fe_sub", h);
		fe_neg(h, lb);      check("random fe_neg", h);
	}

	// 2^51 is not just an upper bound, it is reached, and both producers reach it on a different limb.
	// Pinning that keeps anyone from "tightening" the contract to < 2^51, which would be wrong.
	//
	// fe_mul and fe_sq end with h2 = LOW51 + (h1 >> 51), so limb 2 lands on 2^51 when that shift is 1
	// and the low part is already at 2^51 - 1. x8 is exactly the input that does it.
	{
		fe h;

		fe_mul(h, x8, x8);
		EXPECT_EQ(h[2], MAX_LIMB) << "fe_mul no longer reaches the top of the reduced range";

		fe_sq(h, x8);
		EXPECT_EQ(h[2], MAX_LIMB) << "fe_sq no longer reaches the top of the reduced range";
	}

	// fe51_carry masks limb 1 before the final wrap-around line adds the carry out of limb 0, so limb 1
	// is the one that can end at 2^51 there. Random inputs never land on it, so build it: limb 0 masks
	// to 2^51 - 1, limb 4 carries, 19*c4 pushes limb 0 over, and the 1 lands on a limb 1 already at
	// 2^51 - 1. Every subtrahend limb stays inside the seven-reduced-values limit fe_sub documents.
	{
		constexpr uint64_t MASK = MAX_LIMB - 1;
		constexpr uint64_t EIGHT_P_0 = 0x3fffffffffff68ULL;
		constexpr uint64_t EIGHT_P_N = 0x3ffffffffffff8ULL;
		constexpr uint64_t MAX_SUBTRAHEND = 7 * MAX_LIMB;

		fe zero, g, h;
		fe_0(zero);

		g[0] = EIGHT_P_0 - MASK;
		g[1] = EIGHT_P_N - MASK;
		g[2] = MAX_SUBTRAHEND;
		g[3] = MAX_SUBTRAHEND;
		g[4] = EIGHT_P_N - MAX_LIMB;

		for (int i = 0; i < 5; ++i) {
			ASSERT_LE(g[i], MAX_SUBTRAHEND) << "subtrahend limb " << i << " is outside the documented limit";
		}

		fe_sub(h, zero, g);
		check("fe_sub at the top of the range", h);
		EXPECT_EQ(h[1], MAX_LIMB) << "fe51_carry no longer reaches the top of the reduced range";

		fe n;
		fe_neg(n, g);
		EXPECT_EQ(fe_to_hex(n), fe_to_hex(h)) << "fe_neg and fe_sub from zero must agree";
		EXPECT_EQ(h[1], MAX_LIMB);

		// A limb sitting at the very top must still behave like any other reduced value: it has to
		// encode correctly, and seven of them summed must still be a safe subtrahend. That is the
		// exact corner where the "7, not 8" half of the contract earns its keep.
		EXPECT_EQ(fe_to_hex(h), "12000000000000000000000040fefffffffffff1ffffffffff0f000000000000");

		fe seven, lhs, rhs;
		fe_copy(seven, h);
		for (int i = 0; i < 6; ++i) {
			fe_add(seven, seven, h);
		}

		fe_sub(lhs, big, seven);
		check("fe_sub with a maximal seven-term subtrahend", lhs);

		fe_copy(rhs, big);
		for (int i = 0; i < 7; ++i) {
			fe_sub(rhs, rhs, h);
			check("fe_sub one maximal term at a time", rhs);
		}

		EXPECT_EQ(fe_to_hex(lhs), fe_to_hex(rhs)) << "subtracting 7h at once and one at a time must agree";

		// And it still works as a multiplicand
		fe inv, prod;
		fe_invert(inv, h);
		fe_mul(prod, h, inv);
		check("fe_mul with a maximal reduced operand", prod);
		EXPECT_EQ(fe_to_hex(prod), "0100000000000000000000000000000000000000000000000000000000000000");

		// The other end of the contract: "loose" tops out at 2^54, and eight of these reach it exactly.
		// Doubling p - 1 three times only gets to 2^54 - 8, because p - 1's limbs stop at 2^51 - 1, so
		// this is the only way to build the widest input fe_mul, fe_sq, fe_tobytes and fe_reduce accept.
		fe loose;
		fe_copy(loose, h);
		for (int i = 0; i < 7; ++i) {
			fe_add(loose, loose, h);
		}

		EXPECT_EQ(loose[1], MAX_LOOSE_LIMB) << "eight maximal reduced values must reach the loose bound exactly";

		for (int i = 0; i < 5; ++i) {
			EXPECT_LE(loose[i], MAX_LOOSE_LIMB) << "loose limb " << i << " is above 2^54";
		}

		// Everything that documents itself as accepting loose inputs has to handle it. The subtrahend
		// of an fe_sub is deliberately not among them - that is capped at seven reduced values - but a
		// loose minuend is fine, because fe_sub only ever adds to it.
		EXPECT_EQ(fe_to_hex(loose), "90000000000000000000000000f2ffffffffff8fffffffffff7f000000000000");

		fe reduced;
		fe_reduce(reduced, loose);
		check("fe_reduce of a maximal loose value", reduced);
		EXPECT_EQ(fe_to_hex(reduced), fe_to_hex(loose));

		fe wide_prod, narrow_prod;
		fe_mul(wide_prod, loose, loose);
		check("fe_mul of two maximal loose values", wide_prod);
		EXPECT_EQ(fe_to_hex(wide_prod), "80220200000000320500000000a0dfffffffff7f8bffffffffff530100000000");

		// The same field value in reduced form must multiply to the same result
		fe_mul(narrow_prod, reduced, reduced);
		EXPECT_EQ(fe_to_hex(wide_prod), fe_to_hex(narrow_prod)) << "fe_mul disagrees between loose and reduced inputs";

		fe wide_sq;
		fe_sq(wide_sq, loose);
		check("fe_sq of a maximal loose value", wide_sq);
		EXPECT_EQ(fe_to_hex(wide_sq), fe_to_hex(wide_prod));

		fe mixed;
		fe_mul(mixed, loose, h);
		check("fe_mul of a maximal loose and a maximal reduced value", mixed);
		fe_mul(prod, reduced, h);
		EXPECT_EQ(fe_to_hex(mixed), fe_to_hex(prod));

		// A loose minuend with a subtrahend at its own limit, which is the widest fe_sub ever sees
		fe wide_diff;
		fe_sub(wide_diff, loose, seven);
		check("fe_sub of a maximal loose minuend", wide_diff);

		fe_sub(rhs, reduced, seven);
		EXPECT_EQ(fe_to_hex(wide_diff), fe_to_hex(rhs)) << "fe_sub disagrees between loose and reduced minuends";
	}
#endif
}

TEST(crypto, fe_encoding)
{
	// fe_frombytes_vartime must accept exactly [0, p-1] and reject [p, 2^255-1]
	uint8_t b[HASH_SIZE];
	fe f;

	auto set = [&b](const char* s)
	{
		hash h;
		ASSERT_TRUE(from_hex(s, strlen(s), h));
		memcpy(b, h.h, HASH_SIZE);
	};

	// p - 1 is the largest accepted value
	set("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
	ASSERT_EQ(fe_frombytes_vartime(f, b), 0);
	ASSERT_EQ(fe_to_hex(f), "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");

	// p, p + 1, ..., 2^255 - 1 are all rejected
	for (int i = 0; i < 19; ++i) {
		set("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
		b[0] = static_cast<uint8_t>(0xed + i);
		ASSERT_EQ(fe_frombytes_vartime(f, b), -1) << "accepted p + " << i;
	}

	// Bit 255 is ignored, so p - 1 with the high bit set is still accepted and decodes the same
	set("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
	ASSERT_EQ(fe_frombytes_vartime(f, b), 0);
	ASSERT_EQ(fe_to_hex(f), "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");

	// ...and so is a value that is only non-canonical once bit 255 is cleared
	set("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
	ASSERT_EQ(fe_frombytes_vartime(f, b), -1);

	// Round-trip every byte length boundary
	for (int i = 0; i < 32; ++i) {
		memset(b, 0, sizeof(b));
		b[i] = 0x5a;
		ASSERT_EQ(fe_frombytes_vartime(f, b), 0);
		uint8_t out[HASH_SIZE];
		fe_tobytes(out, f);
		ASSERT_EQ(memcmp(out, b, HASH_SIZE), 0) << "round-trip failed at byte " << i;
	}
}

}
