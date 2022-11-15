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
#include "json_parsers.h"
#include <rapidjson/document.h>
#include "gtest/gtest.h"
#include <random>
#include <sstream>

namespace p2pool {

TEST(difficulty_type, constructors)
{
	difficulty_type diff;
	ASSERT_EQ(diff.lo, 0);
	ASSERT_EQ(diff.hi, 0);

	difficulty_type diff2(123, 456);
	ASSERT_EQ(diff2.lo, 123);
	ASSERT_EQ(diff2.hi, 456);
}

TEST(difficulty_type, target)
{
	// diff = 0
	{
		difficulty_type d(0, 0);
		ASSERT_EQ(d.target(), std::numeric_limits<uint64_t>::max());
	}

	// diff = 1
	{
		difficulty_type d(1, 0);
		ASSERT_EQ(d.target(), std::numeric_limits<uint64_t>::max());
	}

	// diff = 2^64
	{
		difficulty_type d(0, 1);
		ASSERT_EQ(d.target(), 1);
	}

	// diff = max
	{
		difficulty_type d(std::numeric_limits<uint64_t>::max(), std::numeric_limits<uint64_t>::max());
		ASSERT_EQ(d.target(), 1);
	}

	// diff = 2^32
	{
		difficulty_type d(1ull << 32, 0);
		ASSERT_EQ(d.target(), 1ull << 32);
	}

	// diff from block 2440918
	{
		difficulty_type d(334654765825ull, 0);
		ASSERT_EQ(d.target(), 55121714);
	}
}

TEST(difficulty_type, add_sub)
{
	auto check = [](const difficulty_type& a, const difficulty_type& b, const difficulty_type& sum)
	{
		difficulty_type result1 = a + b;
		difficulty_type result2 = a;
		result2 += b;

		ASSERT_EQ(result1, sum);
		ASSERT_EQ(result2, sum);

		ASSERT_EQ(sum - a, b);
		ASSERT_EQ(sum - b, a);

		result1 -= a;
		ASSERT_EQ(result1, b);

		result2 -= b;
		ASSERT_EQ(result2, a);
	};

	// No carry
	{
		difficulty_type diff[4] = { { 0, 0 }, { 1, 0 }, { 0, 1 }, { 1, 1 } };

		for (int i = 0; i <= 3; ++i) {
			for (int j = 0; j <= 3; ++j) {
				difficulty_type sum(diff[i].lo + diff[j].lo, diff[i].hi + diff[j].hi);
				check(diff[i], diff[j], sum);
			}
		}
	}

	// Carry
	{
		difficulty_type a(11400714819323198485ull, 0);
		difficulty_type b(15975348984942515101ull, 0);
		difficulty_type sum(8929319730556161970ull, 1);
		check(a, b, sum);
	}

	// Carry (edge case)
	{
		difficulty_type a(std::numeric_limits<uint64_t>::max(), 0);
		difficulty_type b(1, 0);
		difficulty_type sum(0, 1);
		check(a, b, sum);
	}
}

TEST(difficulty_type, mul_div)
{
	auto check = [](const difficulty_type& a, uint64_t b, const difficulty_type& product)
	{
		difficulty_type result = a;

		result *= b;
		ASSERT_EQ(result, product);

		if (b) {
			result /= b;
			ASSERT_EQ(result, a);
		}
	};

	const difficulty_type max_diff(std::numeric_limits<uint64_t>::max(), std::numeric_limits<uint64_t>::max());

	// (2^128 - 1) * 0 = 0
	check(max_diff, 0, difficulty_type(0, 0));

	// (2^128 - 1) * 1 = 2^128 - 1
	check(max_diff, 1, max_diff);

	// 5057672949897463733145855 * 67280421310721 = 2^128 - 1
	check(difficulty_type(18446744073709277439ull, 274176ull), 67280421310721ull, max_diff);

	// 10^19 * 10 = 10^20
	check(difficulty_type(10000000000000000000ull, 0), 10, difficulty_type(7766279631452241920ull, 5));

	// 10^20 * 10 = 10^21
	check(difficulty_type(7766279631452241920ull, 5), 10, difficulty_type(3875820019684212736ull, 54));

	// 0 * (2^64 - 1) = 0
	check(difficulty_type(0, 0), std::numeric_limits<uint64_t>::max(), difficulty_type(0, 0));

	// 1 * (2^64 - 1) = 2^64 - 1
	check(difficulty_type(1, 0), std::numeric_limits<uint64_t>::max(), difficulty_type(std::numeric_limits<uint64_t>::max(), 0));

	// 2^64 * (2^64 - 1) = 2^128 - 2^64
	check(difficulty_type(0, 1), std::numeric_limits<uint64_t>::max(), difficulty_type(0, std::numeric_limits<uint64_t>::max()));

	// (2^64 + 1) * (2^64 - 1) = 2^128 - 1
	check(difficulty_type(1, 1), std::numeric_limits<uint64_t>::max(), max_diff);

	// 2753074036095 * 6700417 = 2^64 - 1
	check(difficulty_type(2753074036095ull, 0), 6700417, difficulty_type(std::numeric_limits<uint64_t>::max(), 0));

	// 2^32 * 2^32 = 2^64
	check(difficulty_type(4294967296ull, 0), 4294967296ull, difficulty_type(0, 1));

	// 274177 * 67280421310721 = 2^64 + 1
	check(difficulty_type(274177, 0), 67280421310721ull, difficulty_type(1, 1));

	// Powers of 2
	{
		difficulty_type a(1, 0);

		for (int i = 0; i < 64; ++i) {
			ASSERT_EQ(a.lo, 1ull << i);
			ASSERT_EQ(a.hi, 0);
			a *= 2;

			difficulty_type b = a;
			b /= 2;
			ASSERT_EQ(b.lo, 1ull << i);
			ASSERT_EQ(b.hi, 0);
		}

		for (int i = 0; i < 64; ++i) {
			ASSERT_EQ(a.lo, 0);
			ASSERT_EQ(a.hi, 1ull << i);
			a *= 2;

			if (i < 63) {
				difficulty_type b = a;
				b /= 2;
				ASSERT_EQ(b.lo, 0);
				ASSERT_EQ(b.hi, 1ull << i);
			}
		}

		ASSERT_EQ(a.lo, 0);
		ASSERT_EQ(a.hi, 0);
	}

	// No carry
	check(difficulty_type(123, 456), 789, difficulty_type(97047, 359784));
}

TEST(difficulty_type, compare)
{
	const difficulty_type diff[4] = { { 0, 0 }, { 1, 0 }, { 0, 1 }, { 1, 1 } };

	for (int i = 0; i <= 3; ++i) {
		for (int j = 0; j <= 3; ++j) {
			ASSERT_EQ(diff[i] <  diff[j], i <  j);
			ASSERT_EQ(diff[i] >= diff[j], i >= j);
			ASSERT_EQ(diff[i] == diff[j], i == j);
			ASSERT_EQ(diff[i] != diff[j], i != j);
		}
	}
}

TEST(difficulty_type, input_output)
{
	auto test_value = [](uint64_t lo, uint64_t hi, const char* s) {
		difficulty_type diff{ lo, hi };
		std::stringstream ss;
		ss << diff;
		ASSERT_EQ(ss.str(), s);
		difficulty_type diff2;
		ss >> diff2;
		ASSERT_EQ(diff2, diff);
	};

	test_value(0, 0, "0");
	test_value(1, 0, "1");
	test_value(340599339356ull, 0, "340599339356");
	test_value(std::numeric_limits<uint64_t>::max(), 0, "18446744073709551615");
	test_value(0, 1, "18446744073709551616");
	test_value(1, 1, "18446744073709551617");
	test_value(7766279631452241919ull, 5, "99999999999999999999");
	test_value(7766279631452241920ull, 5, "100000000000000000000");
	test_value(7766279631452241921ull, 5, "100000000000000000001");
	test_value(14083847773837265618ull, 6692605942ull, "123456789012345678901234567890");
	test_value(std::numeric_limits<uint64_t>::max(), std::numeric_limits<uint64_t>::max(), "340282366920938463463374607431768211455");
}

TEST(difficulty_type, json_parser)
{
	auto test_value = [](uint64_t lo, uint64_t hi, const char* s) {
		difficulty_type diff{ lo, hi };
		std::stringstream ss;
		ss << "{\"diff\":\"" << s << "\"}";

		using namespace rapidjson;
		Document doc;
		doc.Parse(ss.str().c_str());

		difficulty_type diff2;
		parseValue(doc, "diff", diff2);
		ASSERT_EQ(diff2, diff);
	};

	test_value(0, 0, "0x0");
	test_value(1, 0, "0x1");
	test_value(0x123456789abcdefull, 0, "0x123456789abcdef");
	test_value(0x123456789abcdefull, 0, "0x123456789ABCDEF");
	test_value(std::numeric_limits<uint64_t>::max(), 0, "0xffffffffffffffff");
	test_value(0, 1, "0x10000000000000000");
	test_value(1, 1, "0x10000000000000001");
	test_value(0x1122334455667788ull, 0x99aabbccddeeff00ull, "0x99aabbccddeeff001122334455667788");
	test_value(std::numeric_limits<uint64_t>::max(), std::numeric_limits<uint64_t>::max(), "0xffffffffffffffffffffffffffffffff");
}

TEST(difficulty_type, check_pow)
{
	hash h;

	// Power of 2 close to the current Monero network difficulty
	difficulty_type diff = { 1ull << 38, 0 };
	{
		// 2^256 / 2^38 = 2^218
		// diff.check_pow() will get 2^256 as a multiplication result = lowest possible value that fails the test
		uint64_t data[4] = { 0, 0, 0, 1ull << 26 };
		memcpy(h.h, data, HASH_SIZE);
		ASSERT_EQ(diff.check_pow(h), false);

		// Now decrease the hash by 1. It should pass the test now
		data[0] = data[1] = data[2] = std::numeric_limits<uint64_t>::max();
		--data[3];
		memcpy(h.h, data, HASH_SIZE);
		ASSERT_EQ(diff.check_pow(h), true);
	}

	/*
	* Factors of 2^256 - 1:
	* P1 = 3
	* P1 = 5
	* P2 = 17
	* P3 = 257
	* P3 = 641
	* P5 = 65537
	* P6 = 274177
	* P7 = 6700417
	* P14 = 67280421310721
	* P17 = 59649589127497217
	* P22 = 5704689200685129054721
	*/
	diff = { 67280421310721ull, 0 };
	{
		// (2^256 - 1) / 67280421310721 = 1721036922503113971692907638171526209875755521904893141463060735
		// diff.check_pow() will get 2^256-1 as a multiplication result = highest possible value that still passes the test
		uint64_t data[4] = { 0xfffffffffffbd0ffull, 0x0000000000042f00ull, 0xfffffffffffbd0ffull, 0x42f00ull };
		memcpy(h.h, data, HASH_SIZE);
		ASSERT_EQ(diff.check_pow(h), true);

		// Now increase the hash by 1. It should not pass the test anymore
		++data[0];
		memcpy(h.h, data, HASH_SIZE);
		ASSERT_EQ(diff.check_pow(h), false);
	}

	// diff = 5704689200685129054721
	diff = { 4645281908877605377ull, 309ull };
	{
		// (2^256 - 1) / 5704689200685129054721 = 20297703374166229616474325006177763232573806344580020735
		// diff.check_pow() will get 2^256-1 as a multiplication result = highest possible value that still passes the test
		uint64_t data[4] = { 0xff2c1503c50eb9ffull, 0xffffffffffffffffull, 0xd3eafc3af14600ull, 0 };
		memcpy(h.h, data, HASH_SIZE);
		ASSERT_EQ(diff.check_pow(h), true);

		// Now increase the hash by 1. It should not pass the test anymore
		++data[0];
		memcpy(h.h, data, HASH_SIZE);
		ASSERT_EQ(diff.check_pow(h), false);
	}

	/*
	* Factors of 2^256 + 1:
	* P16 = 1238926361552897
	* P62 = 93461639715357977769163558199606896584051237541638188580280321
	*/
	diff = { 1238926361552897ull, 0 };
	{
		// (2^256 + 1) / 1238926361552897 = 93461639715357977769163558199606896584051237541638188580280321
		// diff.check_pow() will get 2^256+1 as a multiplication result = lowest possible non-power of 2 that fails the test
		uint64_t data[4] = { 0x49baa0ba2c911801ull, 0x6ee3637cab2586d0ull, 0x4c585a8f5c7073e3, 0x3a29ull };
		memcpy(h.h, data, HASH_SIZE);
		ASSERT_EQ(diff.check_pow(h), false);

		// Now decrease the hash by 1. It should pass the test now
		--data[0];
		memcpy(h.h, data, HASH_SIZE);
		ASSERT_EQ(diff.check_pow(h), true);
	}

	// Randomized tests with fixed seed
	std::mt19937_64 r(0);

	for (int i = 0; i < 1000; ++i) {
		// Random difficulty between 300G and 400G
		difficulty_type diff{ 300000000000ull + (r() % 100000000000ull), 0 };
		hash h;

		// All zeros
		memset(h.h, 0, HASH_SIZE);
		ASSERT_EQ(diff.check_pow(h), true);

		// All ones
		memset(h.h, -1, HASH_SIZE);
		ASSERT_EQ(diff.check_pow(h), false);

		{
			uint64_t data[4];
			uint64_t rem;
			data[3] = udiv128(1, 0, diff.lo, &rem);
			data[2] = udiv128(rem, 0, diff.lo, &rem);
			data[1] = udiv128(rem, 0, diff.lo, &rem);
			data[0] = udiv128(rem, 0, diff.lo, &rem);

			// Max hash value that passes this difficulty
			memcpy(h.h, data, HASH_SIZE);
			ASSERT_EQ(diff.check_pow(h), true);

			// Add 1 to data (256-bit number)
			for (int j = 0; j <= 3; ++j) {
				++data[j];
				if (data[j]) {
					// No carry, exit the loop
					break;
				}
			}

			// Min hash value that fails this difficulty
			memcpy(h.h, data, HASH_SIZE);
			ASSERT_EQ(diff.check_pow(h), false);
		}

		const uint64_t target = diff.target();

		// Random values that pass
		for (int j = 0; j < 10000; ++j) {
			const uint64_t data[4] = { r(), r(), r(), r() % target };
			memcpy(h.h, data, HASH_SIZE);
			ASSERT_EQ(diff.check_pow(h), true);
		}

		// Random values that fail
		for (int j = 0; j < 10000; ++j) {
			const uint64_t data[4] = { r(), r(), r(), target + (r() % (std::numeric_limits<uint64_t>::max() - target + 1)) };
			memcpy(h.h, data, HASH_SIZE);
			ASSERT_EQ(diff.check_pow(h), false);
		}
	}
}

}
