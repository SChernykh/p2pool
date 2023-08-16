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

static const difficulty_type max_diff{ std::numeric_limits<uint64_t>::max(), std::numeric_limits<uint64_t>::max() };

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
	ASSERT_EQ(max_diff.target(), 1);

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
		ASSERT_EQ(a * b, product);

		difficulty_type result = a;
		result *= b;
		ASSERT_EQ(result, product);

		if (b) {
			ASSERT_EQ(result / b, a);

			difficulty_type tmp = result;
			tmp /= difficulty_type(b, 0);
			ASSERT_EQ(tmp, a);

			difficulty_type tmp2 = result;
			tmp2 /= b;
			ASSERT_EQ(tmp2, a);
		}
	};

	// (2^128 - 1) * 0 = 0
	check(max_diff, 0, { 0, 0 });

	// (2^128 - 1) * 1 = 2^128 - 1
	check(max_diff, 1, max_diff);

	// 5057672949897463733145855 * 67280421310721 = 2^128 - 1
	check({ 18446744073709277439ull, 274176ull }, 67280421310721ull, max_diff);

	// 10^19 * 10 = 10^20
	check({ 10000000000000000000ull, 0 }, 10, { 7766279631452241920ull, 5 });

	// 10^20 * 10 = 10^21
	check({ 7766279631452241920ull, 5 }, 10, { 3875820019684212736ull, 54 });

	// 0 * (2^64 - 1) = 0
	check({ 0, 0 }, std::numeric_limits<uint64_t>::max(), { 0, 0 });

	// 1 * (2^64 - 1) = 2^64 - 1
	check({ 1, 0 }, std::numeric_limits<uint64_t>::max(), { std::numeric_limits<uint64_t>::max(), 0 });

	// 2^64 * (2^64 - 1) = 2^128 - 2^64
	check({ 0, 1 }, std::numeric_limits<uint64_t>::max(), { 0, std::numeric_limits<uint64_t>::max() });

	// (2^64 + 1) * (2^64 - 1) = 2^128 - 1
	check({ 1, 1 }, std::numeric_limits<uint64_t>::max(), max_diff);

	// 2753074036095 * 6700417 = 2^64 - 1
	check({ 2753074036095ull, 0 }, 6700417, { std::numeric_limits<uint64_t>::max(), 0 });

	// 2^32 * 2^32 = 2^64
	check({ 4294967296ull, 0 }, 4294967296ull, { 0, 1 });

	// 274177 * 67280421310721 = 2^64 + 1
	check({ 274177, 0 }, 67280421310721ull, { 1, 1 });

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
	check({ 123, 456 }, 789, { 97047, 359784 });
}

static NOINLINE difficulty_type div128_ref(difficulty_type a, difficulty_type b)
{
	difficulty_type result{};

	while (a >= b) {
		difficulty_type t = b;
		difficulty_type q{ 1, 0 };
		while (a - t >= t) {
			t += t;
			q += q;
		}
		a -= t;
		result += q;
	}

	return result;
}

TEST(difficulty_type, div128)
{
	auto check = [](difficulty_type a, difficulty_type b, difficulty_type result)
	{
		ASSERT_EQ(div128_ref(a, b), result);
		ASSERT_EQ(a / b, result);
		a /= b;
		ASSERT_EQ(a, result);
	};

	// (2^128 - 1) / (2^128 - 1) = 1
	check(max_diff, max_diff, { 1, 0 });

	// (2^128 - 1) / (2^64 - 1) = 2^64 + 1
	check(max_diff, { std::numeric_limits<uint64_t>::max(), 0 }, { 1, 1 });

	// (2^128 - 1) / 2^64 = 2^64 - 1
	check(max_diff, { 0, 1 }, { std::numeric_limits<uint64_t>::max(), 0 });

	// (2^128 - 1) / (2^64 + 1) = 2^64 - 1
	check(max_diff, { 1, 1 }, { std::numeric_limits<uint64_t>::max(), 0 });

	// (2^128 - 1) / 8100430714362380904069067128193 = 42007935
	check(max_diff, { 439125228929, 439125228929 }, { 42007935, 0 });

	// (2^128 - 2^64) / (2^64 + 1) = 2^64 - 2
	check({ 0, std::numeric_limits<uint64_t>::max() }, { 1, 1 }, { std::numeric_limits<uint64_t>::max() - 1, 0 });

	// (2^128 - 2^64) / 2^64 = 2^64 - 1
	check({ 0, std::numeric_limits<uint64_t>::max() }, { 0, 1 }, { std::numeric_limits<uint64_t>::max(), 0 });

	// (2^128 - 2^64) / (2^64 - 1) = 2^64
	check({ 0, std::numeric_limits<uint64_t>::max() }, { std::numeric_limits<uint64_t>::max(), 0 }, { 0, 1 });

	{
		difficulty_type a = max_diff - 4;

		// (2^128 - 5) / 2002733033099709041094789607565039 = 169909
		check(a, { 7565587230673184495, 108568375269759 }, { 169909, 0 });

		// (2^128 - 5) / 2002733033099709041094789607565040 = 169908
		check(a, { 7565587230673184496, 108568375269759 }, { 169908, 0 });

		a -= 1;

		// (2^128 - 6) / 2002733033099709041094789607565039 = 169908
		check(a, { 7565587230673184495, 108568375269759 }, { 169908, 0 });

		// (2^128 - 6) / 2002733033099709041094789607565038 = 169909
		check(a, { 7565587230673184494, 108568375269759 }, { 169909, 0 });
	}

	// Powers of 2
	for (difficulty_type i{ 1, 0 }, j = max_diff; !i.empty(); i += i, j /= 2) {
		check(max_diff, i, j);
	}

	// Trivial tests
	check({ 0, 3 }, { 0, 1 }, { 3, 0 });
	check({ 0, 3 }, { 1, 1 }, { 2, 0 });
	check({ 123 * 4 - 1, 456 * 4 }, { 123, 456 }, { 3, 0 });
	check({ 123 * 4, 456 * 4 }, { 123, 456 }, { 4, 0 });

	// Exhaustive tests (top 8 bits of each number)
	for (uint64_t i = 1; i < 256; ++i) {
		for (uint64_t j = 1; j < 256; ++j) {
			const difficulty_type a{ 0, i << 56 };
			const difficulty_type b{ 0, j << 56 };
			{
				difficulty_type t = a;
				t /= b;
				ASSERT_EQ(t.lo, i / j);
				ASSERT_EQ(t.hi, 0);
			}
		}
	}

	// Bit patterns
	std::vector<difficulty_type> patterns;

	// 2^N-1, 2^N, 2^N+1
	for (uint64_t i = 0; i < 128; ++i) {
		difficulty_type t;
		reinterpret_cast<uint64_t*>(&t)[i / 64] |= 1ull << (i % 64);
		patterns.emplace_back(t - 1);
		patterns.emplace_back(t);
		patterns.emplace_back(t + 1);
	}

	// 2^N+2^M, 2^N-2^M
	bool check_bits[128] = {};
	for (uint64_t i = 64 - 4; i < 64 + 4; ++i) {
		check_bits[i] = true;
	}
	for (uint64_t i = 128 - 8; i < 128; ++i) {
		check_bits[i] = true;
	}
	for (uint64_t i = 0; i < 128; ++i) {
		if (!check_bits[i]) {
			continue;
		}
		difficulty_type t1;
		reinterpret_cast<uint64_t*>(&t1)[i / 64] = 1ull << (i % 64);
		for (uint64_t j = i + 1; j < 128; ++j) {
			if (!check_bits[j]) {
				continue;
			}
			difficulty_type t2;
			reinterpret_cast<uint64_t*>(&t2)[j / 64] = 1ull << (j % 64);
			patterns.emplace_back(t2 + t1);
			patterns.emplace_back(t2 - t1);
		}
	}

	// All previous patterns, but ~X
	for (size_t i = 0, n = patterns.size(); i < n; ++i) {
		patterns.emplace_back(~patterns[i].lo, ~patterns[i].hi);
	}

	std::sort(patterns.begin(), patterns.end());
	patterns.erase(std::unique(patterns.begin(), patterns.end()), patterns.end());

	// remove 0
	patterns.erase(patterns.begin());

	for (size_t i = 0, n = patterns.size(); i < n; ++i) {
		const difficulty_type& a = patterns[i];
		for (size_t j = i + 1; j < n; ++j) {
			const difficulty_type& b = patterns[j];
			ASSERT_EQ(div128_ref(b, a), b / a);
		}
	}

	// Random tests with fixed seed
	std::mt19937_64 r(0);

	for (uint64_t i = 0; i < 10000000; ++i) {
		// Random number of bits [1, 63]
		const uint64_t N = (r() % 63) + 1;

		// Random multiplier [1, 2^N - 1]
		uint64_t k;
		do {
			k = r() & ((1ull << N) - 1);
		} while (k == 0);

		uint64_t t;
		const uint64_t max_a = udiv128(1, 0, k + 1, &t);

		// Random number [2^64, 2^128 / (k + 1)]
		difficulty_type a{ r(), 0 };
		do {
			a.hi = r() % max_a;
		} while (a.hi == 0);

		difficulty_type b1 = a * k;
		difficulty_type b2 = b1 - 1;
		difficulty_type b3 = b1 + a;
		difficulty_type b4 = b3 - 1;

		b1 /= a;
		ASSERT_EQ(b1.lo, k);
		ASSERT_EQ(b1.hi, 0);

		b2 /= a;
		ASSERT_EQ(b2.lo, k - 1);
		ASSERT_EQ(b2.hi, 0);

		b3 /= a;
		ASSERT_EQ(b3.lo, k + 1);
		ASSERT_EQ(b3.hi, 0);

		b4 /= a;
		ASSERT_EQ(b4.lo, k);
		ASSERT_EQ(b4.hi, 0);
	}
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
		diff.lo = 300000000000ull + (r() % 100000000000ull);
		diff.hi = 0;

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
