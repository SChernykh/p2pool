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
#include "fp64.h"
#include "gtest/gtest.h"
#include <random>
#include <sstream>
#include <cstring>
#include <cstring>
#include <string>
#include <fstream>
#include <map>

namespace p2pool {

static void check_normalised(const fp64& a)
{
	if (!a.empty()) {
		ASSERT_GE(a.mantissa(), 1ULL << 63) << "mantissa is not normalised: " << a;
	}
}

// The exact value of "a" as an integer scaled to 2^e, for e small enough that it fits.
// Returns false when the shift would overflow, so callers can skip that case.
static bool exact_at(const fp64& a, int64_t e, u128& out)
{
	if (a.empty()) {
		out = u128(0);
		return true;
	}

	const int64_t d = a.exponent() - e;

	if ((d < 0) || (d > 60)) {
		return false;
	}

	out = u128(a.mantissa()) << static_cast<uint32_t>(d);
	return true;
}

TEST(fp64, reward_split_conformance_vectors)
{
	std::ifstream file("fp64_vectors.txt");
	ASSERT_TRUE(file.is_open());

	std::string line;
	size_t line_number = 0;
	size_t carries = 0;

	std::map<std::string, size_t> counts;

	while (std::getline(file, line)) {
		++line_number;

		if (line.empty() || (line[0] == '#')) {
			continue;
		}

		SCOPED_TRACE(testing::Message() << "fp64_vectors.txt line " << line_number << ": " << line);

		std::istringstream input(line);

		std::string op;
		ASSERT_TRUE(input >> op);
		++counts[op];

		// every vector starts with one u128 operand, written as a (lo, hi) pair
		uint64_t a_lo, a_hi;
		ASSERT_TRUE(input >> a_lo >> a_hi);

		const fp64 a(u128(a_lo, a_hi));
		check_normalised(a);

		uint64_t m;
		int64_t e;

		if (op == "ctor") {
			ASSERT_TRUE(input >> m >> e);
			ASSERT_EQ(a.mantissa(), m);
			ASSERT_EQ(a.exponent(), e);

			// the uint64_t constructor must agree with the u128 one on values that fit
			if (a_hi == 0) {
				ASSERT_EQ(fp64(a_lo).mantissa(), m);
				ASSERT_EQ(fp64(a_lo).exponent(), e);
			}
			continue;
		}

		if (op == "at") {
			uint64_t expected;
			ASSERT_TRUE(input >> e >> expected);
			ASSERT_EQ(a.at(e), expected);
			continue;
		}

		if (op == "mulu64") {
			uint64_t b;
			ASSERT_TRUE(input >> b >> m >> e);

			const fp64 r = a * b;
			ASSERT_EQ(r.mantissa(), m);
			ASSERT_EQ(r.exponent(), e);
			ASSERT_EQ(r, a * fp64(b)) << "multiplying by an integer must equal multiplying by fp64(integer)";
			continue;
		}

		// the rest take a second u128 operand
		uint64_t b_lo, b_hi;
		ASSERT_TRUE(input >> b_lo >> b_hi);

		const fp64 b(u128(b_lo, b_hi));

		if (op == "mul") {
			ASSERT_TRUE(input >> m >> e);

			const fp64 r = a * b;
			ASSERT_EQ(r.mantissa(), m);
			ASSERT_EQ(r.exponent(), e);
			check_normalised(r);

			fp64 c = a;
			c *= b;
			ASSERT_EQ(c, r) << "the compound form must be identical";
			continue;
		}

		if (op == "sub") {
			ASSERT_TRUE(input >> m >> e);
			ASSERT_TRUE(a > b) << "the generator only emits a > b";

			const fp64 r = a - b;
			ASSERT_EQ(r.mantissa(), m);
			ASSERT_EQ(r.exponent(), e);
			check_normalised(r);

			fp64 c = a;
			c -= b;
			ASSERT_EQ(c, r) << "the compound form must be identical";
			continue;
		}

		if (op == "wide") {
			uint64_t c_lo, c_hi, d_lo, d_hi;
			int carry;
			ASSERT_TRUE(input >> c_lo >> c_hi >> d_lo >> d_hi >> m >> e >> carry);

			const fp64 c(u128(c_lo, c_hi)), d(u128(d_lo, d_hi));
			const fp64::wide num = a.mul_wide(b) + c.mul_wide(d);

			ASSERT_EQ(num.c ? 1 : 0, carry) << "the 129th bit of the sum";
			carries += num.c ? 1 : 0;

			const fp64 r(num);
			ASSERT_EQ(r.mantissa(), m);
			ASSERT_EQ(r.exponent(), e);
			check_normalised(r);
			continue;
		}

		FAIL() << "unknown operation \"" << op << '"';
	}

	for (const char* op : { "ctor", "mul", "mulu64", "sub", "at", "wide" }) {
		ASSERT_GE(counts[op], 50U) << "too few \"" << op << "\" vectors";
	}

	ASSERT_GT(carries, 20U) << "vectors do not cover the 129-bit sum";
}

TEST(fp64, wide_product_is_exact)
{
	std::mt19937_64 rng(20260914);

	for (int i = 0; i < 20000; ++i) {
		const fp64 a(rng() | 1), b(rng() | 1);

		const fp64::wide w = a.mul_wide(b);
		ASSERT_FALSE(w.c);
		ASSERT_EQ(w.e, a.exponent() + b.exponent());
		ASSERT_EQ(w.m, u128(a.mantissa()) * b.mantissa());

		ASSERT_EQ(fp64(w), a * b);
	}
}

TEST(fp64, zero)
{
	const fp64 zero;
	const fp64 one(1ULL);

	ASSERT_TRUE(zero.empty());
	ASSERT_EQ(zero.mantissa(), 0U);
	ASSERT_EQ(zero.exponent(), 0);
	ASSERT_EQ(zero.to_double(), 0.0);

	ASSERT_TRUE(fp64(0ULL).empty());
	ASSERT_TRUE(fp64(u128(0)).empty());
	ASSERT_TRUE(fp64(0ULL, 1000).empty()) << "the exponent must not resurrect a zero";

	ASSERT_TRUE((zero * one).empty());
	ASSERT_TRUE((one * zero).empty());
	ASSERT_TRUE((zero * 12345ULL).empty());
	ASSERT_TRUE((one * 0ULL).empty());
	ASSERT_EQ(zero + one, one);
	ASSERT_EQ(one + zero, one);
	ASSERT_EQ(one - zero, one);
	ASSERT_TRUE((zero - one).empty());
	ASSERT_TRUE((zero + zero).empty());

	ASSERT_TRUE((zero / one).empty());
	ASSERT_TRUE((one / zero).empty());
	ASSERT_TRUE((zero / zero).empty());

	ASSERT_LT(zero, one);
	ASSERT_GT(one, zero);
	ASSERT_EQ(zero, fp64());
	ASSERT_NE(zero, one);
	ASSERT_FALSE(zero < fp64());
	ASSERT_EQ(zero.at(0), 0U);
	ASSERT_EQ(zero.at(-100), 0U) << "zero is zero at every scale, it never saturates";

	for (int64_t e : { -1000, -1, 0, 1, 1000 }) {
		ASSERT_EQ(fp64(0ULL, e), zero);
		ASSERT_EQ(fp64(u128(0), e), zero);
		ASSERT_EQ(fp64(0ULL, e).exponent(), 0);
	}

	const fp64::wide w = zero.mul_wide(one);
	ASSERT_EQ(w.m, u128(0));
	ASSERT_EQ(fp64(w), zero);
	ASSERT_EQ(fp64(w).exponent(), 0);
	ASSERT_EQ(fp64(zero.mul_wide(one) + zero.mul_wide(one)), zero);
}

TEST(fp64, normalisation)
{
	// A power of two always has mantissa 2^63 and exponent (k - 63)
	for (int k = 0; k < 64; ++k) {
		const fp64 a(1ULL << k);
		ASSERT_EQ(a.mantissa(), 1ULL << 63);
		ASSERT_EQ(a.exponent(), k - 63);
	}

	for (int k = 0; k < 128; ++k) {
		const fp64 a(u128(1) << static_cast<uint32_t>(k));
		ASSERT_EQ(a.mantissa(), 1ULL << 63);
		ASSERT_EQ(a.exponent(), k - 63);
	}

	// The explicit-exponent constructor just shifts the exponent
	std::mt19937_64 rng(1);
	for (int i = 0; i < 1000; ++i) {
		const uint64_t v = rng() | 1;
		const int64_t e = static_cast<int64_t>(rng() % 200) - 100;

		const fp64 a(v), b(v, e);
		ASSERT_EQ(b.mantissa(), a.mantissa());
		ASSERT_EQ(b.exponent(), a.exponent() + e);

		const u128 w(rng() | 1, rng());
		const fp64 c(w), d(w, e);
		ASSERT_EQ(d.mantissa(), c.mantissa());
		ASSERT_EQ(d.exponent(), c.exponent() + e);
	}
}

// Construction truncates toward zero: the mantissa is the top 64 bits and nothing is rounded up
TEST(fp64, construction_truncates_toward_zero)
{
	std::mt19937_64 rng(2);

	for (int i = 0; i < 20000; ++i) {
		const u128 v(rng(), rng() | (1ULL << 63));      // always 128 significant bits
		const fp64 a(v);

		ASSERT_EQ(a.exponent(), 64);
		ASSERT_EQ(a.mantissa(), v.hi);                  // the low 64 bits are dropped

		// value >= representation, and the gap is under one ulp
		const u128 back = u128(a.mantissa()) << 64;
		ASSERT_LE(back, v);
		ASSERT_LT(v - back, u128(1) << 64);
	}
}

TEST(fp64, comparison_is_a_total_order)
{
	std::vector<fp64> v;
	v.emplace_back(); // zero
	v.emplace_back(1ULL);
	v.emplace_back(2ULL);
	v.emplace_back(3ULL);
	v.emplace_back(std::numeric_limits<uint64_t>::max());
	v.emplace_back(u128(0, 1));
	v.emplace_back(u128(std::numeric_limits<uint64_t>::max(), std::numeric_limits<uint64_t>::max()));
	v.emplace_back(1ULL, -1000);
	v.emplace_back(1ULL, 1000);

	for (const fp64& a : v) {
		for (const fp64& b : v) {
			SCOPED_TRACE(testing::Message() << a << " vs " << b);

			// exactly one of <, ==, > holds
			const int n = (a < b ? 1 : 0) + (a == b ? 1 : 0) + (a > b ? 1 : 0);
			ASSERT_EQ(n, 1);

			ASSERT_EQ(a <= b, !(a > b));
			ASSERT_EQ(a >= b, !(a < b));
			ASSERT_EQ(a != b, !(a == b));
			ASSERT_EQ(a < b, b > a);

			// agrees with the double approximation wherever doubles can tell them apart
			if (a.to_double() != b.to_double()) {
				ASSERT_EQ(a < b, a.to_double() < b.to_double());
			}

			for (const fp64& c : v) {
				if ((a < b) && (b < c)) {
					ASSERT_LT(a, c) << "transitivity";
				}
			}
		}
	}
}

TEST(fp64, at_scales_and_saturates)
{
	const fp64 a(u128(0, 1)); // 2^64, mantissa 2^63, exponent 1

	ASSERT_EQ(a.exponent(), 1);
	ASSERT_EQ(a.at(1), 1ULL << 63);
	ASSERT_EQ(a.at(2), 1ULL << 62);
	ASSERT_EQ(a.at(64), 1U);
	ASSERT_EQ(a.at(65), 0U) << "shifted out entirely";
	ASSERT_EQ(a.at(1000), 0U);

	// below the exponent the value need not fit in 64 bits: exact while it does, then saturates
	ASSERT_EQ(a.at(0), std::numeric_limits<uint64_t>::max());

	const fp64 b(1ULL); // mantissa 2^63, exponent -63
	ASSERT_EQ(b.at(-63), 1ULL << 63);
	ASSERT_EQ(b.at(-62), 1ULL << 62);
	ASSERT_EQ(b.at(0), 1U);
	ASSERT_EQ(b.at(1), 0U);
	ASSERT_EQ(b.at(-64), std::numeric_limits<uint64_t>::max()) << "2^64 does not fit";

	// at(exponent()) always returns the mantissa itself
	std::mt19937_64 rng(3);
	for (int i = 0; i < 2000; ++i) {
		const fp64 x(u128(rng(), rng()) + u128(1));
		ASSERT_EQ(x.at(x.exponent()), x.mantissa());
	}
}

TEST(fp64, multiply_is_exact_truncation)
{
	std::mt19937_64 rng(4);

	for (int i = 0; i < 50000; ++i) {
		const fp64 a(rng() | 1), b(rng() | 1);
		const fp64 r = a * b;

		check_normalised(r);

		// the exact product of the mantissas, and the shift that renormalises it
		const u128 p = u128(a.mantissa()) * b.mantissa();
		const uint32_t n = p.bit_length();

		ASSERT_TRUE((n == 127) || (n == 128));
		ASSERT_EQ(u128(r.mantissa()), p >> (n - 64));
		ASSERT_EQ(r.exponent(), a.exponent() + b.exponent() + static_cast<int64_t>(n) - 64);
	}
}

TEST(fp64, divide_is_exact_truncation)
{
	std::mt19937_64 rng(5);

	for (int i = 0; i < 50000; ++i) {
		const fp64 a(rng() | 1), b(rng() | 1);
		const fp64 r = a / b;

		ASSERT_FALSE(r.empty());
		check_normalised(r);

		// r.mantissa() == floor(m_a * 2^s / m_b), so m_r*m_b <= m_a*2^s < (m_r+1)*m_b
		const uint32_t s = (a.mantissa() >= b.mantissa()) ? 63 : 64;
		const u128 num = u128(a.mantissa()) << s;

		const u128 lo = u128(r.mantissa()) * b.mantissa();
		const u128 hi = u128(r.mantissa() + 1) * b.mantissa();

		ASSERT_LE(lo, num);
		ASSERT_GT(hi, num);
		ASSERT_EQ(r.exponent(), a.exponent() - b.exponent() - static_cast<int64_t>(s));
	}
}

TEST(fp64, add_is_exact_truncation)
{
	std::mt19937_64 rng(6);
	int checked = 0;

	for (int i = 0; i < 50000; ++i) {
		const fp64 a(rng() | 1, static_cast<int64_t>(rng() % 40));
		const fp64 b(rng() | 1, static_cast<int64_t>(rng() % 40));
		const fp64 r = a + b;

		check_normalised(r);
		ASSERT_EQ(r, b + a) << "addition must be commutative";

		// compare at a scale low enough that both operands and the result are exact integers
		const int64_t e = std::min(a.exponent(), b.exponent());
		u128 ea, eb, er;

		if (!exact_at(a, e, ea) || !exact_at(b, e, eb) || !exact_at(r, e, er)) {
			continue;
		}

		const u128 sum = ea + eb;
		ASSERT_LE(er, sum) << "result must not exceed the exact sum";

		// and the shortfall is under one ulp at the result's own scale
		const u128 ulp = u128(1) << static_cast<uint32_t>(r.exponent() - e);
		ASSERT_LT(sum - er, ulp);
		++checked;
	}

	ASSERT_GT(checked, 40000) << "most cases must be exactly checkable";
}

TEST(fp64, subtract_is_exact_truncation)
{
	std::mt19937_64 rng(7);
	int checked = 0;

	for (int i = 0; i < 50000; ++i) {
		fp64 a(rng() | 1, static_cast<int64_t>(rng() % 40));
		fp64 b(rng() | 1, static_cast<int64_t>(rng() % 40));

		if (a < b) {
			std::swap(a, b);
		}
		if (a == b) {
			continue;
		}

		const fp64 r = a - b;
		check_normalised(r);

		const int64_t e = std::min(b.exponent(), r.exponent());
		u128 ea, eb, er;

		if (!exact_at(a, e, ea) || !exact_at(b, e, eb) || !exact_at(r, e, er)) {
			continue;
		}

		ASSERT_GE(ea, eb);
		const u128 diff = ea - eb;

		// The subtrahend is truncated, so the difference can only be too LARGE
		ASSERT_GE(er, diff);
		const u128 ulp = u128(1) << static_cast<uint32_t>(a.exponent() - e);
		ASSERT_LT(er - diff, ulp);
		++checked;
	}

	ASSERT_GT(checked, 30000) << "most cases must be exactly checkable";
}

TEST(fp64, subtract_saturates_at_zero)
{
	std::mt19937_64 rng(8);

	for (int i = 0; i < 5000; ++i) {
		const fp64 a(rng() | 1), b(rng() | 1);

		if (a > b) {
			ASSERT_FALSE((a - b).empty());
			ASSERT_TRUE((b - a).empty()) << "unsigned: must saturate, not wrap";
		}
		else if (a < b) {
			ASSERT_TRUE((a - b).empty());
		}
		else {
			ASSERT_TRUE((a - b).empty());
		}
	}

	const fp64 a(12345ULL);
	ASSERT_TRUE((a - a).empty());
}

TEST(fp64, multiply_by_power_of_two_is_exact)
{
	std::mt19937_64 rng(9);

	for (int i = 0; i < 5000; ++i) {
		const fp64 a(rng() | 1);

		for (int k = 0; k < 64; ++k) {
			const fp64 r = a * (1ULL << k);

			// scaling by a power of two moves the exponent and leaves the mantissa alone
			ASSERT_EQ(r.mantissa(), a.mantissa());
			ASSERT_EQ(r.exponent(), a.exponent() + k);
		}
	}
}

TEST(fp64, divide_by_self_and_by_one)
{
	std::mt19937_64 rng(10);

	const fp64 one(1ULL);

	for (int i = 0; i < 5000; ++i) {
		const fp64 a(rng() | 1);

		ASSERT_EQ(a / one, a);
		ASSERT_EQ(a * one, a);
		ASSERT_EQ(a / a, one) << "x/x must be exactly 1";

		// a / 2^k is exact
		for (int k = 1; k < 8; ++k) {
			const fp64 r = a / (1ULL << k);
			ASSERT_EQ(r.mantissa(), a.mantissa());
			ASSERT_EQ(r.exponent(), a.exponent() - k);
		}
	}
}

// (a*b)/b recovers a to within one ulp: two truncations cannot drift further
TEST(fp64, multiply_then_divide_round_trips)
{
	std::mt19937_64 rng(11);

	for (int i = 0; i < 20000; ++i) {
		const fp64 a(rng() | 1), b(rng() | 1);
		const fp64 r = (a * b) / b;

		ASSERT_LE(r, a);
		ASSERT_GE(r.exponent(), a.exponent() - 1);

		// Two truncations, each losing under one ulp, so the round trip lands within two.
		const fp64 lo = a - fp64(2ULL, a.exponent());
		ASSERT_GE(r, lo) << "a = " << a << ", (a*b)/b = " << r;
	}
}

TEST(fp64, mixed_operand_types_agree)
{
	std::mt19937_64 rng(12);

	for (int i = 0; i < 20000; ++i) {
		const fp64 a(rng() | 1);
		const uint64_t k = rng() | 1;
		const u128 w(rng() | 1, rng());

		// fp64 op uint64_t == fp64 op fp64(uint64_t)
		ASSERT_EQ(a + k, a + fp64(k));
		ASSERT_EQ(a * k, a * fp64(k));
		ASSERT_EQ(a / k, a / fp64(k));
		if (a > fp64(k)) {
			ASSERT_EQ(a - k, a - fp64(k));
		}

		// and the same for u128
		ASSERT_EQ(a + w, a + fp64(w));
		ASSERT_EQ(a * w, a * fp64(w));
		ASSERT_EQ(a / w, a / fp64(w));
		if (a > fp64(w)) {
			ASSERT_EQ(a - w, a - fp64(w));
		}

		// compound and binary forms must never diverge
		fp64 c = a;
		c += k;
		ASSERT_EQ(c, a + k);

		c = a;
		c *= w;
		ASSERT_EQ(c, a * w);

		c = a;
		c /= k;
		ASSERT_EQ(c, a / k);
	}
}

TEST(fp64, to_double_and_stream)
{
	ASSERT_DOUBLE_EQ(fp64(1ULL).to_double(), 1.0);
	ASSERT_DOUBLE_EQ(fp64(2ULL).to_double(), 2.0);
	ASSERT_DOUBLE_EQ(fp64(3ULL).to_double(), 3.0);
	ASSERT_DOUBLE_EQ(fp64(600000000ULL).to_double(), 600000000.0);
	ASSERT_DOUBLE_EQ((fp64(3ULL) * fp64(5ULL)).to_double(), 15.0);
	ASSERT_DOUBLE_EQ((fp64(10ULL) / fp64(4ULL)).to_double(), 2.5);
	ASSERT_DOUBLE_EQ((fp64(7ULL) + fp64(9ULL)).to_double(), 16.0);
	ASSERT_DOUBLE_EQ((fp64(9ULL) - fp64(7ULL)).to_double(), 2.0);

	std::ostringstream s;
	s << fp64() << ' ' << fp64(1ULL);
	ASSERT_EQ(s.str(), "0 1.0000000000000000000E+00");
}

TEST(u128, bit_length)
{
	ASSERT_EQ(bit_length(0ULL), 0U);
	ASSERT_EQ(u128(0).bit_length(), 0U);

	for (int k = 0; k < 64; ++k) {
		ASSERT_EQ(bit_length(1ULL << k), static_cast<uint32_t>(k) + 1);
		ASSERT_EQ(u128(1ULL << k).bit_length(), static_cast<uint32_t>(k) + 1);
	}

	for (int k = 0; k < 128; ++k) {
		const u128 v = u128(1) << static_cast<uint32_t>(k);
		ASSERT_EQ(v.bit_length(), static_cast<uint32_t>(k) + 1);
		ASSERT_EQ((v - u128(1)).bit_length(), static_cast<uint32_t>(k));
	}

	ASSERT_EQ(u128(std::numeric_limits<uint64_t>::max(), std::numeric_limits<uint64_t>::max()).bit_length(), 128U);
}

TEST(u128, top64)
{
	std::mt19937_64 rng(13);

	for (int i = 0; i < 20000; ++i) {
		const u128 v(rng(), rng());

		if (v == u128(0)) {
			continue;
		}

		const uint32_t n = v.bit_length();
		const uint64_t t = v.top64();

		ASSERT_GE(t, 1ULL << 63) << "top64 must be left-normalised";

		// top64 is the value shifted so that exactly 64 bits remain, truncating toward zero
		ASSERT_EQ(t, (n > 64) ? (v >> (n - 64)).lo : (v << (64 - n)).lo);
	}
}

TEST(u128, shifts)
{
	std::mt19937_64 rng(14);

	for (int i = 0; i < 20000; ++i) {
		const u128 v(rng(), rng());

		for (uint32_t k : { 0U, 1U, 31U, 63U, 64U, 65U, 100U, 127U, 128U, 200U }) {
			const u128 r = v >> k;
			const u128 l = v << k;

			if (k >= 128) {
				ASSERT_EQ(r, u128(0));
				ASSERT_EQ(l, u128(0));
				continue;
			}

			// shifting right then left clears exactly the low k bits
			ASSERT_EQ((r << k) >> k, r);

			// a right shift is a division by 2^k
			u128 q = v;
			for (uint32_t j = 0; j < k; ++j) {
				q /= 2U;
			}
			ASSERT_EQ(r, q);
		}

		ASSERT_EQ(v >> 0, v);
		ASSERT_EQ(v << 0, v);
	}
}

TEST(u128, mulshr)
{
	std::mt19937_64 rng(15);

	// floor(v * m / 2^k), checked against the exact 192-bit product assembled by hand
	for (int i = 0; i < 20000; ++i) {
		const u128 v(rng(), rng() >> (rng() % 64));
		const uint64_t m = rng();

		// the exact product as three limbs
		u128 l(v.lo);
		l *= m;
		u128 t(v.hi);
		t *= m;
		t += l.hi;
		const uint64_t p[3] = { l.lo, t.lo, t.hi };

		for (uint32_t k : { 64U, 65U, 96U, 127U, 128U, 160U, 191U }) {
			// the exact answer: shift the three limbs right by k
			const uint32_t limb = k >> 6, sh = k & 63;
			uint64_t expected = p[limb] >> sh;

			if (sh) {
				expected |= ((limb + 1 < 3) ? p[limb + 1] : 0) << (64 - sh);
			}

			// only meaningful where the true quotient fits in 64 bits
			const bool fits = (limb + 2 >= 3) || (p[limb + 2] == 0);

			if (fits) {
				ASSERT_EQ(v.mulshr(m, k), expected) << "v = " << v << ", m = " << m << ", k = " << k;
			}
		}
	}

	// exact small cases
	ASSERT_EQ(u128(1).mulshr(1, 64), 0U);
	ASSERT_EQ(u128(0, 1).mulshr(1, 64), 1U);                    // 2^64 * 1 / 2^64
	ASSERT_EQ(u128(0, 1).mulshr(3, 64), 3U);
	ASSERT_EQ(u128(6).mulshr(7, 64), 0U);
	ASSERT_EQ((u128(0, 1) * 5).mulshr(1, 64), 5U);
}

TEST(fp64, scientific_notation)
{
	static const struct { uint64_t v; int64_t e; const char* expected; } vectors[] = {
		{ 0, 0, "0" },                                     // zero
		{ UINT64_C(1), 0, "1.0000000000000000000E+00" },
		{ UINT64_C(2), 0, "2.0000000000000000000E+00" },
		{ UINT64_C(3), 0, "3.0000000000000000000E+00" },
		{ UINT64_C(10), 0, "1.0000000000000000000E+01" },
		{ UINT64_C(100), 0, "1.0000000000000000000E+02" },
		{ UINT64_C(10), -1, "5.0000000000000000000E+00" },
		{ UINT64_C(1), -1, "5.0000000000000000000E-01" },  // a half
		{ UINT64_C(3), -2, "7.5000000000000000000E-01" },  // exact in binary
		{ UINT64_C(1), -4, "6.2500000000000000000E-02" },
		{ UINT64_C(1), -63, "1.0842021724855044340E-19" },
		{ UINT64_C(1), 63, "9.2233720368547758080E+18" },
		{ UINT64_C(1), 64, "1.8446744073709551616E+19" },

		// 2^62 is exactly representable in 19 digits
		{ UINT64_C(4611686018427387904), 0, "4.6116860184273879040E+18" },

		// a 64-bit mantissa needs 20 significant digits, and here it uses all of them
		{ UINT64_C(18446744073709551615), 0, "1.8446744073709551615E+19" },

		{ UINT64_C(600000000), 0, "6.0000000000000000000E+08" },
		{ UINT64_C(18446744073709551615), 64, "3.4028236692093846344E+38" },

		// rounding carries out of the leading digit and into a new decade: the value is
		// 9.99999999999999999995... and the 20-digit rounding is 10^20
		{ UINT64_C(11467493079950357558), -349, "1.0000000000000000000E-86" },
		{ UINT64_C(14615016373309029182), -160, "1.0000000000000000000E-29" },
		{ UINT64_C(13292279957849158729), -120, "1.0000000000000000000E-17" },

		{ UINT64_C(1), 1000000, "9.9006562292958982507E+301029" },
		{ UINT64_C(1), -1000000, "1.0100340591980302247E-301030" },
		{ UINT64_C(18446744073709551615), 1000000, "1.8263487162359966664E+301049" },
	};

	for (const auto& t : vectors) {
		SCOPED_TRACE(testing::Message() << "v = " << t.v << ", e = " << t.e);

		const fp64 a(t.v, t.e);

		// straight from the type
		char buf[fp64::SCIENTIFIC_BUF_SIZE];
		const size_t n = a.to_scientific(buf);

		ASSERT_STREQ(buf, t.expected);
		ASSERT_EQ(n, strlen(t.expected));
		ASSERT_LT(n, sizeof(buf));

		// and through log.h, which is what actually gets used
		char out[fp64::SCIENTIFIC_BUF_SIZE + 8] = {};
		log::Stream s(out);
		s << a << '\0';

		ASSERT_STREQ(out, t.expected);
	}
}

// The exponent is signed and always carries at least two digits, like printf's %e
TEST(fp64, scientific_notation_format)
{
	char buf[fp64::SCIENTIFIC_BUF_SIZE];

	fp64(1ULL).to_scientific(buf);
	const std::string one(buf);

	ASSERT_EQ(one.size(), 25U);
	ASSERT_EQ(one[1], '.');
	ASSERT_EQ(one[21], 'E');
	ASSERT_EQ(one[22], '+');
	ASSERT_EQ(one.find_first_not_of("0123456789", 2), 21U) << "19 digits after the point";

	fp64(1ULL, -1).to_scientific(buf);
	ASSERT_EQ(std::string(buf)[22], '-');

	// every value fits the buffer, including the widest exponent the type can reach
	for (int64_t e : { std::numeric_limits<int64_t>::min() / 2, INT64_C(-1000000000000),
	                   INT64_C(0), INT64_C(1000000000000), std::numeric_limits<int64_t>::max() / 2 }) {
		const fp64 a(std::numeric_limits<uint64_t>::max(), e);
		const size_t n = a.to_scientific(buf);

		ASSERT_GT(n, 0U);
		ASSERT_LT(n, sizeof(buf));
		ASSERT_EQ(n, strlen(buf));
		ASSERT_EQ(buf[1], '.');
	}
}

TEST(fp64, exponent_extremes_are_total)
{
	constexpr int64_t MAX = std::numeric_limits<int64_t>::max();
	constexpr int64_t MIN = std::numeric_limits<int64_t>::min();

	// saturating exponent arithmetic, exact where it does not saturate
	ASSERT_EQ(add_sat(INT64_C(1), INT64_C(2)), 3);
	ASSERT_EQ(add_sat(MAX, INT64_C(1)), MAX);
	ASSERT_EQ(add_sat(MAX, MAX), MAX);
	ASSERT_EQ(add_sat(MIN, INT64_C(-1)), MIN);
	ASSERT_EQ(add_sat(MIN, MIN), MIN);
	ASSERT_EQ(add_sat(MAX, MIN), -1);
	ASSERT_EQ(add_sat(MIN, MAX), -1);

	ASSERT_EQ(sub_sat(INT64_C(3), INT64_C(2)), 1);
	ASSERT_EQ(sub_sat(MIN, INT64_C(1)), MIN);
	ASSERT_EQ(sub_sat(MAX, INT64_C(-1)), MAX);
	ASSERT_EQ(sub_sat(MAX, MIN), MAX);
	ASSERT_EQ(sub_sat(MIN, MAX), MIN);
	ASSERT_EQ(sub_sat(INT64_C(0), MIN), MAX);

	const fp64 hi(3ULL, MAX);
	const fp64 lo(3ULL, MIN);
	const fp64 one(1ULL);

	// every operator must be total at the extremes rather than overflowing the exponent
	for (const fp64& a : { hi, lo, one, fp64() }) {
		for (const fp64& b : { hi, lo, one, fp64() }) {
			const fp64 s = a + b, d = a - b, m = a * b, q = a / b;

			check_normalised(s);
			check_normalised(d);
			check_normalised(m);
			check_normalised(q);

			// the exponent never leaves the representable range
			for (const fp64& r : { s, d, m, q }) {
				ASSERT_GE(r.exponent(), MIN);
				ASSERT_LE(r.exponent(), MAX);
			}

			ASSERT_EQ(a + b, b + a);
		}
	}

	// at() must not overflow its difference, nor negate INT64_MIN
	// hi is 3 * 2^MAX and lo is 3 * 2^MIN, both held as mantissa 3 * 2^62
	ASSERT_EQ(lo.at(MAX), 0U) << "shifted out entirely";
	ASSERT_EQ(hi.at(MIN), std::numeric_limits<uint64_t>::max()) << "does not fit, saturates";
	ASSERT_EQ(hi.at(MAX), 3U) << "the value really is three at that scale";
	ASSERT_EQ(lo.at(MIN), UINT64_C(3) << 62);

	// to_double narrows the exponent to int, which must be clamped
	ASSERT_GT(hi.to_double(), 1e300);
	ASSERT_EQ(lo.to_double(), 0.0);

	// and the decimal conversion must stay inside its buffer
	char buf[fp64::SCIENTIFIC_BUF_SIZE];

	for (const fp64& a : { hi, lo, one, fp64() }) {
		const size_t n = a.to_scientific(buf);
		ASSERT_GT(n, 0U);
		ASSERT_LT(n, sizeof(buf));
		ASSERT_EQ(n, strlen(buf));
	}
}

TEST(u128, edge_cases_are_total)
{
	ASSERT_EQ(u128(0).top64(), 0U);
	ASSERT_EQ(u128(0).bit_length(), 0U);
	ASSERT_TRUE(fp64(u128(0)).empty());

	const u128 v(0xdeadbeefcafef00dULL, 0x0123456789abcdefULL);

	for (uint32_t k : { 191U, 192U, 193U, 255U, 256U, 1000U, 0xffffffffU }) {
		const uint64_t r = v.mulshr(0xffffffffffffffffULL, k);

		if (k >= 192) {
			ASSERT_EQ(r, 0U) << "the product is below 2^192";
		}
	}

	// shifts at and beyond the width
	for (uint32_t k : { 0U, 63U, 64U, 127U, 128U, 129U, 1000U, 0xffffffffU }) {
		const u128 a = v >> k;
		const u128 b = v << k;

		if (k >= 128) {
			ASSERT_EQ(a, u128(0));
			ASSERT_EQ(b, u128(0));
		}
	}
}

TEST(fp64, to_double_bit_pattern)
{
	auto bits = [](double d) { uint64_t b; memcpy(&b, &d, sizeof(b)); return b; };

	ASSERT_EQ(bits(fp64().to_double()), UINT64_C(0));
	ASSERT_EQ(bits(fp64(1ULL).to_double()), UINT64_C(0x3FF0000000000000));
	ASSERT_EQ(bits(fp64(2ULL).to_double()), UINT64_C(0x4000000000000000));
	ASSERT_EQ(bits(fp64(3ULL).to_double()), UINT64_C(0x4008000000000000));
	ASSERT_EQ(bits(fp64(1ULL, -1).to_double()), UINT64_C(0x3FE0000000000000)); // 0.5

	// the fraction is the 52 bits below the leading one, truncated
	{
		const fp64 a(std::numeric_limits<uint64_t>::max());
		ASSERT_EQ(bits(a.to_double()) & ((UINT64_C(1) << 52) - 1), (UINT64_C(1) << 52) - 1);
		ASSERT_LT(a.to_double(), 18446744073709551616.0) << "truncation keeps it below 2^64";
	}

	// saturation at both ends, without relying on the infinity() constant
	ASSERT_EQ(bits(fp64(3ULL, std::numeric_limits<int64_t>::max()).to_double()), UINT64_C(0x7FEFFFFFFFFFFFFF));
	ASSERT_EQ(bits(fp64(3ULL, std::numeric_limits<int64_t>::min()).to_double()), UINT64_C(0));
	ASSERT_EQ(bits(fp64(1ULL, 1024).to_double()), UINT64_C(0x7FEFFFFFFFFFFFFF)) << "saturates finite";
	ASSERT_EQ(bits(fp64(1ULL, -1023).to_double()), UINT64_C(0)) << "below the smallest normal";

	// against the field-by-field decomposition, over the whole normal range
	std::mt19937_64 rng(77);

	for (int i = 0; i < 200000; ++i) {
		const uint64_t m = rng() | (1ULL << 63);
		const int64_t e = static_cast<int64_t>(rng() % 2000) - 1000;
		const fp64 a(m, e);

		const uint64_t b = bits(a.to_double());
		const int64_t biased = a.exponent() + 63 + 1023;

		if ((biased > 0) && (biased < 2047)) {
			ASSERT_EQ(b >> 63, UINT64_C(0)) << "fp64 is unsigned";
			ASSERT_EQ((b >> 52) & 0x7FF, static_cast<uint64_t>(biased));
			ASSERT_EQ(b & ((UINT64_C(1) << 52) - 1), (a.mantissa() >> 11) & ((UINT64_C(1) << 52) - 1));
		}
	}
}

} // namespace p2pool
