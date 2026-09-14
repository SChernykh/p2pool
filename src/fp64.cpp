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

#include <ostream>
#include <cstring>

namespace p2pool {

fp64& fp64::operator/=(const fp64& b)
{
	if (empty() || b.empty()) {
		return set_zero();
	}

	const bool shift = (m_m >= b.m_m);
	const u128 num = shift ? u128(m_m << 63, m_m >> 1) : u128(0, m_m);

	const u128 q = num / u128(b.m_m);

	m_m = q.lo;
	m_e = sub_sat(m_e, add_sat(b.m_e, shift ? 63 : 64));

	return *this;
}

namespace {

struct big
{
	uint64_t w[4];
	int64_t e;
};

// 10 and 1/10
static constexpr big BIG_TEN = { { 0, 0, 0, 0xa000000000000000ULL }, -252 };
static constexpr big BIG_TENTH = { { 0xccccccccccccccccULL, 0xccccccccccccccccULL, 0xccccccccccccccccULL, 0xccccccccccccccccULL }, -259 };

// log10(2) in 0.64 fixed point, for estimating the decimal exponent
static constexpr uint64_t LOG10_2_Q64 = 0x4d104d427de7fbccULL;

// Schoolbook 256x256 -> 512. r[0] is the least significant word.
static FORCEINLINE void mul256(const uint64_t (&a)[4], const uint64_t (&b)[4], uint64_t (&r)[8])
{
	for (uint32_t i = 0; i < 8; ++i) {
		r[i] = 0;
	}

	for (uint32_t i = 0; i < 4; ++i) {
		uint64_t carry = 0;

		for (uint32_t j = 0; j < 4; ++j) {
			uint64_t hi;
			const uint64_t lo = umul128(a[i], b[j], &hi);

			uint64_t t = r[i + j] + lo;
			hi += (t < lo) ? 1 : 0;

			t += carry;
			hi += (t < carry) ? 1 : 0;

			r[i + j] = t;
			carry = hi;
		}

		r[i + 4] = carry;
	}
}

// a * b, keeping the top 256 bits and renormalising
static FORCEINLINE big mul(const big& a, const big& b)
{
	uint64_t p[8];
	mul256(a.w, b.w, p);

	// both operands have bit 255 set, so the product has 511 or 512 significant bits
	const uint32_t shift = (p[7] >> 63) ? 0 : 1;

	big r;
	r.e = add_sat(add_sat(a.e, b.e), 256 - static_cast<int64_t>(shift));

	for (uint32_t i = 0; i < 4; ++i) {
		r.w[i] = shift ? ((p[i + 4] << 1) | (p[i + 3] >> 63)) : p[i + 4];
	}

	return r;
}

// w >>= n, for n < 64
static FORCEINLINE void shr(uint64_t (&w)[4], uint32_t n)
{
	if (n == 0) {
		return;
	}

	for (uint32_t i = 0; i < 3; ++i) {
		w[i] = (w[i] >> n) | (w[i + 1] << (64 - n));
	}

	w[3] >>= n;
}

// w *= 10. The caller keeps the value under 1.6 so the four integer bits never overflow.
static FORCEINLINE void mul10(uint64_t (&w)[4])
{
	uint64_t carry = 0;

	for (uint32_t i = 0; i < 4; ++i) {
		uint64_t hi;
		const uint64_t lo = umul128(w[i], 10, &hi);

		w[i] = lo + carry;
		carry = hi + ((w[i] < carry) ? 1 : 0);
	}
}

// w /= 10
static FORCEINLINE void div10(uint64_t (&w)[4])
{
	uint64_t rem = 0;

	for (int32_t i = 3; i >= 0; --i) {
		uint64_t r;
		w[i] = udiv128(rem, w[i], 10, &r);
		rem = r;
	}
}

// base^n by squaring: ~2*bit_length(n) multiplies, so any exponent is affordable
static big pow10(const big& base, uint64_t n)
{
	big result = { { 0, 0, 0, 1ULL << 63 }, -255 }; // exactly 1
	big b = base;

	for (; n; n >>= 1) {
		if (n & 1) {
			result = mul(result, b);
		}
		if (n >> 1) {
			b = mul(b, b);
		}
	}

	return result;
}

} // namespace

size_t fp64::to_scientific(char (&buf)[SCIENTIFIC_BUF_SIZE]) const
{
	if (empty()) {
		memcpy(buf, "0", 2);
		return 1;
	}

	// m * 2^e as a normalised 256-bit value
	big v = { { 0, 0, 0, m_m }, sub_sat(m_e, 192) };

	// Estimate K = floor(log10(value)).
	const bool neg = (m_e < 0);
	const uint64_t abs_e = neg ? (0U - static_cast<uint64_t>(m_e)) : static_cast<uint64_t>(m_e);
	const int64_t scaled = static_cast<int64_t>((u128(abs_e) * LOG10_2_Q64).hi);

	int64_t k = (neg ? -scaled : scaled) + 19;

	// Scale by 10^-k, which brings the value to about [1, 10).
	{
		constexpr uint64_t CHUNK = uint64_t(1) << 60;

		const big& base = (k < 0) ? BIG_TEN : BIG_TENTH;
		uint64_t n = (k < 0) ? (0U - static_cast<uint64_t>(k)) : static_cast<uint64_t>(k);

		while (n) {
			const uint64_t c = (n < CHUNK) ? n : CHUNK;
			v = mul(v, pow10(base, c));
			n -= c;
		}
	}

	// Re-lay the value as fixed point with 12 integer bits and 244 fractional bits, so the
	// leading decimal digit is the top of w[3].
	for (uint32_t guard = 0; (v.e > -244) && (guard < 64); ++guard) {
		v = mul(v, BIG_TENTH);
		k = add_sat(k, 1);
	}

	for (int64_t shift = -(v.e + 244); shift > 0; ) {
		const uint32_t n = static_cast<uint32_t>(std::min<int64_t>(shift, 63));
		shr(v.w, n);
		shift -= n;
	}

	// The leading digit must end up in 1..9. Both directions are reachable when the estimate
	// was out; from here on the value is fixed point, so the words can be scaled directly.
	for (uint32_t guard = 0; guard < 16; ++guard) {
		const uint64_t lead = v.w[3] >> 52;

		if (lead == 0) {
			mul10(v.w);
			k = sub_sat(k, 1);
		}
		else if (lead > 9) {
			div10(v.w);
			k = add_sat(k, 1);
		}
		else {
			break;
		}
	}

	// Peel the digits off the top, one per multiply by 10
	uint8_t digits[SCIENTIFIC_DIGITS + 1];

	for (size_t i = 0; i <= SCIENTIFIC_DIGITS; ++i) {
		digits[i] = static_cast<uint8_t>(v.w[3] >> 52);
		v.w[3] &= (1ULL << 52) - 1;
		mul10(v.w);
	}

	if (digits[SCIENTIFIC_DIGITS] >= 5) {
		size_t i = SCIENTIFIC_DIGITS;

		while (i > 0) {
			--i;
			if (++digits[i] < 10) {
				break;
			}
			digits[i] = 0;
		}

		// carried out of the leading digit: the value is now exactly 10, so renormalise
		if ((digits[0] == 0) && (i == 0)) {
			digits[0] = 1;
			++k;
		}
	}

	// "d.ddddddddddddddddddd" then "E+dd"
	char* p = buf;

	*p++ = static_cast<char>('0' + digits[0]);
	*p++ = '.';

	for (size_t i = 1; i < SCIENTIFIC_DIGITS; ++i) {
		*p++ = static_cast<char>('0' + digits[i]);
	}

	*p++ = 'E';
	*p++ = (k < 0) ? '-' : '+';

	uint64_t a = (k < 0) ? (0U - static_cast<uint64_t>(k)) : static_cast<uint64_t>(k);
	char tmp[24];
	size_t n = 0;

	do {
		tmp[n++] = static_cast<char>('0' + (a % 10));
		a /= 10;
	} while (a);

	if (n < 2) {
		*p++ = '0';
	}

	while (n) {
		*p++ = tmp[--n];
	}

	*p = '\0';
	return static_cast<size_t>(p - buf);
}

double fp64::to_double() const
{
	uint64_t bits = 0;

	if (!empty()) {
		const int64_t biased = add_sat(m_e, 63 + 1023);

		if (biased >= 2047) {
			bits = 0x7FEFFFFFFFFFFFFFULL; // DBL_MAX
		}
		else if (biased > 0) {
			bits = (static_cast<uint64_t>(biased) << 52) | ((m_m >> 11) & ((1ULL << 52) - 1));
		}
		// biased <= 0 is below the smallest normal double, and flushes to zero
	}

	double result;
	memcpy(&result, &bits, sizeof(result));

	return result;
}

std::ostream& operator<<(std::ostream& s, const fp64& v)
{
	if (v.empty()) {
		s << '0';
	}
	else {
		char buf[fp64::SCIENTIFIC_BUF_SIZE];
		v.to_scientific(buf);

		s << buf;
	}
	return s;
}

} // namespace p2pool
