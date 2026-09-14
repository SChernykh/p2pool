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

#pragma once

namespace p2pool {

// fp64 holds a non-negative value as m * 2^e with the mantissa always normalised so that
// bit 63 is set: 2^63 <= m < 2^64. Zero is the one exception and is held as m == 0, e == 0.
// Every operation truncates toward zero and renormalises exactly once.

// Saturating signed addition and subtraction for the exponent.
[[nodiscard]] FORCEINLINE int64_t add_sat(int64_t a, int64_t b)
{
#if defined(__GNUC__) || defined(__clang__)
	int64_t r;
	const bool overflow = __builtin_add_overflow(a, b, &r);

	return overflow ? ((b < 0) ? std::numeric_limits<int64_t>::min() : std::numeric_limits<int64_t>::max()) : r;
#else
	if (b >= 0) {
		return (a > std::numeric_limits<int64_t>::max() - b) ? std::numeric_limits<int64_t>::max() : (a + b);
	}
	return (a < std::numeric_limits<int64_t>::min() - b) ? std::numeric_limits<int64_t>::min() : (a + b);
#endif
}

[[nodiscard]] FORCEINLINE int64_t sub_sat(int64_t a, int64_t b)
{
#if defined(__GNUC__) || defined(__clang__)
	int64_t r;
	const bool overflow = __builtin_sub_overflow(a, b, &r);

	return overflow ? ((b < 0) ? std::numeric_limits<int64_t>::max() : std::numeric_limits<int64_t>::min()) : r;
#else
	if (b >= 0) {
		return (a < std::numeric_limits<int64_t>::min() + b) ? std::numeric_limits<int64_t>::min() : (a - b);
	}
	return (a > std::numeric_limits<int64_t>::max() + b) ? std::numeric_limits<int64_t>::max() : (a - b);
#endif
}

class alignas(16) fp64
{
public:
	FORCEINLINE constexpr fp64() noexcept : m_m(0), m_e(0) {}

	explicit FORCEINLINE fp64(uint64_t v) noexcept { set(v); }
	explicit FORCEINLINE fp64(const u128& v) noexcept { set(v); }

	FORCEINLINE fp64(uint64_t v, int64_t e) noexcept { set(v); shift_exponent(e); }
	FORCEINLINE fp64(const u128& v, int64_t e) noexcept { set(v); shift_exponent(e); }

	// The exact 128-bit product of two mantissas, unnormalized
	struct wide
	{
		FORCEINLINE wide(const u128& _m, int64_t _e, bool _c) : m(_m), e(_e), c(_c) {}

		u128 m;    // mantissa, unnormalized
		int64_t e; // exponent
		bool c;    // carry flag for values up to 2^129
	};

	explicit FORCEINLINE fp64(const wide& w) noexcept
	{
		if (w.c) {
			// 2^128 + w.m
			m_m = (1ULL << 63) | (w.m >> 65).lo;
			m_e = add_sat(w.e, 65);
		}
		else {
			set(w.m);
			shift_exponent(w.e);
		}
	}

	[[nodiscard]] FORCEINLINE wide mul_wide(const fp64& b) const
	{
		return { u128(m_m) * b.m_m, add_sat(m_e, b.m_e), false };
	}

	FORCEINLINE fp64& operator*=(const fp64& b)
	{
		if (empty() || b.empty()) {
			return set_zero();
		}

		const u128 p = u128(m_m) * b.m_m;
		const bool full = ((p.hi >> 63) != 0);

		m_m = full ? p.hi : ((p.hi << 1) | (p.lo >> 63));
		m_e = add_sat(add_sat(m_e, b.m_e), full ? 64 : 63);

		return *this;
	}

	FORCEINLINE fp64& operator*=(uint64_t b)    { return operator*=(fp64(b)); }
	FORCEINLINE fp64& operator*=(const u128& b) { return operator*=(fp64(b)); }

	FORCEINLINE fp64& operator+=(const fp64& b)
	{
		if (b.empty()) {
			return *this;
		}

		if (empty()) {
			return *this = b;
		}

		const bool swap = (m_e < b.m_e);

		const uint64_t m_hi = swap ? b.m_m : m_m;
		const uint64_t m_lo = swap ? m_m : b.m_m;
		const int64_t e_hi = swap ? b.m_e : m_e;
		const int64_t d = sub_sat(e_hi, swap ? m_e : b.m_e);

		u128 s(m_hi);

		if (d < 64) {
			s += m_lo >> static_cast<uint32_t>(d);
		}

		const bool carried = (s.hi != 0);

		m_m = carried ? ((s.hi << 63) | (s.lo >> 1)) : s.lo;
		m_e = add_sat(e_hi, carried ? 1 : 0);

		return *this;
	}

	FORCEINLINE fp64& operator+=(uint64_t b)    { return operator+=(fp64(b)); }
	FORCEINLINE fp64& operator+=(const u128& b) { return operator+=(fp64(b)); }

	FORCEINLINE fp64& operator-=(const fp64& b)
	{
		if (b.empty()) {
			return *this;
		}

		if (!operator>(b)) {
			return set_zero();
		}

		const int64_t e = m_e;
		const int64_t d = sub_sat(e, b.m_e);
		const uint64_t sub = (d < 64) ? (b.m_m >> static_cast<uint32_t>(d)) : 0;

		set(m_m - sub);
		m_e = add_sat(m_e, e);

		return *this;
	}

	FORCEINLINE fp64& operator-=(uint64_t b)    { return operator-=(fp64(b)); }
	FORCEINLINE fp64& operator-=(const u128& b) { return operator-=(fp64(b)); }

	fp64& operator/=(const fp64& b);

	FORCEINLINE fp64& operator/=(uint64_t b)    { return operator/=(fp64(b)); }
	FORCEINLINE fp64& operator/=(const u128& b) { return operator/=(fp64(b)); }

	[[nodiscard]] FORCEINLINE bool operator<(const fp64& b) const
	{
		if (empty() || b.empty()) {
			return empty() && !b.empty();
		}

		return (m_e != b.m_e) ? (m_e < b.m_e) : (m_m < b.m_m);
	}

	[[nodiscard]] FORCEINLINE bool operator> (const fp64& b) const { return b.operator<(*this); }
	[[nodiscard]] FORCEINLINE bool operator<=(const fp64& b) const { return !operator>(b); }
	[[nodiscard]] FORCEINLINE bool operator>=(const fp64& b) const { return !operator<(b); }
	[[nodiscard]] FORCEINLINE bool operator==(const fp64& b) const { return (m_m == b.m_m) && (m_e == b.m_e); }
	[[nodiscard]] FORCEINLINE bool operator!=(const fp64& b) const { return !operator==(b); }

	// The value as an exact integer scaled to 2^e, truncated toward zero.
	[[nodiscard]] FORCEINLINE uint64_t at(int64_t e) const
	{
		if (empty()) {
			return 0;
		}

		const int64_t d = sub_sat(e, m_e);

		if (d >= 0) {
			return (d < 64) ? (m_m >> static_cast<uint32_t>(d)) : 0;
		}

		if (d <= -64) {
			return std::numeric_limits<uint64_t>::max();
		}

		const uint32_t k = static_cast<uint32_t>(-d);

		return ((m_m >> (64 - k)) == 0) ? (m_m << k) : std::numeric_limits<uint64_t>::max();
	}

	[[nodiscard]] FORCEINLINE int64_t exponent() const { return m_e; }
	[[nodiscard]] FORCEINLINE uint64_t mantissa() const { return m_m; }
	[[nodiscard]] FORCEINLINE bool empty() const { return m_m == 0; }

	[[nodiscard]] double to_double() const;

	static constexpr size_t SCIENTIFIC_DIGITS = 20;
	static constexpr size_t SCIENTIFIC_BUF_SIZE = 48;

	NOINLINE size_t to_scientific(char (&buf)[SCIENTIFIC_BUF_SIZE]) const;

	friend std::ostream& operator<<(std::ostream& s, const fp64& v);

private:
	FORCEINLINE fp64& set_zero() { m_m = 0; m_e = 0; return *this; }

	FORCEINLINE void shift_exponent(int64_t e)
	{
		if (!empty()) {
			m_e = add_sat(m_e, e);
		}
	}

	FORCEINLINE void set(const u128& v)
	{
		const uint32_t n = v.bit_length();

		if (n == 0) {
			set_zero();
			return;
		}

		m_m = v.top64();
		m_e = static_cast<int64_t>(n) - 64;
	}

	FORCEINLINE void set(uint64_t v)
	{
		const uint32_t n = bit_length(v);

		if (n == 0) {
			set_zero();
			return;
		}

		m_m = v << (64 - n);
		m_e = static_cast<int64_t>(n) - 64;
	}

	uint64_t m_m; // mantissa: 0, or bit 63 set
	int64_t m_e;  // exponent
};

static_assert(sizeof(fp64) == sizeof(uint64_t) * 2, "struct fp64 has invalid size, check your compiler options");
static_assert(std::is_standard_layout<fp64>::value, "struct fp64 is not a POD, check your compiler options");
static_assert(std::is_trivially_copyable<fp64>::value, "struct fp64 is not trivially copyable, fix it");
static_assert(alignof(fp64) == alignof(u128), "struct fp64 must have the same alignment as u128");

template<typename T> FORCEINLINE fp64 operator+(const fp64& a, const T& b) { fp64 result = a; result += b; return result; }
template<typename T> FORCEINLINE fp64 operator-(const fp64& a, const T& b) { fp64 result = a; result -= b; return result; }
template<typename T> FORCEINLINE fp64 operator*(const fp64& a, const T& b) { fp64 result = a; result *= b; return result; }
template<typename T> FORCEINLINE fp64 operator/(const fp64& a, const T& b) { fp64 result = a; result /= b; return result; }

// x + y on two wide products, aligned to the larger exponent. The result is up to 129 bits
// The carry out of the 128-bit add is kept in "c"
[[nodiscard]] FORCEINLINE fp64::wide operator+(const fp64::wide& x, const fp64::wide& y)
{
	const bool swap = (x.e < y.e);

	const fp64::wide& hi = swap ? y : x;
	const fp64::wide& lo = swap ? x : y;
	const int64_t d = hi.e - lo.e;

	u128 v = hi.m;

	const bool c = (d < 128) && v.add_carry(lo.m >> static_cast<uint32_t>(d));

	return { v, hi.e, c };
}

} // namespace p2pool
