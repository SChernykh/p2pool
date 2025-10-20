/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2025 SChernykh <https://github.com/SChernykh>
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

namespace ConstexprKeccak
{

template<int ROUNDS>
static FORCEINLINE constexpr void keccakf(std::array<uint64_t, 25>& st)
{
	constexpr uint64_t round_constants[24] = 
	{
		0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
		0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
		0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
		0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
		0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
		0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 
		0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
		0x8000000000008080, 0x0000000080000001, 0x8000000080008008
	};
	constexpr int order[25] = { 1, 6, 9, 22, 14, 20, 2, 12, 13, 19, 23, 15, 4, 24, 21, 8, 16, 5, 3, 18, 17, 11, 7, 10, 1 };
	constexpr int shift[24] = { 44, 20, 61, 39, 18, 62, 43, 25, 8, 56, 41, 27, 14, 2, 55, 45, 36, 28, 21, 15, 10, 6, 3, 1 };

	for (int round = 0; round < ROUNDS; ++round) {
		uint64_t bc[5] = {};

		// Theta
		for (int i = 0; i < 5; ++i) bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];

		for (int i = 0; i < 5; ++i) {
			const uint64_t t = bc[(i + 4) % 5] ^ ((bc[(i + 1) % 5] << 1) | (bc[(i + 1) % 5] >> 63));
			for (int j = 0; j < 25; j += 5) st[i + j] ^= t;
		}

		// Rho Pi
		const auto st0 = st;
		for (int i = 0; i < 24; ++i) st[order[i]] = (st0[order[i + 1]] << shift[i]) | (st0[order[i + 1]] >> (64 - shift[i]));

		//  Chi
		for (int i = 0; i < 25; i += 5) {
			const uint64_t t[5] = { st[i], st[i + 1], st[i + 2], st[i + 3], st[i + 4] };
			for (int j = 0; j < 5; ++j) st[i + j] ^= ~t[(j + 1) % 5] & t[(j + 2) % 5];
		}

		// Iota
		st[0] ^= round_constants[round];
	}
}

} // namespace ConstexprKeccak

template<int len>
static constexpr hash keccak(const char (&input)[len])
{
	constexpr int rsiz = 136;
	constexpr int inlen = len - 1;
	static_assert(inlen < rsiz, "Too long input");

	uint8_t temp[rsiz] = {};

	for (int i = 0; i < inlen; ++i) {
		temp[i] = static_cast<uint8_t>(input[i]);
	}

	temp[inlen] = 1;
	temp[rsiz - 1] |= 0x80;

	std::array<uint64_t, 25> st = {};

	for (int i = 0; i < rsiz / 8; i++) {
		uint64_t k = 0;
		for (int j = 0; j < 8; ++j) {
			k |= static_cast<uint64_t>(temp[i * 8 + j]) << (j * 8);
		}
		st[i] ^= k;
	}

	ConstexprKeccak::keccakf<24>(st);

	hash result{};

	for (size_t i = 0; i < HASH_SIZE; ++i) {
		result.h[i] = static_cast<uint8_t>(st[i / 8] >> ((i % 8) * 8));
	}

	return result;
}

constexpr hash keccak_0x00 = keccak("\0");
constexpr hash keccak_subaddress_viewpub = keccak("subaddress_viewpub");
constexpr hash keccak_onion_address_v3 = keccak("onion_address_v3");

static_assert(keccak_0x00.u64<0>() == 0x14281E7A9E7836BCULL, "constexpr keccak code check failed");

} // namespace p2pool
