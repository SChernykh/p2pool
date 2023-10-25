/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2023 SChernykh <https://github.com/SChernykh>
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

enum KeccakParams {
	HASH_DATA_AREA = 136,
	ROUNDS = 24,
};

void keccakf(uint64_t (&st)[25]);
void keccak_step(const uint8_t* &in, int &inlen, uint64_t (&st)[25]);
void keccak_finish(const uint8_t* in, int inlen, uint64_t (&st)[25]);

template<size_t N>
FORCEINLINE void keccak(const uint8_t* in, int inlen, uint8_t (&md)[N])
{
	static_assert((N == 32) || (N == 200), "invalid size");

	uint64_t st[25] = {};
	keccak_step(in, inlen, st);
	keccak_finish(in, inlen, st);
	memcpy(md, st, N);
}

template<typename T>
FORCEINLINE void keccak_custom(T&& in, int inlen, uint8_t* md, int mdlen)
{
	// TODO: remove after testing
#if 0
	if (inlen > 100) {
		printf("\nkeccak_custom %d", inlen);
		for (int i = 0; i < inlen; ++i) {
			if ((i & 31) == 0) printf("\n");
			printf("%02X ", static_cast<uint8_t>(in(i)));
		}
		printf("\n");
	}
#endif

	uint64_t st[25] = {};

	const int rsiz = sizeof(st) == mdlen ? KeccakParams::HASH_DATA_AREA : 200 - 2 * mdlen;
	const int rsizw = rsiz / 8;

	int offset = 0;

	for (; inlen >= rsiz; inlen -= rsiz, offset += rsiz) {
		for (int i = 0; i < rsizw; ++i) {
			uint64_t k = 0;
			for (int j = 0; j < 8; ++j) {
				k |= static_cast<uint64_t>(in(offset + i * 8 + j)) << (j * 8);
			}
			st[i] ^= k;
		}
		keccakf(st);
	}

	// last block and padding
	alignas(8) uint8_t temp[144];

	for (int i = 0; i < inlen; ++i) {
		temp[i] = in(offset + i);
	}

	temp[inlen++] = 1;
	memset(temp + inlen, 0, rsiz - inlen);
	temp[rsiz - 1] |= 0x80;

	for (int i = 0; i < rsizw; i++) {
		st[i] ^= reinterpret_cast<uint64_t*>(temp)[i];
	}

	keccakf(st);

	memcpy(md, st, mdlen);
}

} // namespace p2pool
