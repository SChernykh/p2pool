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
#include "keccak.h"
#ifdef WITH_RANDOMX
#include "RandomX/src/cpu.hpp"
#endif

namespace p2pool {

#ifndef ROTL64
#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))
#endif

const uint64_t keccakf_rndc[24] = 
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

NOINLINE void keccakf_plain(std::array<uint64_t, 25>& st)
{
	for (int round = 0; round < KeccakParams::ROUNDS; ++round) {
		uint64_t bc[5];

		// Theta
		bc[0] = st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20];
		bc[1] = st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21];
		bc[2] = st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22];
		bc[3] = st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23];
		bc[4] = st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24];

#define THETA(i) { \
			const uint64_t t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1); \
			st[i +  0 ] ^= t; \
			st[i +  5] ^= t; \
			st[i + 10] ^= t; \
			st[i + 15] ^= t; \
			st[i + 20] ^= t; \
		}

		THETA(0);
		THETA(1);
		THETA(2);
		THETA(3);
		THETA(4);

		// Rho Pi
		const uint64_t t = st[1];
		st[ 1] = ROTL64(st[ 6], 44);
		st[ 6] = ROTL64(st[ 9], 20);
		st[ 9] = ROTL64(st[22], 61);
		st[22] = ROTL64(st[14], 39);
		st[14] = ROTL64(st[20], 18);
		st[20] = ROTL64(st[ 2], 62);
		st[ 2] = ROTL64(st[12], 43);
		st[12] = ROTL64(st[13], 25);
		st[13] = ROTL64(st[19],  8);
		st[19] = ROTL64(st[23], 56);
		st[23] = ROTL64(st[15], 41);
		st[15] = ROTL64(st[ 4], 27);
		st[ 4] = ROTL64(st[24], 14);
		st[24] = ROTL64(st[21],  2);
		st[21] = ROTL64(st[ 8], 55);
		st[ 8] = ROTL64(st[16], 45);
		st[16] = ROTL64(st[ 5], 36);
		st[ 5] = ROTL64(st[ 3], 28);
		st[ 3] = ROTL64(st[18], 21);
		st[18] = ROTL64(st[17], 15);
		st[17] = ROTL64(st[11], 10);
		st[11] = ROTL64(st[ 7],  6);
		st[ 7] = ROTL64(st[10],  3);
		st[10] = ROTL64(t, 1);

		//  Chi
#define CHI(j) { \
			const uint64_t st0 = st[j    ]; \
			const uint64_t st1 = st[j + 1]; \
			const uint64_t st2 = st[j + 2]; \
			const uint64_t st3 = st[j + 3]; \
			const uint64_t st4 = st[j + 4]; \
			st[j    ] ^= ~st1 & st2; \
			st[j + 1] ^= ~st2 & st3; \
			st[j + 2] ^= ~st3 & st4; \
			st[j + 3] ^= ~st4 & st0; \
			st[j + 4] ^= ~st0 & st1; \
		}

		CHI( 0);
		CHI( 5);
		CHI(10);
		CHI(15);
		CHI(20);

		// Iota
		st[0] ^= keccakf_rndc[round];
	}
}

void (*keccakf)(std::array<uint64_t, 25>&) = keccakf_plain;

#if defined(WITH_RANDOMX) && (defined(__x86_64__) || defined(_M_AMD64))
static struct KeccakBMI_Check {
	KeccakBMI_Check() {
		if (randomx::Cpu().hasBmi()) {
			keccakf = keccakf_bmi;
		}
	}
} keccak_bmi_check;
#endif

NOINLINE void keccak_step(const uint8_t* &in, int &inlen, std::array<uint64_t, 25>& st)
{
	constexpr int rsiz = KeccakParams::HASH_DATA_AREA;
	constexpr int rsizw = rsiz / 8;

	for (; inlen >= rsiz; inlen -= rsiz, in += rsiz) {
		for (int i = 0; i < rsizw; i++) {
			st[i] ^= read_unaligned(reinterpret_cast<const uint64_t*>(in) + i);
		}
		keccakf(st);
	}
}

NOINLINE void keccak_finish(const uint8_t* in, int inlen, std::array<uint64_t, 25>& st)
{
	constexpr int rsiz = KeccakParams::HASH_DATA_AREA;
	constexpr int rsizw = rsiz / 8;

	keccak_step(in, inlen, st);

	// last block and padding
	alignas(8) uint8_t temp[144];

	memcpy(temp, in, inlen);
	temp[inlen++] = 1;
	memset(temp + inlen, 0, rsiz - inlen);
	temp[rsiz - 1] |= 0x80;

	for (int i = 0; i < rsizw; i++) {
		st[i] ^= reinterpret_cast<uint64_t*>(temp)[i];
	}

	keccakf(st);
}

} // namespace p2pool
