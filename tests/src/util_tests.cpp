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
#include "util.h"
#include "gtest/gtest.h"

namespace p2pool {

TEST(util, varint)
{
	std::vector<uint8_t> v;
	v.reserve(16);

	uint64_t check;

	// 0...2^7 - 1
	for (uint64_t value = 0; value < 0x80; ++value) {
		v.clear();
		writeVarint(value, v);
		ASSERT_EQ(v.size(), 1);
		ASSERT_EQ(v[0], value);
		ASSERT_EQ(readVarint(v.data(), v.data() + v.size(), check), v.data() + v.size());
		ASSERT_EQ(check, value);
	}

	// 2^7...2^14 - 1
	for (uint64_t value = 0x80; value < 0x4000; ++value) {
		v.clear();
		writeVarint(value, v);
		ASSERT_EQ(v.size(), 2);
		ASSERT_EQ(v[0], (value & 0x7F) | 0x80);
		ASSERT_EQ(v[1], value >> 7);
		ASSERT_EQ(readVarint(v.data(), v.data() + v.size(), check), v.data() + v.size());
		ASSERT_EQ(check, value);
	}

	// 2^14...2^21 - 1
	for (uint64_t value = 0x4000; value < 0x200000; ++value) {
		v.clear();
		writeVarint(value, v);
		ASSERT_EQ(v.size(), 3);
		ASSERT_EQ(v[0], (value & 0x7F) | 0x80);
		ASSERT_EQ(v[1], ((value >> 7) & 0x7F) | 0x80);
		ASSERT_EQ(v[2], value >> 14);
		ASSERT_EQ(readVarint(v.data(), v.data() + v.size(), check), v.data() + v.size());
		ASSERT_EQ(check, value);
	}

	// 2^64 - 1
	v.clear();
	writeVarint(std::numeric_limits<uint64_t>::max(), v);
	ASSERT_EQ(v.size(), 10);
	for (int i = 0; i < 9; ++i) {
		ASSERT_EQ(v[i], 0xFF);
	}
	ASSERT_EQ(v[9], 1);
	ASSERT_EQ(readVarint(v.data(), v.data() + v.size(), check), v.data() + v.size());
	ASSERT_EQ(check, std::numeric_limits<uint64_t>::max());

	// Invalid value 1
	uint8_t buf[16];
	memset(buf, -1, sizeof(buf));
	ASSERT_EQ(readVarint(buf, buf + sizeof(buf), check), nullptr);

	// Invalid value 2
	uint8_t buf2[1] = { 0x80 };
	ASSERT_EQ(readVarint(buf2, buf2 + 1, check), nullptr);

	// Invalid value 3
	uint8_t buf3[16];
	memset(buf3, 128, sizeof(buf3));
	ASSERT_EQ(readVarint(buf3, buf3 + sizeof(buf3), check), nullptr);

	// Invalid value 4
	uint32_t check2;
	uint8_t buf4[] = {255, 255, 255, 255, 127};
	ASSERT_EQ(readVarint(buf4, buf4 + sizeof(buf4), check2), nullptr);

	// Invalid value 5
	uint8_t buf5[] = {128, 0};
	ASSERT_EQ(readVarint(buf5, buf5 + sizeof(buf5), check), nullptr);

	// Invalid value 6 (2^64)
	uint8_t buf6[] = {128, 128, 128, 128, 128, 128, 128, 128, 128, 2};
	ASSERT_EQ(readVarint(buf6, buf6 + sizeof(buf6), check), nullptr);
}

TEST(util, bsr)
{
	for (uint64_t i = 0, x = 1; i <= 63; ++i, x <<= 1) {
		ASSERT_EQ(bsr(x), i);
		ASSERT_EQ(bsr_reference(x), i);

		const uint64_t y = x | (x - 1);
		ASSERT_EQ(bsr(y), i);
		ASSERT_EQ(bsr_reference(y), i);
	}
}

}
