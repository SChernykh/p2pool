/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2024 SChernykh <https://github.com/SChernykh>
 * Copyright (c) 2026 jpk68
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

#include <string>
#include <cstdint>
#include "gtest/gtest.h"
#include "i2p.h"
#include "common.h"

namespace p2pool {

TEST(i2p, decode_encode)
{
	const std::string addr1 = "vxghq7uoi3m5juvfk2otmxlh4qhwb42xdbytehtahqeksoclcetq.b32.i2p";
	const hash result1 = from_i2p_b32(addr1);

	const hash expected1{
		0xad, 0xcc, 0x78, 0x7e, 0x8e, 0x46, 0xd9, 0xd4,
		0xd2, 0xa5, 0x56, 0x9d, 0x36, 0x5d, 0x67, 0xe4,
		0x0f, 0x60, 0xf3, 0x57, 0x18, 0x71, 0x32, 0x1e,
		0x60, 0x3c, 0x08, 0xa9, 0x38, 0x4b, 0x11, 0x27
	};
	EXPECT_EQ(result1, expected1);

	const std::string result2 = to_i2p_b32(result1);
	EXPECT_EQ(result2, addr1);
}

} // namespace p2pool
