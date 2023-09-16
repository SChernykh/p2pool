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

#include "common.h"
#include "gtest/gtest.h"

namespace p2pool {

TEST(log, stream)
{
	constexpr int N = 63;

	char buf[N + 1] = {};
	log::Stream s(buf);

	for (int iter = 0; iter < 2; ++iter) {
		ASSERT_EQ(s.m_bufSize, N);

		for (int i = 0; i < N; ++i) {
			s << ' ';

			ASSERT_EQ(s.m_pos, i + 1);
			ASSERT_EQ(s.m_spilled, 0);
		}

		s << ' ';

		ASSERT_EQ(s.m_pos, N);
		ASSERT_EQ(s.m_spilled, 1);

		for (int i = 0; i < N; ++i) {
			ASSERT_EQ(buf[i], ' ');
		}

		ASSERT_EQ(buf[N], '\0');

		s.reset(buf, N + 1);
	}
}

TEST(log, pad_right)
{
	constexpr int N = 63;

	char buf[N + 1] = {};
	log::Stream s(buf);

	s << log::pad_right('1', N);

	ASSERT_EQ(s.m_pos, N);
	ASSERT_EQ(s.m_spilled, 0);

	ASSERT_EQ(buf[0], '1');

	for (int i = 1; i < N; ++i) {
		ASSERT_EQ(buf[i], ' ');
	}

	ASSERT_EQ(buf[N], '\0');
}

}
