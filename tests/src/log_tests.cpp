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

template<typename T, bool hex>
void check_number(T value)
{
	constexpr size_t N = 64;

	char buf[N];
	memset(buf, -1, N);
	log::Stream s(buf);
	s << log::BasedValue<T, hex ? 16 : 10>(value) << '\0';

	std::stringstream s2;
	s2 << (hex ? std::hex : std::dec) << value;

	ASSERT_EQ(strcmp(buf, s2.str().c_str()), 0);
}

TEST(log, numbers)
{
	for (int64_t i = -1024; i <= 1024; ++i) {
		check_number<int64_t, false>(i);

		if (i >= 0) {
			check_number<int64_t, true>(i);
			check_number<uint64_t, false>(i);
			check_number<uint64_t, true>(i);
		}
	}

	check_number<int64_t, false>(std::numeric_limits<int64_t>::min());
	check_number<int64_t, false>(std::numeric_limits<int64_t>::max());
	check_number<int64_t, true>(std::numeric_limits<int64_t>::max());

	check_number<uint64_t, false>(std::numeric_limits<uint64_t>::max());
	check_number<uint64_t, true>(std::numeric_limits<uint64_t>::max());
}

}
