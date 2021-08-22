/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021 SChernykh <https://github.com/SChernykh>
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

#include <thread>

namespace p2pool {

class p2pool;

class ConsoleCommands : public nocopy_nomove
{
public:
	explicit ConsoleCommands(p2pool* pool);
	~ConsoleCommands();

private:
	p2pool* m_pool;
	std::thread* m_worker;

	static bool stopped;
	void run();
};

} // namespace p2pool
