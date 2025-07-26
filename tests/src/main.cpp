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
#include "pool_block.h"
#include "json_rpc_request.h"
#include "merge_mining_client.h"

#include "gtest/gtest.h"

void p2pool_usage() {}

namespace p2pool {

IMergeMiningClient* IMergeMiningClient::create(p2pool*, const std::string&, const std::string&) noexcept { return nullptr; }

namespace JSONRPCRequest {
	void Call(const std::string&, int, const std::string&, const std::string&, const std::string&, bool, const std::string&, CallbackBase*, CallbackBase*, uv_loop_t*) {}
}

}

using namespace p2pool;

int main(int argc, char** argv)
{
	set_main_thread();
	p2pool_usage();

	PoolBlock::s_precalculatedSharesLock = new ReadWriteLock();

	testing::InitGoogleTest(&argc, argv);
	const int result = RUN_ALL_TESTS();

	delete PoolBlock::s_precalculatedSharesLock;

	return result;
}
