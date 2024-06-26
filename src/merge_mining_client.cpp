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
#include "merge_mining_client.h"
#include "merge_mining_client_json_rpc.h"

#if defined(WITH_GRPC) && !defined(P2POOL_UNIT_TESTS)
#include "merge_mining_client_tari.h"
#endif

LOG_CATEGORY(MergeMiningClient)

namespace p2pool {

IMergeMiningClient* IMergeMiningClient::create(p2pool* pool, const std::string& host, const std::string& wallet) noexcept
{
	try {
#if defined(WITH_GRPC) && !defined(P2POOL_UNIT_TESTS)
		if (host.find(MergeMiningClientTari::TARI_PREFIX) == 0) {
			return new MergeMiningClientTari(pool, host, wallet);
		}
		else
#endif
		{
			return new MergeMiningClientJSON_RPC(pool, host, wallet);
		}
	}
	catch (...) {
		LOGERR(1, "Failed to create merge mining client for " << host);
	}
	return nullptr;
}

} // namespace p2pool
