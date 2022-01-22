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

#include "wallet.h"

namespace p2pool {

struct Params
{
	Params(int argc, char* argv[]);

	bool ok() const;

	std::string m_host = "127.0.0.1";
	uint32_t m_rpcPort = 18081;
	uint32_t m_zmqPort = 18083;
	bool m_lightMode = false;
	Wallet m_wallet{ nullptr };
	std::string m_stratumAddresses;
	std::string m_p2pAddresses;
	std::string m_p2pPeerList;
	std::string m_config;
	std::string m_apiPath;
	bool m_localStats = false;
	bool m_blockCache = true;
	bool m_disableRandomX = false;
	uint32_t m_maxOutgoingPeers = 10;
	uint32_t m_maxIncomingPeers = 1000;
	uint32_t m_minerThreads = 0;
};

} // namespace p2pool
