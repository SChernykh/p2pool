/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2025 SChernykh <https://github.com/SChernykh>
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

static constexpr uint64_t DEFAULT_STRATUM_BAN_TIME = 600;

struct Params
{
	Params(int argc, char* const argv[]);

	bool valid() const;

	struct Host
	{
		Host() : m_address("127.0.0.1"), m_rpcPort(18081), m_zmqPort(18083), m_rpcSSL(false) {}

		Host(const char* address, uint32_t rpcPort, uint32_t zmqPort, const char* rpcLogin)
			: m_address(address)
			, m_rpcPort(rpcPort)
			, m_zmqPort(zmqPort)
			, m_rpcLogin(rpcLogin)
			, m_rpcSSL(false)
		{}

		bool valid() const { return !m_address.empty() && m_rpcPort && m_zmqPort && (m_rpcPort != m_zmqPort); }

		bool init_display_name(const Params& p);

		std::string m_address;
		uint32_t m_rpcPort;
		uint32_t m_zmqPort;

		std::string m_rpcLogin;

		bool m_rpcSSL;
		std::string m_rpcSSL_Fingerprint;

		std::string m_displayName;
	};

	std::vector<Host> m_hosts;

	struct MergeMiningHost
	{
		MergeMiningHost(const char* host, const char* wallet) : m_host(host), m_wallet(wallet) {}

		std::string m_host;
		std::string m_wallet;
	};

	std::vector<MergeMiningHost> m_mergeMiningHosts;

	bool m_lightMode = false;
	Wallet m_wallet{ nullptr };
	std::string m_stratumAddresses;
	std::string m_p2pAddresses;
	std::string m_p2pPeerList;
	std::string m_sidechainConfig;
	std::string m_apiPath;
	uint64_t m_stratumBanTime = DEFAULT_STRATUM_BAN_TIME;
	bool m_localStats = false;
	bool m_blockCache = true;
#ifdef WITH_RANDOMX
	bool m_disableRandomX = false;
#else
	bool m_disableRandomX = true;
#endif
	uint32_t m_maxOutgoingPeers = 10;
	uint32_t m_maxIncomingPeers = 450;
	uint32_t m_minerThreads = 0;
	bool m_mini = false;
	bool m_nano = false;
	bool m_autoDiff = true;
	std::string m_socks5Proxy;
	bool m_dns = true;
	uint32_t m_p2pExternalPort = 0;
#ifdef WITH_UPNP
	bool m_upnp = true;
	bool m_upnpStratum = false;
#else
	bool m_upnp = false;
	bool m_upnpStratum = false;
#endif
#ifdef WITH_TLS
	std::string m_tlsCert;
	std::string m_tlsCertKey;
#endif
	bool m_enableStratumHTTP = true;

#ifdef WITH_MERGE_MINING_DONATION
	std::string m_authorKeyFile;

	struct AuthorKey {
		uint8_t pub_key[32];
		uint8_t expiration_time[8];
		uint8_t master_key_signature[64];
		uint8_t priv_key[64];
	};
#endif
};

} // namespace p2pool
