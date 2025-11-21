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
#ifdef P2POOL_UNIT_TESTS
	FORCEINLINE Params() {}
#endif

	Params(const std::vector<std::vector<std::string_view>>& args);

	bool valid() const;

	struct Host
	{
		Host() : m_address("127.0.0.1"), m_rpcPort(18081), m_zmqPort(18083), m_rpcSSL(false) {}

		Host(const char* address, int32_t rpcPort, int32_t zmqPort, const char* rpcLogin)
			: m_address(address)
			, m_rpcPort(rpcPort)
			, m_zmqPort(zmqPort)
			, m_rpcLogin(rpcLogin)
			, m_rpcSSL(false)
		{}

		bool valid() const { return !m_address.empty() && m_rpcPort && m_zmqPort && (m_rpcPort != m_zmqPort); }

		bool init_display_name(const Params& p);

		std::string m_address;
		int32_t m_rpcPort;
		int32_t m_zmqPort;

		std::string m_rpcLogin;

		bool m_rpcSSL;
		std::string m_rpcSSL_Fingerprint;

		std::string m_displayName;
	};

	std::vector<Host> m_hosts;

	struct MergeMiningHost
	{
		template<typename T>
		FORCEINLINE MergeMiningHost(const T& host, const T& wallet) : m_host(host), m_wallet(wallet) {}

		std::string m_host;
		std::string m_wallet;
	};

	std::vector<MergeMiningHost> m_mergeMiningHosts;

	bool m_lightMode = false;

	Wallet m_mainWallet{ nullptr };
	Wallet m_subaddress{ nullptr };

	Wallet m_miningWallet{ nullptr };

	std::string m_displayWallet;

	std::string m_stratumAddresses;
	std::string m_p2pAddresses;
	std::string m_p2pPeerList;
	std::string m_dataDir;
	std::string m_logFilePath;
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
	int32_t m_p2pExternalPort = 0;
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
	bool m_enableFullValidation = false;

	std::string m_onionAddress;
	hash m_onionPubkey;
	bool m_noClearnetP2P = false;
};

} // namespace p2pool
