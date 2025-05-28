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
#include "params.h"
#include "stratum_server.h"
#include "p2p_server.h"

LOG_CATEGORY(Params)

void p2pool_usage();

namespace p2pool {

Params::Params(int argc, char* const argv[])
{
	for (int i = 1; i < argc; ++i) {
		bool ok = false;

		if ((strcmp(argv[i], "--host") == 0) && (i + 1 < argc)) {
			const char* address = argv[++i];

			if (m_hosts.empty()) {
				m_hosts.emplace_back(Host());
				m_hosts.back().m_address = address;
			}
			else {
				const Host& h = m_hosts.back();
				m_hosts.emplace_back(address, h.m_rpcPort, h.m_zmqPort, "");
			}

			ok = true;
		}

		if ((strcmp(argv[i], "--rpc-port") == 0) && (i + 1 < argc)) {
			if (m_hosts.empty()) {
				m_hosts.emplace_back(Host());
			}

			m_hosts.back().m_rpcPort = std::min(std::max(strtoul(argv[++i], nullptr, 10), 1UL), 65535UL);
			ok = true;
		}

		if ((strcmp(argv[i], "--zmq-port") == 0) && (i + 1 < argc)) {
			if (m_hosts.empty()) {
				m_hosts.emplace_back(Host());
			}

			m_hosts.back().m_zmqPort = std::min(std::max(strtoul(argv[++i], nullptr, 10), 1UL), 65535UL);
			ok = true;
		}

		if (strcmp(argv[i], "--light-mode") == 0) {
			m_lightMode = true;
			ok = true;
		}

		if ((strcmp(argv[i], "--wallet") == 0) && (i + 1 < argc)) {
			m_wallet.decode(argv[++i]);
			ok = true;
		}

		if ((strcmp(argv[i], "--stratum") == 0) && (i + 1 < argc)) {
			m_stratumAddresses = argv[++i];
			ok = true;
		}

		if ((strcmp(argv[i], "--p2p") == 0) && (i + 1 < argc)) {
			m_p2pAddresses = argv[++i];
			ok = true;
		}

		if ((strcmp(argv[i], "--addpeers") == 0) && (i + 1 < argc)) {
			m_p2pPeerList = argv[++i];
			ok = true;
		}

		if ((strcmp(argv[i], "--loglevel") == 0) && (i + 1 < argc)) {
			const int level = std::min(std::max<int>(strtol(argv[++i], nullptr, 10), 0), log::MAX_GLOBAL_LOG_LEVEL);
			log::GLOBAL_LOG_LEVEL = level;
			ok = true;
		}

		if ((strcmp(argv[i], "--data-dir") == 0) && (i + 1 < argc)) {
			// Processed in main.cpp
			++i;
			ok = true;
		}

		if ((strcmp(argv[i], "--sidechain-config") == 0) && (i + 1 < argc)) {
			m_sidechainConfig = argv[++i];
			ok = true;
		}

		if ((strcmp(argv[i], "--data-api") == 0) && (i + 1 < argc)) {
			m_apiPath = argv[++i];
			ok = true;
		}

		if ((strcmp(argv[i], "--local-api") == 0) || (strcmp(argv[i], "--stratum-api") == 0)) {
			m_localStats = true;
			ok = true;
		}

		if (strcmp(argv[i], "--no-cache") == 0) {
			m_blockCache = false;
			ok = true;
		}

		if (strcmp(argv[i], "--no-color") == 0) {
			log::CONSOLE_COLORS = false;
			ok = true;
		}

#ifdef WITH_RANDOMX
		if (strcmp(argv[i], "--no-randomx") == 0) {
			m_disableRandomX = true;
			ok = true;
		}
#endif

		if ((!strcmp(argv[i], "--out-peers") || !strcmp(argv[i], "--outpeers")) && (i + 1 < argc)) {
			m_maxOutgoingPeers = std::min(std::max(strtoul(argv[++i], nullptr, 10), 10UL), 450UL);
			ok = true;
		}

		if ((!strcmp(argv[i], "--in-peers") || !strcmp(argv[i], "--inpeers")) && (i + 1 < argc)) {
			m_maxIncomingPeers = std::min(std::max(strtoul(argv[++i], nullptr, 10), 10UL), 450UL);
			ok = true;
		}

		if ((strcmp(argv[i], "--start-mining") == 0) && (i + 1 < argc)) {
			m_minerThreads = std::min(std::max(strtoul(argv[++i], nullptr, 10), 1UL), 64UL);
			ok = true;
		}

		if (strcmp(argv[i], "--mini") == 0) {
			m_mini = true;
			ok = true;
		}

		if (strcmp(argv[i], "--nano") == 0) {
			m_nano = true;
			ok = true;
		}

		if (strcmp(argv[i], "--no-autodiff") == 0) {
			m_autoDiff = false;
			ok = true;
		}

		if ((strcmp(argv[i], "--rpc-login") == 0) && (i + 1 < argc)) {
			if (m_hosts.empty()) {
				m_hosts.emplace_back(Host());
			}

			m_hosts.back().m_rpcLogin = argv[++i];
			ok = true;
		}

#ifdef WITH_TLS
		if (strcmp(argv[i], "--rpc-ssl") == 0) {
			if (m_hosts.empty()) {
				m_hosts.emplace_back(Host());
			}

			m_hosts.back().m_rpcSSL = true;
			ok = true;
		}

		if ((strcmp(argv[i], "--rpc-ssl-fingerprint") == 0) && (i + 1 < argc)) {
			if (m_hosts.empty()) {
				m_hosts.emplace_back(Host());
			}

			m_hosts.back().m_rpcSSL_Fingerprint = argv[++i];
			ok = true;
		}
#endif

		if ((strcmp(argv[i], "--socks5") == 0) && (i + 1 < argc)) {
			m_socks5Proxy = argv[++i];
			ok = true;
		}

		if (strcmp(argv[i], "--no-dns") == 0) {
			m_dns = false;
			disable_resolve_host = true;
			ok = true;
		}

		if ((strcmp(argv[i], "--p2p-external-port") == 0) && (i + 1 < argc)) {
			m_p2pExternalPort = std::min(std::max(strtoul(argv[++i], nullptr, 10), 1UL), 65535UL);
			ok = true;
		}

#ifdef WITH_UPNP
		if ((strcmp(argv[i], "--no-upnp") == 0) || (strcmp(argv[i], "--no-igd") == 0)) {
			m_upnp = false;
			ok = true;
		}

		if (strcmp(argv[i], "--upnp-stratum") == 0) {
			m_upnpStratum = true;
			ok = true;
		}
#endif

		if ((strcmp(argv[i], "--merge-mine") == 0) && (i + 2 < argc)) {
			m_mergeMiningHosts.emplace_back(argv[i + 1], argv[i + 2]);
			i += 2;
			ok = true;
		}

#ifdef WITH_TLS
		if ((strcmp(argv[i], "--tls-cert") == 0) && (i + 1 < argc)) {
			m_tlsCert = argv[++i];
			ok = true;
		}

		if ((strcmp(argv[i], "--tls-cert-key") == 0) && (i + 1 < argc)) {
			m_tlsCertKey = argv[++i];
			ok = true;
		}
#endif

		if (strcmp(argv[i], "--no-stratum-http") == 0) {
			m_enableStratumHTTP = false;
			ok = true;
		}

#ifdef WITH_MERGE_MINING_DONATION
		if ((strcmp(argv[i], "--adkf") == 0) && (i + 1 < argc)) {
			m_authorKeyFile = argv[++i];
			ok = true;
		}
#endif

		if (!ok) {
			// Wait to avoid log messages overlapping with printf() calls and making a mess on screen
			std::this_thread::sleep_for(std::chrono::milliseconds(10));

			fprintf(stderr, "Unknown command line parameter %s\n\n", argv[i]);
			p2pool_usage();
			throw std::exception();
		}
	}

	auto invalid_host = [](const Host& h)
	{
		if (!h.valid()) {
			LOGERR(1, "Invalid host " << h.m_address << ':' << h.m_rpcPort << ":ZMQ:" << h.m_zmqPort << ". Try \"p2pool --help\".");
			return true;
		}
		return false;
	};

	m_hosts.erase(std::remove_if(m_hosts.begin(), m_hosts.end(), invalid_host), m_hosts.end());

	if (m_hosts.empty()) {
		m_hosts.emplace_back(Host());
	}

	if (m_stratumAddresses.empty()) {
		const int stratum_port = DEFAULT_STRATUM_PORT;

		char buf[48] = {};
		log::Stream s(buf);
		s << "[::]:" << stratum_port << ",0.0.0.0:" << stratum_port;

		m_stratumAddresses = buf;
	}
}

bool Params::valid() const
{
	if (!m_wallet.valid()) {
		LOGERR(1, "Invalid wallet address. Try \"p2pool --help\".");
		return false;
	}

	if (m_mergeMiningHosts.size() > 10) {
		LOGERR(1, "Too many merge mining blockchains.");
		return false;
	}

#ifdef WITH_TLS
	if (m_tlsCert.empty() != m_tlsCertKey.empty()) {
		LOGERR(1, "Both --tls-cert and --tls-cert-key files must be specified");
		return false;
	}
#endif

	if (m_mini && m_nano) {
		LOGERR(1, "You can't have both --mini and --nano in the command line");
		return false;
	}

	return true;
}

bool Params::Host::init_display_name(const Params& p)
{
	m_displayName = m_address;

	if (p.m_socks5Proxy.empty()) {
		if (p.m_dns) {
			bool is_v6;
			if (!resolve_host(m_address, is_v6)) {
				LOGERR(1, "resolve_host failed for " << m_address);
				return false;
			}
		}
		else if (m_address.find_first_not_of("0123456789.:") != std::string::npos) {
			LOGERR(1, "Can't resolve hostname " << m_address << " with DNS disabled");
			return false;
		}
	}

	char buf[log::Stream::BUF_SIZE + 1];
	buf[0] = '\0';
	log::Stream s(buf);

	s << m_displayName << (m_rpcSSL ? ":RPC-SSL " : ":RPC ") << m_rpcPort << ":ZMQ " << m_zmqPort;
	if (m_address != m_displayName) {
		s << " (" << m_address << ')';
	}

	m_displayName.assign(buf, s.m_pos);

	return true;
}

} // namespace p2pool
