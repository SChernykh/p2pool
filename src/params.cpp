/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2022 SChernykh <https://github.com/SChernykh>
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

void p2pool_usage();

namespace p2pool {

Params::Params(int argc, char* argv[])
{
	for (int i = 1; i < argc; ++i) {
		bool ok = false;

		if ((strcmp(argv[i], "--host") == 0) && (i + 1 < argc)) {
			m_host = argv[++i];
			ok = true;
		}

		if ((strcmp(argv[i], "--rpc-port") == 0) && (i + 1 < argc)) {
			m_rpcPort = strtoul(argv[++i], nullptr, 10);
			ok = true;
		}

		if ((strcmp(argv[i], "--zmq-port") == 0) && (i + 1 < argc)) {
			m_zmqPort = strtoul(argv[++i], nullptr, 10);
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

		if ((strcmp(argv[i], "--config") == 0) && (i + 1 < argc)) {
			m_config = argv[++i];
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

		if (strcmp(argv[i], "--no-randomx") == 0) {
			m_disableRandomX = true;
			ok = true;
		}

		if ((strcmp(argv[i], "--out-peers") == 0) && (i + 1 < argc)) {
			m_maxOutgoingPeers = std::min(std::max(strtoul(argv[++i], nullptr, 10), 10UL), 1000UL);
			ok = true;
		}

		if ((strcmp(argv[i], "--in-peers") == 0) && (i + 1 < argc)) {
			m_maxIncomingPeers = std::min(std::max(strtoul(argv[++i], nullptr, 10), 10UL), 1000UL);
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

		if (strcmp(argv[i], "--no-autodiff") == 0) {
			m_autoDiff = false;
			ok = true;
		}

		if (!ok) {
			fprintf(stderr, "Unknown command line parameter %s\n\n", argv[i]);
			p2pool_usage();
			panic();
		}
	}

	if (m_stratumAddresses.empty()) {
		const int stratum_port = DEFAULT_STRATUM_PORT;

		char buf[log::Stream::BUF_SIZE + 1];
		log::Stream s(buf);
		s << "[::]:" << stratum_port << ",0.0.0.0:" << stratum_port << '\0';

		m_stratumAddresses = buf;
	}
}

bool Params::ok() const
{
	return !m_host.empty() && m_rpcPort && m_zmqPort && m_wallet.valid();
}

} // namespace p2pool
