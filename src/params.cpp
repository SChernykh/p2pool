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

#include "common.h"
#include "params.h"
#include "stratum_server.h"
#include "p2p_server.h"
#include <fstream>

LOG_CATEGORY(Params)

void p2pool_usage();

namespace p2pool {

static constexpr uint64_t MIN_STRATUM_BAN_TIME = UINT64_C(1);
static constexpr uint64_t MAX_STRATUM_BAN_TIME = (UINT64_C(1) << 34) - 1;

Params::Params(const std::vector<std::vector<std::string_view>>& args)
{
	auto has1 = [](const auto& v) { return (v.size() > 1) && !v[1].empty();};
	auto has2 = [](const auto& v) { return (v.size() > 2) && !v[2].empty();};

	for (const auto& arg : args) {
		// Ignore empty parameters
		if (arg.empty() || arg[0].empty()) {
			continue;
		}

		bool ok = false;

		if ((arg[0] == "host") && has1(arg)) {
			const char* address = arg[1].data();

			if (m_hosts.empty()) {
				m_hosts.emplace_back();
				m_hosts.back().m_address = address;
			}
			else {
				const Host& h = m_hosts.back();
				m_hosts.emplace_back(address, h.m_rpcPort, h.m_zmqPort, "");
			}

			ok = true;
		}

		if ((arg[0] == "rpc-port") && has1(arg)) {
			if (m_hosts.empty()) {
				m_hosts.emplace_back();
			}

			m_hosts.back().m_rpcPort = static_cast<int32_t>(std::min(std::max(strtoul(arg[1].data(), nullptr, 10), 1UL), 65535UL));
			ok = true;
		}

		if ((arg[0] == "zmq-port") && has1(arg)) {
			if (m_hosts.empty()) {
				m_hosts.emplace_back();
			}

			m_hosts.back().m_zmqPort = static_cast<int32_t>(std::min(std::max(strtoul(arg[1].data(), nullptr, 10), 1UL), 65535UL));
			ok = true;
		}

		if (arg[0] == "light-mode") {
			m_lightMode = true;
			ok = true;
		}

		if ((arg[0] == "wallet") && has1(arg)) {
			const char* s = arg[1].data();

			if (!m_mainWallet.decode(s)) {
				LOGERR(1, "Wallet " << s << " failed to decode");
			}

			ok = true;
		}

		if ((arg[0] == "subaddress") && has1(arg)) {
			const char* s = arg[1].data();

			if (!m_subaddress.decode(s)) {
				LOGERR(1, "Subaddress " << s << " failed to decode");
			}

			ok = true;
		}

		if ((arg[0] == "stratum") && has1(arg)) {
			m_stratumAddresses = arg[1];
			ok = true;
		}

		if ((arg[0] == "stratum-ban-time") && has1(arg)) {
			m_stratumBanTime = strtoull(arg[1].data(), nullptr, 10);
			ok = true;
		}

		if ((arg[0] == "p2p") && has1(arg)) {
			m_p2pAddresses = arg[1];
			ok = true;
		}

		if ((arg[0] == "addpeers") && has1(arg)) {
			m_p2pPeerList = arg[1];
			ok = true;
		}

		if ((arg[0] == "loglevel") && has1(arg)) {
			const int level = std::min(std::max<int>(static_cast<int>(strtol(arg[1].data(), nullptr, 10)), 0), log::MAX_GLOBAL_LOG_LEVEL);
			log::GLOBAL_LOG_LEVEL = level;
			ok = true;
		}

		if ((arg[0] == "data-dir") && has1(arg)) {
			m_dataDir = arg[1];
			ok = true;
		}

		if ((arg[0] == "log-file") && has1(arg)) {
			m_logFilePath = arg[1];
			ok = true;
		}

		if ((arg[0] == "sidechain-config") && has1(arg)) {
			m_sidechainConfig = arg[1];
			ok = true;
		}

		if ((arg[0] == "data-api") && has1(arg)) {
			m_apiPath = arg[1];
			ok = true;
		}

		if ((arg[0] == "local-api") || (arg[0] == "stratum-api")) {
			m_localStats = true;
			ok = true;
		}

		if (arg[0] == "no-cache") {
			m_blockCache = false;
			ok = true;
		}

		if (arg[0] == "no-color") {
			log::CONSOLE_COLORS = false;
			ok = true;
		}

#ifdef WITH_RANDOMX
		if (arg[0] == "no-randomx") {
			m_disableRandomX = true;
			ok = true;
		}
#endif

		if (((arg[0] == "out-peers") || (arg[0] == "outpeers")) && has1(arg)) {
			m_maxOutgoingPeers = std::min(std::max(strtoul(arg[1].data(), nullptr, 10), 10UL), 450UL);
			ok = true;
		}

		if (((arg[0] == "in-peers") || (arg[0] == "inpeers")) && has1(arg)) {
			m_maxIncomingPeers = std::min(std::max(strtoul(arg[1].data(), nullptr, 10), 10UL), 450UL);
			ok = true;
		}

		if ((arg[0] == "start-mining") && has1(arg)) {
			m_minerThreads = std::min(std::max(strtoul(arg[1].data(), nullptr, 10), 1UL), 64UL);
			ok = true;
		}

		if (arg[0] == "mini") {
			m_mini = true;
			ok = true;
		}

		if (arg[0] == "nano") {
			m_nano = true;
			ok = true;
		}

		if (arg[0] == "no-autodiff") {
			m_autoDiff = false;
			ok = true;
		}

		if ((arg[0] == "rpc-login") && has1(arg)) {
			if (m_hosts.empty()) {
				m_hosts.emplace_back();
			}

			m_hosts.back().m_rpcLogin = arg[1];
			ok = true;
		}

#ifdef WITH_TLS
		if (arg[0] == "rpc-ssl") {
			if (m_hosts.empty()) {
				m_hosts.emplace_back();
			}

			m_hosts.back().m_rpcSSL = true;
			ok = true;
		}

		if ((arg[0] == "rpc-ssl-fingerprint") && has1(arg)) {
			if (m_hosts.empty()) {
				m_hosts.emplace_back();
			}

			m_hosts.back().m_rpcSSL_Fingerprint = arg[1];
			ok = true;
		}
#endif

		if ((arg[0] == "socks5") && has1(arg)) {
			m_socks5Proxy = arg[1];
			ok = true;
		}

		if (arg[0] == "no-dns") {
			m_dns = false;
			disable_resolve_host = true;
			ok = true;
		}

		if ((arg[0] == "p2p-external-port") && has1(arg)) {
			m_p2pExternalPort = static_cast<int32_t>(std::min(std::max(strtoul(arg[1].data(), nullptr, 10), 1UL), 65535UL));
			ok = true;
		}

#ifdef WITH_UPNP
		if ((arg[0] == "no-upnp") || (arg[0] == "no-igd")) {
			m_upnp = false;
			ok = true;
		}

		if (arg[0] == "upnp-stratum") {
			m_upnpStratum = true;
			ok = true;
		}
#endif

		if ((arg[0] == "merge-mine") && has1(arg) && has2(arg)) {
			m_mergeMiningHosts.emplace_back(arg[1], arg[2]);
			ok = true;
		}

#ifdef WITH_TLS
		if ((arg[0] == "tls-cert") && has1(arg)) {
			m_tlsCert = arg[1];
			ok = true;
		}

		if ((arg[0] == "tls-cert-key") && has1(arg)) {
			m_tlsCertKey = arg[1];
			ok = true;
		}
#endif

		if (arg[0] == "no-stratum-http") {
			m_enableStratumHTTP = false;
			ok = true;
		}

#ifdef WITH_MERGE_MINING_DONATION
		if ((arg[0] == "adkf") && has1(arg)) {
			m_authorKeyFile = arg[1];
			ok = true;
		}
#endif

		if (arg[0] == "full-validation") {
			m_enableFullValidation = true;
			ok = true;
		}

		if ((arg[0] == "onion-address") && has1(arg)) {
			m_onionAddress = arg[1];
			ok = true;
		}

		if (arg[0] == "no-clearnet-p2p") {
			m_noClearnetP2P = true;
			ok = true;
		}

		if (!ok) {
			fprintf(stderr, "Unknown or invalid command line parameter \"%s\"\n\n", arg[0].data());
			p2pool_usage();
			throw std::exception();
		}
	}

	if (!m_onionAddress.empty()) {
		m_onionPubkey = from_onion_v3(m_onionAddress);

		if (m_onionPubkey.empty()) {
			LOGERR(1, "Failed to parse \"" << m_onionAddress << '"');
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
		m_hosts.emplace_back();
	}

	const int p2p_port = m_mini ? DEFAULT_P2P_PORT_MINI : (m_nano ? DEFAULT_P2P_PORT_NANO : DEFAULT_P2P_PORT);

	if (m_noClearnetP2P) {
		char buf[48] = {};
		log::Stream s(buf);
		s << "127.0.0.1:" << p2p_port;

		m_p2pAddresses = buf;
	}
	else if (m_p2pAddresses.empty()) {
		char buf[48] = {};
		log::Stream s(buf);
		s << "[::]:" << p2p_port << ",0.0.0.0:" << p2p_port;

		m_p2pAddresses = buf;
	}

	if (m_stratumAddresses.empty()) {
		const int stratum_port = DEFAULT_STRATUM_PORT;

		char buf[48] = {};
		log::Stream s(buf);
		s << "[::]:" << stratum_port << ",0.0.0.0:" << stratum_port;

		m_stratumAddresses = buf;
	}

	if(m_stratumBanTime < MIN_STRATUM_BAN_TIME) {
		LOGWARN(1, "Value for --stratum-ban-time is too low, adjusting to " << MIN_STRATUM_BAN_TIME);
		m_stratumBanTime = MIN_STRATUM_BAN_TIME;
	} else if(m_stratumBanTime > MAX_STRATUM_BAN_TIME) {
		LOGWARN(1, "Value for --stratum-ban-time is too high, adjusting to " << MAX_STRATUM_BAN_TIME);
		m_stratumBanTime = MAX_STRATUM_BAN_TIME;
	}

	char display_wallet_buf[Wallet::ADDRESS_LENGTH] = {};

	if (m_mainWallet.valid() && m_subaddress.valid()) {
		if (!m_miningWallet.assign(m_subaddress.spend_public_key(), m_mainWallet.view_public_key(), m_mainWallet.type(), false)) {
			LOGERR(1, "Failed to configure the mining wallet, falling back to " << m_mainWallet);
			m_miningWallet = m_mainWallet;
			m_mainWallet.encode(display_wallet_buf);
		}
		else {
			m_subaddress.encode(display_wallet_buf);
		}
	}
	else if (m_mainWallet.valid()) {
		m_miningWallet = m_mainWallet;
		m_mainWallet.encode(display_wallet_buf);
	}

	m_displayWallet.assign(display_wallet_buf, Wallet::ADDRESS_LENGTH);

	for (Params::Host& h : m_hosts) {
		if (!h.init_display_name(*this)) {
			throw std::exception();
		}
	}

	// If the data directory is not set, check if P2Pool has write access to the current directory
	// If it doesn't, switch to user's home directory
	if (m_dataDir.empty()) {
		std::ofstream f("p2pool.tmp");
		if (f && f.put(' ')) {
			f.close();
			std::remove("p2pool.tmp");
		}
		else {
			char buf[1024];
			size_t size = sizeof(buf);

			if (uv_os_homedir(buf, &size) == 0) {
				m_dataDir.assign(buf, size);
				fixup_path(m_dataDir);

				m_dataDir += ".p2pool/";

				if (m_mini) {
					m_dataDir += "mini/";
				}
				else if (m_nano) {
					m_dataDir += "nano/";
				}
			}
		}
	}
	else {
		fixup_path(m_dataDir);
	}
}

bool Params::valid() const
{
	if (!m_mainWallet.valid() || !m_miningWallet.valid()) {
		LOGERR(1, "Invalid wallet address. Try \"p2pool --help\".");
		return false;
	}

	if (m_mainWallet.is_subaddress()) {
		LOGERR(1, "Wallet address must be a main address (starting with 4...). Try \"p2pool --help\".");
		return false;
	}

	if (m_subaddress.valid()) {
		if (!m_subaddress.is_subaddress()) {
			LOGERR(1, "Subaddress must start with 8... Try \"p2pool --help\".");
			return false;
		}
		if (m_subaddress.type() != m_mainWallet.type()) {
			LOGERR(1, "Subaddress must belong to the same network type as the main wallet address. Try \"p2pool --help\".");
			return false;
		}
	}

	if (!m_mainWallet.torsion_check()) {
		LOGERR(1, m_mainWallet << " didn't pass the torsion check. It will be incompatible with FCMP++.");
		return false;
	}

	if (m_subaddress.valid() && !m_subaddress.torsion_check()) {
		LOGERR(1, m_subaddress << " didn't pass the torsion check. It will be incompatible with FCMP++.");
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
