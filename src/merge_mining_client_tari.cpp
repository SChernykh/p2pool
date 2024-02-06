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
#include "merge_mining_client_tari.h"
#include "p2pool.h"
#include "params.h"
#include "Tari/proto.h"

LOG_CATEGORY(MergeMiningClientTari)

namespace p2pool {

MergeMiningClientTari::MergeMiningClientTari(p2pool* pool, const std::string& host, const std::string& wallet)
	: m_server(new gRPC_Server(pool->params().m_socks5Proxy))
	, m_host(host)
	, m_port(0)
	, m_auxWallet(wallet)
	, m_pool(pool)
{
	if (host.find(TARI_PREFIX) != 0) {
		LOGERR(1, "Invalid host " << host << " - \"" << TARI_PREFIX << "\" prefix not found");
		throw std::exception();
	}

	const size_t k = host.find_last_of(':');
	if (k != std::string::npos) {
		m_host = host.substr(sizeof(TARI_PREFIX) - 1, k - (sizeof(TARI_PREFIX) - 1));
		m_port = std::stoul(host.substr(k + 1), nullptr, 10);
	}

	if (m_host.empty() || (m_port == 0) || (m_port >= 65536)) {
		LOGERR(1, "Invalid host " << host);
		throw std::exception();
	}

	uv_rwlock_init_checked(&m_lock);

	if (!m_server->start(m_pool->params().m_dns, m_host, m_port)) {
		throw std::exception();
	}
}

MergeMiningClientTari::~MergeMiningClientTari()
{
	m_server->shutdown_tcp();
	delete m_server;

	LOGINFO(1, "stopped");
}

bool MergeMiningClientTari::get_params(ChainParameters& out_params) const
{
	ReadLock lock(m_lock);

	if (m_chainParams.aux_id.empty() || m_chainParams.aux_diff.empty()) {
		return false;
	}

	out_params = m_chainParams;
	return true;
}

void MergeMiningClientTari::submit_solution(const std::vector<uint8_t>& blob, const std::vector<hash>& merkle_proof)
{
	(void)blob;
	(void)merkle_proof;
}

MergeMiningClientTari::gRPC_Client::gRPC_Client()
	: Client(m_buf, sizeof(m_buf))
{
	m_buf[0] = '\0';
}

void MergeMiningClientTari::gRPC_Client::reset()
{
	m_data.clear();
}

bool MergeMiningClientTari::gRPC_Client::on_connect()
{
	const MergeMiningClientTari::gRPC_Server* server = static_cast<MergeMiningClientTari::gRPC_Server*>(m_owner);
	if (server) {
		LOGINFO(4, "Connected to " << server->m_host << ':' << server->m_port);
	}

	return true;
}

bool MergeMiningClientTari::gRPC_Client::on_read(char* data, uint32_t size)
{
	const MergeMiningClientTari::gRPC_Server* server = static_cast<MergeMiningClientTari::gRPC_Server*>(m_owner);
	if (server) {
		LOGINFO(4, "Read " << size << " bytes from " << server->m_host << ':' << server->m_port);
		LOGINFO(4, log::hex_buf(data, size));
	}

	m_data.insert(m_data.end(), data, data + size);

	return true;
}

void MergeMiningClientTari::gRPC_Client::on_read_failed(int err)
{
	const MergeMiningClientTari::gRPC_Server* server = static_cast<MergeMiningClientTari::gRPC_Server*>(m_owner);
	if (server) {
		LOGERR(1, "Read from " << server->m_host << ':' << server->m_port << "failed, error " << err);
	}
}

void MergeMiningClientTari::gRPC_Client::on_disconnected()
{
	const MergeMiningClientTari::gRPC_Server* server = static_cast<MergeMiningClientTari::gRPC_Server*>(m_owner);
	if (server) {
		LOGINFO(4, "Disconnected from " << server->m_host << ':' << server->m_port);
	}
}

MergeMiningClientTari::gRPC_Server::gRPC_Server(const std::string& socks5Proxy)
	: TCPServer(1, MergeMiningClientTari::gRPC_Client::allocate, socks5Proxy)
	, m_port(0)
{
}

MergeMiningClientTari::gRPC_Server::~gRPC_Server()
{
}

bool MergeMiningClientTari::gRPC_Server::start(bool use_dns, const std::string& host, int port)
{
	const int err = uv_thread_create(&m_loopThread, loop, this);
	if (err) {
		LOGERR(1, "failed to start event loop thread, error " << uv_err_name(err));
		return false;
	}

	m_loopThreadCreated = true;

	m_host = host;
	m_port = port;

	std::string ip = host;
	bool is_v6 = host.find_first_of(':') != std::string::npos;

	if (!use_dns || resolve_host(ip, is_v6)) {
		if (!connect_to_peer(is_v6, ip.c_str(), port)) {
			LOGERR(1, "Failed to connect to " << host << ':' << port);
			return false;
		}
	}

	return true;
}

void MergeMiningClientTari::gRPC_Server::on_shutdown()
{
}

const char* MergeMiningClientTari::gRPC_Server::get_log_category() const
{
	return log_category_prefix;
}

} // namespace p2pool
