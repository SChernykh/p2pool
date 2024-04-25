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

LOG_CATEGORY(MergeMiningClientTari)

using namespace tari::rpc;

namespace p2pool {

MergeMiningClientTari::MergeMiningClientTari(p2pool* pool, std::string host, const std::string& wallet)
	: m_chainParams{}
	, m_auxWallet(wallet)
	, m_pool(pool)
	, m_server(new TariServer(pool->params().m_socks5Proxy))
	, m_hostStr(host)
	, m_workerStop(0)
{
	if (host.find(TARI_PREFIX) != 0) {
		LOGERR(1, "Invalid host " << host << " - \"" << TARI_PREFIX << "\" prefix not found");
		throw std::exception();
	}

	host.erase(0, sizeof(TARI_PREFIX) - 1);

	while (!host.empty() && (host.back() == '/')) {
		host.pop_back();
	}

	if (host.empty()) {
		LOGERR(1, "Invalid host");
		throw std::exception();
	}

	m_server->parse_address_list(host,
		[this](bool is_v6, const std::string& /*address*/, std::string ip, int port)
		{
			if (!m_pool->params().m_dns || resolve_host(ip, is_v6)) {
				m_server->m_TariNodeIsV6 = is_v6;
				m_server->m_TariNodeHost = ip;
				m_server->m_TariNodePort = port;
			}
		});

	if (m_server->m_TariNodeHost.empty() || (m_server->m_TariNodePort == 0) || (m_server->m_TariNodePort >= 65536)) {
		LOGERR(1, "Invalid host " << host);
		throw std::exception();
	}

	uv_rwlock_init_checked(&m_chainParamsLock);

	if (!m_server->start()) {
		throw std::exception();
	}

	char buf[32] = {};
	log::Stream s(buf);
	s << "127.0.0.1:" << m_server->external_listen_port();

	m_TariNode = new BaseNode::Stub(grpc::CreateChannel(buf, grpc::InsecureChannelCredentials()));

	uv_mutex_init_checked(&m_workerLock);
	uv_cond_init_checked(&m_workerCond);

	const int err = uv_thread_create(&m_worker, run_wrapper, this);
	if (err) {
		LOGERR(1, "failed to start worker thread, error " << uv_err_name(err));
		throw std::exception();
	}
}

MergeMiningClientTari::~MergeMiningClientTari()
{
	LOGINFO(1, "stopping");

	m_workerStop.exchange(1);
	{
		MutexLock lock(m_workerLock);
		uv_cond_signal(&m_workerCond);
	}
	uv_thread_join(&m_worker);

	m_server->shutdown_tcp();
	delete m_server;

	delete m_TariNode;

	uv_rwlock_destroy(&m_chainParamsLock);

	uv_mutex_destroy(&m_workerLock);
	uv_cond_destroy(&m_workerCond);

	LOGINFO(1, "stopped");
}

bool MergeMiningClientTari::get_params(ChainParameters& out_params) const
{
	ReadLock lock(m_chainParamsLock);

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

void MergeMiningClientTari::run_wrapper(void* arg)
{
	reinterpret_cast<MergeMiningClientTari*>(arg)->run();
	LOGINFO(1, "worker thread stopped");
}

void MergeMiningClientTari::run()
{
	LOGINFO(1, "worker thread ready");

	using namespace std::chrono;

	for (;;) {
		const auto t1 = high_resolution_clock::now();

		MutexLock lock(m_workerLock);

		LOGINFO(6, "Getting new block template from Tari node");

		GetNewBlockTemplateWithCoinbasesRequest request;
		PowAlgo* algo = new PowAlgo();
		algo->set_pow_algo(PowAlgo_PowAlgos_POW_ALGOS_RANDOMX);
		request.clear_algo();
		request.set_allocated_algo(algo);
		request.set_max_weight(1);

		NewBlockCoinbase* coinbase = request.add_coinbases();
		coinbase->set_address(m_auxWallet);

		// TODO this should be equal to the total weight of shares in the PPLNS window for each wallet
		coinbase->set_value(1);

		coinbase->set_stealth_payment(false);
		coinbase->set_revealed_value_proof(true);
		coinbase->clear_coinbase_extra();

		grpc::ClientContext ctx;
		GetNewBlockResult response;

		const grpc::Status status = m_TariNode->GetNewBlockTemplateWithCoinbases(&ctx, request, &response);

		if (!status.ok()) {
			LOGWARN(5, "GetNewBlockTemplateWithCoinbases failed: " << status.error_message());
			if (!status.error_details().empty()) {
				LOGWARN(5, "GetNewBlockTemplateWithCoinbases failed: " << status.error_details());
			}
		}
		else {
			bool aux_id_empty;
			{
				ReadLock lock2(m_chainParamsLock);
				aux_id_empty = m_chainParams.aux_id.empty();
			}

			if (aux_id_empty) {
				const std::string& id = response.tari_unique_id();
				LOGINFO(1, m_hostStr << " uses chain_id " << log::LightCyan() << log::hex_buf(id.data(), id.size()));

				if (id.size() == HASH_SIZE) {
					WriteLock lock2(m_chainParamsLock);
					std::copy(id.begin(), id.end(), m_chainParams.aux_id.h);
				}
				else {
					LOGERR(1, "Tari unique_id has invalid size (" << id.size() << ')');
				}
			}

			LOGINFO(6, "Tari block template: height = " << response.block().header().height()
				<< ", diff = " << response.miner_data().target_difficulty()
				<< ", reward = " << response.miner_data().reward()
				<< ", fees = " << response.miner_data().total_fees()
			);
		}

		const int64_t timeout = std::max<int64_t>(500'000'000 - duration_cast<nanoseconds>(high_resolution_clock::now() - t1).count(), 1'000'000);

		if ((m_workerStop.load() != 0) || (uv_cond_timedwait(&m_workerCond, &m_workerLock, timeout) != UV_ETIMEDOUT)) {
			return;
		}
	}
}

// TariServer and TariClient are simply a proxy from a localhost TCP port to the external Tari node
// This is needed for SOCKS5 proxy support (gRPC library doesn't support it natively)

MergeMiningClientTari::TariServer::TariServer(const std::string& socks5Proxy)
	: TCPServer(1, MergeMiningClientTari::TariClient::allocate, socks5Proxy)
	, m_TariNodeIsV6(false)
	, m_TariNodeHost()
	, m_TariNodePort(0)
	, m_internalPort(0)
{
	m_callbackBuf.resize(MergeMiningClientTari::BUF_SIZE);
}

bool MergeMiningClientTari::TariServer::start()
{
	std::random_device rd;

	for (size_t i = 0; i < 10; ++i) {
		if (start_listening(false, "127.0.0.1", 49152 + (rd() % 16384))) {
			break;
		}
	}

	if (m_listenPort < 0) {
		LOGERR(1, "failed to listen on TCP port");
		return false;
	}

	const int err = uv_thread_create(&m_loopThread, loop, this);
	if (err) {
		LOGERR(1, "failed to start event loop thread, error " << uv_err_name(err));
		return false;
	}

	m_loopThreadCreated = true;
	return true;
}

bool MergeMiningClientTari::TariServer::connect_upstream(TariClient* downstream)
{
	const bool is_v6 = m_TariNodeIsV6;
	const std::string& ip = m_TariNodeHost;
	const int port = m_TariNodePort;

	TariClient* upstream = static_cast<TariClient*>(get_client());

	upstream->m_owner = this;
	upstream->m_port = port;
	upstream->m_isV6 = is_v6;

	if (!str_to_ip(is_v6, ip.c_str(), upstream->m_addr)) {
		return_client(upstream);
		return false;
	}

	log::Stream s(upstream->m_addrString);
	if (is_v6) {
		s << '[' << ip << "]:" << port << '\0';
	}
	else {
		s << ip << ':' << port << '\0';
	}

	if (!connect_to_peer(upstream)) {
		return false;
	}

	upstream->m_pairedClient = downstream;
	upstream->m_pairedClientSavedResetCounter = downstream->m_resetCounter;

	return true;
}

void MergeMiningClientTari::TariServer::on_shutdown()
{
}

const char* MergeMiningClientTari::TariServer::get_log_category() const
{
	return log_category_prefix;
}

MergeMiningClientTari::TariClient::TariClient()
	: Client(m_buf, sizeof(m_buf))
	, m_pairedClient(nullptr)
	, m_pairedClientSavedResetCounter(std::numeric_limits<uint32_t>::max())
{
	m_buf[0] = '\0';
}

void MergeMiningClientTari::TariClient::reset()
{
	if (is_paired()) {
		m_pairedClient->m_pairedClient = nullptr;
		m_pairedClient->close();
		m_pairedClient = nullptr;
	}
	m_pairedClientSavedResetCounter = std::numeric_limits<uint32_t>::max();
}

bool MergeMiningClientTari::TariClient::on_connect()
{
	MergeMiningClientTari::TariServer* server = static_cast<MergeMiningClientTari::TariServer*>(m_owner);
	if (!server) {
		return false;
	}

	if (m_isIncoming) {
		return server->connect_upstream(this);
	}
	else {
		// The outgoing connection is ready now
		// Check if the incoming connection (downstream) has already sent something that needs to be relayed
		TariClient* downstream = m_pairedClient;
		downstream->m_pairedClient = this;
		downstream->m_pairedClientSavedResetCounter = m_resetCounter;

		const std::vector<uint8_t>& v = downstream->m_pendingData;

		if (!v.empty()) {
			const bool result = server->send(this,
				[&v](uint8_t* buf, size_t buf_size) -> size_t
				{
					if (v.size() > buf_size) {
						return 0U;
					}

					std::copy(v.begin(), v.end(), buf);
					return v.size();
				});

			downstream->m_pendingData.clear();
			return result;
		}
	}

	return true;
}

bool MergeMiningClientTari::TariClient::on_read(char* data, uint32_t size)
{
	MergeMiningClientTari::TariServer* server = static_cast<MergeMiningClientTari::TariServer*>(m_owner);
	if (!server) {
		return false;
	}

	if (!is_paired()) {
		LOGWARN(5, "Read " << size << " bytes from " << static_cast<char*>(m_addrString) << " but it's not paired yet. Buffering it.");
		m_pendingData.insert(m_pendingData.end(), data, data + size);
		return true;
	}

	return server->send(m_pairedClient,
		[data, size](uint8_t* buf, size_t buf_size) -> size_t
		{
			if (size > buf_size) {
				return 0U;
			}

			std::copy(data, data + size, buf);
			return size;
		});
}

} // namespace p2pool
