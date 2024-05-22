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
#include "block_template.h"
#include "keccak.h"

LOG_CATEGORY(MergeMiningClientTari)

using namespace tari::rpc;

namespace p2pool {

MergeMiningClientTari::MergeMiningClientTari(p2pool* pool, std::string host, const std::string& wallet)
	: m_chainParams{}
	, m_auxWallet(wallet)
	, m_pool(pool)
	, m_tariJobParams{}
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

void MergeMiningClientTari::submit_solution(const BlockTemplate* block_tpl, const uint8_t (&hashing_blob)[128], size_t nonce_offset, const hash& seed_hash, const std::vector<uint8_t>& blob, const std::vector<hash>& merkle_proof, uint32_t merkle_proof_path)
{
	Block block;
	{
		ReadLock lock(m_chainParamsLock);
		block = m_tariBlock;
	}

	ProofOfWork* pow = block.mutable_header()->mutable_pow();
	pow->set_pow_algo(PowAlgo_PowAlgos_POW_ALGOS_RANDOMX);

	{
		std::string data;

		// Monero header + nonce
		data.append(reinterpret_cast<const char*>(blob.data()), nonce_offset + sizeof(uint32_t));

		// Monero seed
		data.append(1, HASH_SIZE);
		data.append(reinterpret_cast<const char*>(seed_hash.h), HASH_SIZE);

		uint64_t transaction_count;
		if (!readVarint(hashing_blob + nonce_offset + sizeof(uint32_t) + HASH_SIZE, hashing_blob + sizeof(hashing_blob), transaction_count)) {
			return;
		}

		if (transaction_count > std::numeric_limits<uint16_t>::max()) {
			return;
		}

		// Total number of transactions in this block (including the miner tx)
		data.append(reinterpret_cast<const char*>(&transaction_count), sizeof(uint16_t));

		// Tx Merkle tree root
		data.append(reinterpret_cast<const char*>(hashing_blob + nonce_offset + sizeof(uint32_t)), HASH_SIZE);

		// Coinbase transaction's Merkle proof
		const std::vector<uint8_t> coinbase_merkle_proof = block_tpl->get_coinbase_merkle_proof();

		// Number of hashes in the proof (varint, but an O(logN) proof will never get bigger than 127)
		data.append(1, static_cast<char>(coinbase_merkle_proof.size() / HASH_SIZE));

		// Hashes in the proof
		data.append(reinterpret_cast<const char*>(coinbase_merkle_proof.data()), coinbase_merkle_proof.size());

		// Path bitmap (always 0 for the coinbase tx)
		data.append(1, 0);

		// coinbase_tx_hasher
		const uint8_t* coinbase_tx = blob.data() + nonce_offset + sizeof(uint32_t);

		const uint8_t* p = coinbase_tx;
		const uint8_t* e = blob.data() + blob.size();

		uint64_t k;

		p += 1; // TX_VERSION
		p = readVarint(p, e, k); if (!p) return; // unlock height
		p += 2; // '1', TXIN_GEN
		p = readVarint(p, e, k); if (!p) return; // txinGenHeight
		p = readVarint(p, e, k); if (!p) return; // num_outputs

		for (uint64_t i = 0; i < k; ++i) {
			uint64_t reward;
			p = readVarint(p, e, reward); if (!p) return;
			p += 1 + HASH_SIZE + 1; // tx_type, public key, view tag
		}

		std::array<uint64_t, 25> keccak_state = {};

		size_t offset = p - coinbase_tx;

		uint32_t tx_extra_size;
		p = readVarint(p, e, tx_extra_size); if (!p) return;

		const uint8_t* tx_extra_begin = p;
		p = coinbase_tx;

		while (offset >= KeccakParams::HASH_DATA_AREA) {
			for (size_t i = 0; i < KeccakParams::HASH_DATA_AREA / sizeof(uint64_t); ++i) {
				keccak_state[i] ^= read_unaligned(reinterpret_cast<const uint64_t*>(p) + i);
			}
			keccakf(keccak_state);
			p += KeccakParams::HASH_DATA_AREA;
			offset -= KeccakParams::HASH_DATA_AREA;
		}

		for (size_t i = 0; i < offset; ++i, ++p) {
			reinterpret_cast<uint8_t*>(keccak_state.data())[i] ^= *p;
		}

		// coinbase_tx_hasher.buffer
		data.append(reinterpret_cast<const char*>(keccak_state.data()), sizeof(keccak_state));

		// coinbase_tx_hasher.offset
		data.append(1, static_cast<uint8_t>(offset));

		// coinbase_tx_hasher.rate
		data.append(1, static_cast<uint8_t>(KeccakParams::HASH_DATA_AREA));

		// coinbase_tx_hasher.mode
		data.append(1, 1);

		// coinbase_tx_extra
		data.append(reinterpret_cast<const char*>(&tx_extra_size), sizeof(tx_extra_size));
		data.append(reinterpret_cast<const char*>(tx_extra_begin), tx_extra_size);

		// aux_chain_merkle_proof
		data.append(1, static_cast<char>(merkle_proof.size()));
		data.append(reinterpret_cast<const char*>(merkle_proof.data()), merkle_proof.size() * HASH_SIZE);
		writeVarint(merkle_proof_path, [&data](uint8_t value) { data.append(1, value); });

		pow->set_pow_data(data);
	}

	grpc::ClientContext ctx;
	SubmitBlockResponse response;

	const grpc::Status status = m_TariNode->SubmitBlock(&ctx, block, &response);

	if (!status.ok()) {
		LOGWARN(5, "SubmitBlock failed: " << status.error_message());
		if (!status.error_details().empty()) {
			LOGWARN(5, "SubmitBlock failed: " << status.error_details());
		}
	}
	else {
		const std::string& h = response.block_hash();
		LOGINFO(0, log::LightGreen() << "Mined Tari block " << log::hex_buf(h.data(), h.size()) << " at height " << block.header().height());
	}
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

		GetNewBlockTemplateWithCoinbasesRequest request;
		PowAlgo* algo = new PowAlgo();
		algo->set_pow_algo(PowAlgo_PowAlgos_POW_ALGOS_RANDOMX);
		request.clear_algo();
		request.set_allocated_algo(algo);
		request.set_max_weight(0);

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
			const std::string& id = response.tari_unique_id();
			const std::string& mm_hash = response.merge_mining_hash();

			bool ok = true;

			if (id.size() != HASH_SIZE) {
				LOGERR(1, "Tari unique_id has invalid size (" << id.size() << ')');
				ok = false;
			}

			if (mm_hash.size() != HASH_SIZE) {
				LOGERR(1, "Tari merge mining hash has invalid size (" << mm_hash.size() << ')');
				ok = false;
			}

			if (ok) {
				TariJobParams job_params;

				job_params.height = response.block().header().height();
				job_params.diff = response.miner_data().target_difficulty();
				job_params.reward = response.miner_data().reward();
				job_params.fees = response.miner_data().total_fees();

				hash chain_id;
				{
					WriteLock lock2(m_chainParamsLock);

					if (job_params != m_tariJobParams) {
						m_tariJobParams = job_params;

						if (m_chainParams.aux_id.empty()) {
							LOGINFO(1, m_hostStr << " uses chain_id " << log::LightCyan() << log::hex_buf(id.data(), id.size()));
							std::copy(id.begin(), id.end(), m_chainParams.aux_id.h);
						}

						chain_id = m_chainParams.aux_id;

						std::copy(mm_hash.begin(), mm_hash.end(), m_chainParams.aux_hash.h);
						m_chainParams.aux_diff = static_cast<difficulty_type>(response.miner_data().target_difficulty());

						m_tariBlock = response.block();

						LOGINFO(5, "Tari block template: height = " << job_params.height
							<< ", diff = " << job_params.diff
							<< ", reward = " << job_params.reward
							<< ", fees = " << job_params.fees
							<< ", hash = " << log::hex_buf(mm_hash.data(), mm_hash.size())
						);
					}
				}

				if (!chain_id.empty()) {
					m_pool->update_aux_data(chain_id);
				}
			}
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
