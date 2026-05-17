/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2026 SChernykh <https://github.com/SChernykh>
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
#include "p2pool.h"
#include "params.h"
#include "json_rpc_request.h"
#include "json_parsers.h"
#include "rapidjson_wrapper.h"

LOG_CATEGORY(MergeMiningClientJSON_RPC)

namespace p2pool {

MergeMiningClientJSON_RPC::MergeMiningClientJSON_RPC(p2pool* pool, const std::string& host, const std::string& wallet, const std::string& spkiFingerprint)
	: MergeMiningClientShared(pool, wallet)
	, m_host(host)
	, m_tls(false)
	, m_spkiFingerprint(spkiFingerprint)
	, m_port(80)
	, m_loop{}
	, m_loopThread{}
	, m_timer{}
	, m_getJobRunning(false)
	, m_shutdownAsync{}
{
	if (m_host.find(HTTPS_PREFIX) == 0) {
#ifdef WITH_TLS
		m_host.erase(0, sizeof(HTTPS_PREFIX) - 1);
		m_tls = true;
		m_port = 443;
#else
		LOGERR(1, "P2Pool was built without TLS support, can't connect to " << host);
		throw std::exception();
#endif
	}

	const size_t k = m_host.find_last_of(':');
	if (k != std::string::npos) {
		m_port = static_cast<int32_t>(strtoul(m_host.c_str() + k + 1, nullptr, 10));
		m_host.resize(k);

		// Handle IPv6 addresses
		if ((m_host.length() > 2) && (m_host.find_first_of(':') != std::string::npos) && (m_host.front() == '[') && (m_host.back() == ']')) {
			m_host.erase(m_host.begin());
			m_host.pop_back();
		}
	}

	if (m_host.empty() || (m_port <= 0) || (m_port >= 65536)) {
		LOGERR(1, "Invalid host " << host);
		throw std::exception();
	}

	int err = uv_loop_init(&m_loop);
	if (err) {
		LOGERR(1, "failed to create event loop, error " << uv_err_name(err));
		throw std::exception();
	}

	// Init loop user data before running it
	GetLoopUserData(&m_loop);

	err = uv_async_init(&m_loop, &m_shutdownAsync, on_shutdown);
	if (err) {
		LOGERR(1, "uv_async_init failed, error " << uv_err_name(err));
		uv_loop_close(&m_loop);
		throw std::exception();
	}
	m_shutdownAsync.data = this;

	err = uv_timer_init(&m_loop, &m_timer);
	if (err) {
		LOGERR(1, "failed to create timer, error " << uv_err_name(err));
		uv_loop_close(&m_loop);
		throw std::exception();
	}
	m_timer.data = this;

	err = uv_thread_create(&m_loopThread, loop, this);
	if (err) {
		LOGERR(1, "failed to start event loop thread, error " << uv_err_name(err));
		uv_loop_close(&m_loop);
		throw std::exception();
	}

	merge_mining_get_chain_id();
}

MergeMiningClientJSON_RPC::~MergeMiningClientJSON_RPC()
{
	uv_async_send(&m_shutdownAsync);
	uv_thread_join(&m_loopThread);

	LOGINFO(1, "stopped");
}

void MergeMiningClientJSON_RPC::on_timer()
{
	if (m_pool->stopped()) {
		return;
	}

	MinerData data = m_pool->miner_data();
	merge_mining_get_aux_block(data.height, data.prev_id, m_auxWallet);
}

void MergeMiningClientJSON_RPC::merge_mining_get_chain_id()
{
	const std::string req = "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"merge_mining_get_chain_id\"}";

	JSONRPCRequest::call(m_host, m_port, req, std::string(), m_pool->params().m_socks5Proxy, m_tls, m_spkiFingerprint,
		[this](const JSONRPCRequest::CallbackData& data) {
			WriteLock lock(m_chainParamsLock);

			if (parse_merge_mining_get_chain_id(data.m_response.data(), data.m_response.size())) {
				LOGINFO(1, m_host << ':' << m_port << " uses chain_id " << log::LightCyan() << m_chainParams.aux_id);

				if (data.m_ping > 0.0) {
					LOGINFO(1, m_host << ':' << m_port << " ping is " << data.m_ping << " ms");
				}

#ifdef WITH_TLS
				if (!data.m_spkiFingerprint.empty()) {
					LOGINFO(1, m_host << ':' << m_port << " fingerprint is " << data.m_spkiFingerprint);
				}
#endif

				// Chain ID received successfully, we can start polling for new mining jobs now
				const int err = uv_timer_start(&m_timer, on_timer, 0, 500);
				if (err) {
					LOGERR(1, "failed to start timer, error " << uv_err_name(err));
				}
			}
		},
		[this](const JSONRPCRequest::CallbackData& data) {
			if (!data.m_error.empty()) {
				LOGERR(1, "couldn't get merge mining id from " << m_host << ':' << m_port << ", error " << data.m_error);
			}
		}, &m_loop);
}

bool MergeMiningClientJSON_RPC::parse_merge_mining_get_chain_id(const char* data, size_t size)
{
	auto err = [this](const char* msg) {
		LOGWARN(3, "merge_mining_get_chain_id RPC call failed: " << msg << ". Trying again in 1 second.");
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		merge_mining_get_chain_id();
		return false;
	};

	rapidjson::Document doc;

	if (doc.Parse(data, size).HasParseError() || !doc.IsObject()) {
		return err("parsing failed");
	}

	if (doc.HasMember("error")) {
		return err(doc["error"].IsString() ? doc["error"].GetString() : "an unknown error occurred");
	}

	if (!doc.HasMember("result")) {
		return err("\"result\" field not found");
	}

	const auto& result = doc["result"];

	if (!result.IsObject() || !result.HasMember("chain_id")) {
		return err("couldn't parse result");
	}

	const auto& chain_id = result["chain_id"];

	if (!chain_id.IsString() || !from_hex(chain_id.GetString(), chain_id.GetStringLength(), m_chainParams.aux_id)) {
		return err("invalid chain_id");
	}

	return true;
}

void MergeMiningClientJSON_RPC::merge_mining_get_aux_block(uint64_t height, const hash& prev_id, const std::string& wallet)
{
	if (m_getJobRunning) {
		return;
	}

	m_getJobRunning = true;

	char buf[log::Stream::BUF_SIZE + 1];
	// cppcheck-suppress uninitvar
	log::Stream s(buf);

	hash aux_hash;
	{
		ReadLock lock(m_chainParamsLock);
		aux_hash = m_chainParams.aux_hash;
	}

	s << "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"merge_mining_get_aux_block\",\"params\":{"
	  << "\"address\":\"" << wallet << '"'
	  << ",\"aux_hash\":\"" << aux_hash << '"'
	  << ",\"height\":" << height
	  << ",\"prev_id\":\"" << prev_id << '"'
	  << "}}";

	JSONRPCRequest::call(m_host, m_port, std::string(buf, s.m_pos), std::string(), m_pool->params().m_socks5Proxy, m_tls, m_spkiFingerprint,
		[this](const JSONRPCRequest::CallbackData& data) {
			bool changed = false;
			hash chain_id;

			hash prev_aux_hash;
			std::vector<uint8_t> prev_aux_blob;
			{
				WriteLock lock(m_chainParamsLock);

				prev_aux_hash = m_chainParams.aux_hash;
				prev_aux_blob = m_chainParams.aux_blob;

				if (parse_merge_mining_get_aux_block(data.m_response.data(), data.m_response.size(), changed)) {
					chain_id = m_chainParams.aux_id;
				}
			}

			if (changed && !chain_id.empty()) {
				{
					WriteLock lock(m_chainParamsLock);

					const uint32_t index = (m_previousAuxHashesIndex++) % NUM_PREVIOUS_HASHES;

					m_previousAuxHashes[index] = prev_aux_hash;
					m_previousAuxBlobs[index] = prev_aux_blob;
				}

				m_pool->update_aux_data(chain_id);
			}
		},
		[this](const JSONRPCRequest::CallbackData& data) {
			if (!data.m_error.empty()) {
				LOGERR(3, "couldn't get merge mining job from " << m_host << ':' << m_port << ", error " << data.m_error);
			}
			m_getJobRunning = false;
		}, &m_loop);
}

bool MergeMiningClientJSON_RPC::parse_merge_mining_get_aux_block(const char* data, size_t size, bool& changed)
{
	auto err = [](const char* msg) {
		LOGWARN(3, "merge_mining_get_aux_block RPC call failed: " << msg);
		return false;
	};

	rapidjson::Document doc;

	if (doc.Parse(data, size).HasParseError() || !doc.IsObject()) {
		return err("parsing failed");
	}

	if (doc.HasMember("error")) {
		return err(doc["error"].IsString() ? doc["error"].GetString() : "an unknown error occurred");
	}

	if (!doc.HasMember("result")) {
		return err("\"result\" field not found");
	}

	const auto& result = doc["result"];

	if (!result.IsObject()) {
		return err("couldn't parse result");
	}

	if (!result.HasMember("aux_hash")) {
		return true;
	}

	const auto& aux_hash = result["aux_hash"];

	hash h;
	if (!aux_hash.IsString() || !from_hex(aux_hash.GetString(), aux_hash.GetStringLength(), h)) {
		return err("invalid aux_hash");
	}

	if (h == m_chainParams.aux_hash) {
		return true;
	}

	std::vector<uint8_t> aux_blob;

	if (!result.HasMember("aux_blob") || !result["aux_blob"].IsString() || !from_hex(result["aux_blob"].GetString(), result["aux_blob"].GetStringLength(), aux_blob)) {
		return err("invalid aux_blob");
	}

	if (!result.HasMember("aux_diff") || !result["aux_diff"].IsUint64()) {
		return err("invalid aux_diff");
	}

	m_chainParams.aux_blob = std::move(aux_blob);
	m_chainParams.aux_hash = h;
	m_chainParams.aux_diff.lo = result["aux_diff"].GetUint64();
	m_chainParams.aux_diff.hi = 0;
	m_chainParams.last_updated = seconds_since_epoch();

	m_chainParamsTimestamp = time(nullptr);

	changed = true;

	return true;
}

void MergeMiningClientJSON_RPC::submit_solution(const std::vector<uint8_t>& /*coinbase_merkle_proof*/, const uint8_t (&/*hashing_blob*/)[HASHING_BLOB_MAX_SIZE], size_t /*nonce_offset*/, const hash& seed_hash, const std::vector<uint8_t>& blob, const std::vector<hash>& merkle_proof, uint32_t merkle_proof_path)
{
	ReadLock lock(m_chainParamsLock);

	const uint32_t index = m_previousAuxHashesFoundIndex.exchange(std::numeric_limits<uint32_t>::max());

	const std::vector<uint8_t>& aux_blob = (index < NUM_PREVIOUS_HASHES) ? m_previousAuxBlobs[index] : m_chainParams.aux_blob;
	const hash& aux_hash = (index < NUM_PREVIOUS_HASHES) ? m_previousAuxHashes[index] : m_chainParams.aux_hash;

	std::vector<char> buf((aux_blob.size() + HASH_SIZE + blob.size()) * 2 + merkle_proof.size() * (HASH_SIZE * 2 + 3) + 256);
	log::Stream s(buf.data(), buf.size());

	s << "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"merge_mining_submit_solution\",\"params\":{"
		<< "\"aux_blob\":\"" << log::hex_buf(aux_blob.data(), aux_blob.size()) << '"'
		<< ",\"aux_hash\":\"" << aux_hash << '"'
		<< ",\"blob\":\"" << log::hex_buf(blob.data(), blob.size()) << '"'
		<< ",\"merkle_proof\":[";

	for (size_t i = 0, n = merkle_proof.size(); i < n; ++i) {
		if (i != 0) {
			s << ',';
		}
		s << '"' << merkle_proof[i] << '"';
	}

	s << "],\"path\":" << merkle_proof_path
		<< ",\"seed_hash\":\"" << seed_hash << "\"}}";

	JSONRPCRequest::call(m_host, m_port, std::string(buf.data(), s.m_pos), std::string(), m_pool->params().m_socks5Proxy, m_tls, m_spkiFingerprint,
		[this](const JSONRPCRequest::CallbackData& data) {
			parse_merge_mining_submit_solution(data.m_response.data(), data.m_response.size());
		},
		[this](const JSONRPCRequest::CallbackData& data) {
			if (!data.m_error.empty()) {
				LOGERR(3, "couldn't submit merge mining solution to " << m_host << ':' << m_port << ", error " << data.m_error);
			}
			// Get new mining job
			on_timer();
		}, &m_loop);
}

void MergeMiningClientJSON_RPC::print_status() const
{
	ReadLock lock(m_chainParamsLock);

	LOGINFO(0, "status" <<
		"\nHost       = " << m_host << ':' << m_port <<
		"\nWallet     = " << m_auxWallet <<
		"\nDifficulty = " << m_chainParams.aux_diff
	);
}

void MergeMiningClientJSON_RPC::api_status(log::Stream& s) const
{
	ReadLock lock(m_chainParamsLock);

	s << '{'
		<< "\"api\":\"JSON RPC\","
		<< "\"id\":\"" << m_chainParams.aux_id << "\","
		<< "\"host\":\"" << m_host << ':' << m_port << "\","
		<< "\"wallet\":\"" << m_auxWallet << "\","
		<< "\"difficulty\":" << m_chainParams.aux_diff << ","
		<< "\"timestamp\":" << m_chainParamsTimestamp
		<< '}';
}

bool MergeMiningClientJSON_RPC::get_params(ChainParameters& out_params) const
{
	const uint64_t t = seconds_since_epoch();

	ReadLock lock(m_chainParamsLock);

	if (m_chainParams.aux_id.empty() || m_chainParams.aux_diff.empty()) {
		return false;
	}

	if (t >= m_chainParams.last_updated + ChainParameters::EXPIRE_TIME) {
		LOGWARN(4, m_host << ':' << m_port << " merge mining data is outdated (" << (t - m_chainParams.last_updated) << " seconds old)");
		return false;
	}

	out_params = m_chainParams;
	return true;
}

bool MergeMiningClientJSON_RPC::parse_merge_mining_submit_solution(const char* data, size_t size) const
{
	auto err = [this](const char* msg) {
		LOGWARN(3, "merge_mining_submit_solution to " << m_host << ':' << m_port << " failed: " << msg);
		return false;
	};

	rapidjson::Document doc;

	if (doc.Parse(data, size).HasParseError() || !doc.IsObject()) {
		return err("parsing failed");
	}

	if (doc.HasMember("error")) {
		const auto& error_result = doc["error"];

		if (error_result.IsString()) {
			return err(error_result.GetString());
		}
		if (error_result.IsObject() && error_result.HasMember("message") && error_result["message"].IsString()) {
			return err(error_result["message"].GetString());
		}
		return err("an unknown error occurred");
	}

	if (!doc.HasMember("result")) {
		return err("\"result\" field not found");
	}

	const auto& result = doc["result"];

	if (!result.IsObject()) {
		return err("couldn't parse result");
	}

	if (!result.HasMember("status") || !result["status"].IsString()) {
		return err("invalid status");
	}

	const char* status = result["status"].GetString();

	// Empty string means no errors and the block was accepted
	if (status[0] == '\0') {
		status = "accepted";
	}

	LOGINFO(0, log::LightGreen() << "merge_mining_submit_solution to " << m_host << ':' << m_port << ": " << status);
	return true;
}

void MergeMiningClientJSON_RPC::loop(void* data)
{
	LOGINFO(1, "event loop started");

	set_thread_name("MM JSON RPC");

	MergeMiningClientJSON_RPC* client = static_cast<MergeMiningClientJSON_RPC*>(data);

	int err = uv_run(&client->m_loop, UV_RUN_DEFAULT);
	if (err) {
		LOGWARN(1, "uv_run returned " << err);
	}

	err = uv_loop_close(&client->m_loop);
	if (err) {
		LOGWARN(1, "uv_loop_close returned error " << uv_err_name(err));
	}

	LOGINFO(1, "event loop stopped");
}

void MergeMiningClientJSON_RPC::on_shutdown()
{
	uv_timer_stop(&m_timer);
	uv_close(reinterpret_cast<uv_handle_t*>(&m_timer), nullptr);
}

const char* MergeMiningClientJSON_RPC::get_log_category() const
{
	return log_category_prefix;
}

} // namespace p2pool
