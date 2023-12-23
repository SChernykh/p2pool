/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2023 SChernykh <https://github.com/SChernykh>
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
#include "p2pool.h"
#include "params.h"
#include "json_rpc_request.h"
#include "json_parsers.h"
#include <rapidjson/document.h>

LOG_CATEGORY(MergeMiningClient)

namespace p2pool {

MergeMiningClient::MergeMiningClient(p2pool* pool, const std::string& host, const std::string& wallet)
	: m_host(host)
	, m_port(80)
	, m_auxWallet(wallet)
	, m_ping(0.0)
	, m_pool(pool)
	, m_loop{}
	, m_loopThread{}
	, m_timer{}
	, m_getJobRunning(false)
	, m_shutdownAsync{}
{
	const size_t k = host.find_last_of(':');
	if (k != std::string::npos) {
		m_host = host.substr(0, k);
		m_port = std::stoul(host.substr(k + 1), nullptr, 10);
	}

	if (m_host.empty() || (m_port == 0) || (m_port >= 65536)) {
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

	uv_rwlock_init_checked(&m_lock);

	err = uv_thread_create(&m_loopThread, loop, this);
	if (err) {
		LOGERR(1, "failed to start event loop thread, error " << uv_err_name(err));
		uv_loop_close(&m_loop);
		throw std::exception();
	}

	merge_mining_get_chain_id();
}

MergeMiningClient::~MergeMiningClient()
{
	uv_async_send(&m_shutdownAsync);
	uv_thread_join(&m_loopThread);

	uv_rwlock_destroy(&m_lock);

	LOGINFO(1, "stopped");
}

void MergeMiningClient::on_timer()
{
	MinerData data = m_pool->miner_data();
	merge_mining_get_job(data.height, data.prev_id, m_auxWallet, aux_data());
}

void MergeMiningClient::merge_mining_get_chain_id()
{
	const std::string req = "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"merge_mining_get_chain_id\"}";

	JSONRPCRequest::call(m_host, m_port, req, std::string(), m_pool->params().m_socks5Proxy,
		[this](const char* data, size_t size, double ping) {
			WriteLock lock(m_lock);

			if (parse_merge_mining_get_chain_id(data, size)) {
				if (ping > 0.0) {
					m_ping = ping;
				}

				LOGINFO(1, m_host << ':' << m_port << " uses chain_id " << log::LightCyan() << m_chainID);
				LOGINFO(1, m_host << ':' << m_port << " ping is " << m_ping << " ms");

				// Chain ID received successfully, we can start polling for new mining jobs now
				const int err = uv_timer_start(&m_timer, on_timer, 0, 500);
				if (err) {
					LOGERR(1, "failed to start timer, error " << uv_err_name(err));
				}
			}
		},
		[this](const char* data, size_t size, double) {
			if (size > 0) {
				LOGERR(1, "couldn't get merge mining id from " << m_host << ':' << m_port << ", error " << log::const_buf(data, size));
			}
		}, &m_loop);
}

bool MergeMiningClient::parse_merge_mining_get_chain_id(const char* data, size_t size)
{
	auto err = [this](const char* msg) {
		LOGWARN(1, "merge_mining_get_chain_id RPC call failed: " << msg << ". Trying again in 1 second.");
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

	const auto& result = doc["result"];

	if (!result.IsObject() || !result.HasMember("chain_id")) {
		return err("couldn't parse result");
	}

	const auto& chain_id = result["chain_id"];

	if (!chain_id.IsString() || !from_hex(chain_id.GetString(), chain_id.GetStringLength(), m_chainID)) {
		return err("invalid chain_id");
	}

	return true;
}

void MergeMiningClient::merge_mining_get_job(uint64_t height, const hash& prev_id, const std::string& wallet, const hash& aux_hash)
{
	if (m_getJobRunning) {
		return;
	}

	m_getJobRunning = true;

	char buf[log::Stream::BUF_SIZE + 1];
	// cppcheck-suppress uninitvar
	log::Stream s(buf);

	s << "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"merge_mining_get_job\",\"params\":{"
	  << "\"address\":\"" << wallet << '"'
	  << ",\"aux_hash\":\"" << aux_hash << '"'
	  << ",\"height\":" << height
	  << ",\"prev_id\":\"" << prev_id << '"'
	  << "}}";

	JSONRPCRequest::call(m_host, m_port, std::string(buf, s.m_pos), std::string(), m_pool->params().m_socks5Proxy,
		[this](const char* data, size_t size, double) {
			bool changed = false;
			hash chain_id;

			{
				WriteLock lock(m_lock);
				if (parse_merge_mining_get_job(data, size, changed)) {
					chain_id = m_chainID;
				}
			}

			if (changed && !chain_id.empty()) {
				m_pool->update_aux_data(chain_id);
			}
		},
		[this](const char* data, size_t size, double) {
			if (size > 0) {
				LOGERR(1, "couldn't get merge mining job from " << m_host << ':' << m_port << ", error " << log::const_buf(data, size));
			}
			m_getJobRunning = false;
		}, &m_loop);
}

bool MergeMiningClient::parse_merge_mining_get_job(const char* data, size_t size, bool& changed)
{
	auto err = [](const char* msg) {
		LOGWARN(1, "merge_mining_get_job RPC call failed: " << msg);
		return false;
	};

	rapidjson::Document doc;

	if (doc.Parse(data, size).HasParseError() || !doc.IsObject()) {
		return err("parsing failed");
	}

	if (doc.HasMember("error")) {
		return err(doc["error"].IsString() ? doc["error"].GetString() : "an unknown error occurred");
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

	if (h == m_auxHash) {
		return true;
	}

	std::vector<uint8_t> aux_blob;

	if (!result.HasMember("aux_blob") || !result["aux_blob"].IsString() || !from_hex(result["aux_blob"].GetString(), result["aux_blob"].GetStringLength(), aux_blob)) {
		return err("invalid aux_blob");
	}

	if (!result.HasMember("aux_diff") || !result["aux_diff"].IsUint64()) {
		return err("invalid aux_diff");
	}

	m_auxBlob = std::move(aux_blob);
	m_auxHash = h;
	m_auxDiff.lo = result["aux_diff"].GetUint64();
	m_auxDiff.hi = 0;

	changed = true;

	return true;
}

void MergeMiningClient::merge_mining_submit_solution(const std::vector<uint8_t>& blob, const std::vector<hash>& merkle_proof)
{
	ReadLock lock(m_lock);

	std::vector<char> buf((m_auxBlob.size() + HASH_SIZE + blob.size()) * 2 + merkle_proof.size() * (HASH_SIZE * 2 + 3) + 256);
	log::Stream s(buf.data(), buf.size());

	s << "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"merge_mining_submit_solution\",\"params\":{"
		<< "\"aux_blob\":\"" << log::hex_buf(m_auxBlob.data(), m_auxBlob.size()) << '"'
		<< ",\"aux_hash\":\"" << m_auxHash << '"'
		<< ",\"blob\":\"" << log::hex_buf(blob.data(), blob.size()) << '"'
		<< ",\"merkle_proof\":[";

	for (size_t i = 0, n = merkle_proof.size(); i < n; ++i) {
		if (i > 0) {
			s << ',';
		}
		s << '"' << merkle_proof[i] << '"';
	}

	s << "]}}";

	JSONRPCRequest::call(m_host, m_port, std::string(buf.data(), s.m_pos), std::string(), m_pool->params().m_socks5Proxy,
		[this](const char* data, size_t size, double) {
			parse_merge_mining_submit_solution(data, size);
		},
		[this](const char* data, size_t size, double) {
			if (size > 0) {
				LOGERR(1, "couldn't submit merge mining solution to " << m_host << ':' << m_port << ", error " << log::const_buf(data, size));
			}
		}, &m_loop);
}

bool MergeMiningClient::parse_merge_mining_submit_solution(const char* data, size_t size)
{
	auto err = [this](const char* msg) {
		LOGWARN(1, "merge_mining_submit_solution to " << m_host << ':' << m_port << " failed: " << msg);
		return false;
	};

	rapidjson::Document doc;

	if (doc.Parse(data, size).HasParseError() || !doc.IsObject()) {
		return err("parsing failed");
	}

	if (doc.HasMember("error")) {
		return err(doc["error"].IsString() ? doc["error"].GetString() : "an unknown error occurred");
	}

	const auto& result = doc["result"];

	if (!result.IsObject()) {
		return err("couldn't parse result");
	}

	if (!result.HasMember("status") || !result["status"].IsString()) {
		return err("invalid status");
	}

	const char* status = result["status"].GetString();
	LOGINFO(0, log::LightGreen() << "merge_mining_submit_solution to " << m_host << ':' << m_port << ": " << status);

	// Get new mining job
	on_timer();

	return true;
}

void MergeMiningClient::loop(void* data)
{
	LOGINFO(1, "event loop started");

	MergeMiningClient* client = static_cast<MergeMiningClient*>(data);

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

void MergeMiningClient::on_shutdown()
{
	uv_timer_stop(&m_timer);
	uv_close(reinterpret_cast<uv_handle_t*>(&m_timer), nullptr);
}

} // namespace p2pool
