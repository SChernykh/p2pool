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

MergeMiningClient::MergeMiningClient(p2pool* pool, const std::string& host, const std::string& address)
	: m_host(host)
	, m_port(80)
	, m_auxAddress(address)
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
		m_port = strtoul(host.substr(k + 1).c_str(), nullptr, 10);
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

	LOGINFO(1, "stopped");
}

void MergeMiningClient::on_timer()
{
	MinerData data = m_pool->miner_data();
	merge_mining_get_job(data.height, data.prev_id, m_auxAddress, m_auxHash);
}

void MergeMiningClient::merge_mining_get_chain_id()
{
	constexpr char req[] = "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"merge_mining_get_chain_id\"}";

	JSONRPCRequest::call(m_host, m_port, req, std::string(), m_pool->params().m_socks5Proxy,
		[this](const char* data, size_t size, double) {
			if (parse_merge_mining_get_chain_id(data, size)) {
				const int err = uv_timer_start(&m_timer, on_timer, 0, 500);
				if (err) {
					LOGERR(1, "failed to start timer, error " << uv_err_name(err));
				}
			}
		},
		[](const char* data, size_t size, double) {
			if (size > 0) {
				LOGERR(1, "couldn't get merge mining id, error " << log::const_buf(data, size));
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

void MergeMiningClient::merge_mining_get_job(uint64_t height, const hash& prev_id, const std::string& address, const hash& aux_hash)
{
	if (m_getJobRunning) {
		return;
	}

	m_getJobRunning = true;

	char buf[log::Stream::BUF_SIZE + 1];
	log::Stream s(buf);

	s << "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"merge_mining_get_job\",\"params\":{"
	  << "\"address\":\"" << address << '"'
	  << ",\"aux_hash\":\"" << aux_hash << '"'
	  << ",\"height\":" << height
	  << ",\"prev_id\":\"" << prev_id << '"'
	  << "}}\0";

	JSONRPCRequest::call(m_host, m_port, buf, std::string(), m_pool->params().m_socks5Proxy,
		[this](const char* data, size_t size, double) {
			parse_merge_mining_get_job(data, size);
		},
		[this](const char* data, size_t size, double) {
			if (size > 0) {
				LOGERR(1, "couldn't get merge mining job, error " << log::const_buf(data, size));
			}
			m_getJobRunning = false;
		}, &m_loop);
}

bool MergeMiningClient::parse_merge_mining_get_job(const char* data, size_t size)
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

	if (!result.HasMember("aux_blob") || !result["aux_blob"].IsString()) {
		return err("invalid aux_blob");
	}

	if (!result.HasMember("aux_diff") || !result["aux_diff"].IsUint64()) {
		return err("invalid aux_diff");
	}

	m_auxBlob = result["aux_blob"].GetString();
	m_auxHash = h;
	m_auxDiff.lo = result["aux_diff"].GetUint64();
	m_auxDiff.hi = 0;

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
