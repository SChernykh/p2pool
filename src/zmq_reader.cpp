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
#include "zmq_reader.h"
#include "json_parsers.h"
#include <rapidjson/document.h>

static constexpr char log_category_prefix[] = "ZMQReader ";

namespace p2pool {

ZMQReader::ZMQReader(const std::string& address, uint32_t zmq_port, const std::string& proxy, MinerCallbackHandler* handler)
	: m_address(address)
	, m_zmqPort(zmq_port)
	, m_proxy(proxy)
	, m_handler(handler)
	, m_tx()
	, m_minerData()
	, m_chainmainData()
{
	if (!m_proxy.empty() && is_localhost(address)) {
		LOGINFO(5, "not using proxy to connect to localhost address " << log::Gray() << address);
		m_proxy.clear();
	}

	for (uint32_t i = m_publisherPort; i < std::numeric_limits<uint16_t>::max(); ++i) {
		try {
			m_publisherPort = 0;

			char addr[32];
			snprintf(addr, sizeof(addr), "tcp://127.0.0.1:%u", i);
			m_publisher.bind(addr);
			m_publisherPort = static_cast<uint16_t>(i);
			break;
		}
		catch (const std::exception& e) {
			LOGWARN(1, "failed to to bind port " << i << " for ZMQ publisher, error " << e.what());
		}
	}

	if (!m_publisherPort) {
		LOGERR(1, "failed to to bind ZMQ publisher port, aborting");
		throw zmq::error_t(EFSM);
	}

	const int err = uv_thread_create(&m_worker, run_wrapper, this);
	if (err) {
		LOGERR(1, "failed to start ZMQ thread, error " << uv_err_name(err));
		throw zmq::error_t(EFSM);
	}
}

ZMQReader::~ZMQReader()
{
	LOGINFO(1, "stopping");

	m_finished.exchange(1);

	try {
		const char msg[] = "json-minimal-txpool_add:[]";
		m_publisher.send(zmq::const_buffer(msg, sizeof(msg) - 1));
		uv_thread_join(&m_worker);
	}
	catch (const std::exception& e) {
		LOGERR(1, "exception " << e.what());
	}
}

void ZMQReader::run_wrapper(void* arg)
{
	reinterpret_cast<ZMQReader*>(arg)->run();
	LOGINFO(1, "worker thread stopped");
}

void ZMQReader::run()
{
	try {
		if (!m_proxy.empty()) {
			m_subscriber.set(zmq::sockopt::socks_proxy, zmq::const_buffer(m_proxy.c_str(), m_proxy.length()));
		}

		std::string addr = "tcp://" + m_address + ':' + std::to_string(m_zmqPort);
		if (!connect(addr)) {
			return;
		}

		m_subscriber.set(zmq::sockopt::socks_proxy, zmq::const_buffer());

		addr = "tcp://127.0.0.1:" + std::to_string(m_publisherPort);
		if (!connect(addr)) {
			return;
		}

		m_subscriber.set(zmq::sockopt::subscribe, "json-full-chain_main");
		m_subscriber.set(zmq::sockopt::subscribe, "json-full-miner_data");
		m_subscriber.set(zmq::sockopt::subscribe, "json-minimal-txpool_add");

		zmq_msg_t message;
		int rc = zmq_msg_init(&message);
		if (rc != 0) {
			throw zmq::error_t(errno);
		}

		LOGINFO(1, "worker thread ready");

		do {
			rc = zmq_msg_recv(&message, m_subscriber, 0);
			if (rc < 0) {
				throw zmq::error_t(errno);
			}

			if (m_finished.load()) {
				break;
			}

			parse(reinterpret_cast<char*>(zmq_msg_data(&message)), zmq_msg_size(&message));
		} while (true);

		zmq_msg_close(&message);
	}
	catch (const std::exception& e) {
		LOGERR(1, "exception " << e.what());
	}
}

bool ZMQReader::connect(const std::string& address)
{
	struct ConnectMonitor : public zmq::monitor_t
	{
		void on_event_connected(const zmq_event_t&, const char* address) ZMQ_OVERRIDE
		{
			LOGINFO(1, "connected to " << address);
			connected = true;
		}

		bool connected = false;
	} monitor;

	static uint64_t id = 0;

	if (!id) {
		std::random_device rd;
		id = (static_cast<uint64_t>(rd()) << 32) | static_cast<uint32_t>(rd());
	}

	char buf[log::Stream::BUF_SIZE + 1];
	log::Stream s(buf);
	s << "inproc://p2pool-connect-mon-" << id << '\0';
	++id;

	monitor.init(m_subscriber, buf);
	m_subscriber.connect(address);

	using namespace std::chrono;
	steady_clock::time_point start_time = steady_clock::now();

	while (!monitor.connected && monitor.check_event(-1)) {
		const steady_clock::time_point cur_time = steady_clock::now();
		const int64_t elapsed_time = duration_cast<milliseconds>(cur_time - start_time).count();
		if (elapsed_time >= 3000) {
			LOGERR(1, "failed to connect to " << address);
			if (m_finished.load()) {
				return false;
			}
			start_time = cur_time;
		}
	}

	return true;
}

void ZMQReader::parse(char* data, size_t size)
{
	char* value = data;
	char* end = data + size;

	while ((value < end) && (*value != ':')) {
		++value;
	}

	if (value >= end) {
		LOGWARN(1, "ZeroMQ message doesn't have ':' delimiter, skipping it");
		return;
	}

	*value = '\0';
	++value;

	using namespace rapidjson;

	Document doc;
	if (doc.Parse<kParseCommentsFlag | kParseTrailingCommasFlag>(value, end - value).HasParseError()) {
		LOGWARN(1, "ZeroMQ message failed to parse, skipping it");
		return;
	}

	if (strcmp(data, "json-minimal-txpool_add") == 0) {
		if (!doc.IsArray()) {
			LOGWARN(1, "json-minimal-txpool_add is not an array, skipping it");
			return;
		}

		m_tx.time_received = seconds_since_epoch();

		for (SizeType i = 0, n = doc.Size(); i < n; ++i) {
			const auto& v = doc[i];
			if (PARSE(v, m_tx, id) && PARSE(v, m_tx, blob_size) && PARSE(v, m_tx, weight) && PARSE(v, m_tx, fee)) {
				m_handler->handle_tx(m_tx);
			}
			else {
				LOGWARN(1, "transaction #" << (i + 1) << " in json-minimal-txpool_add failed to parse, skipped it");
			}
		}
	}
	else if (strcmp(data, "json-full-miner_data") == 0) {
		if (!doc.IsObject()) {
			LOGWARN(1, "json-full-miner_data is not an object, skipping it");
			return;
		}

		if (!PARSE(doc, m_minerData, major_version) ||
			!PARSE(doc, m_minerData, height) ||
			!PARSE(doc, m_minerData, prev_id) ||
			!PARSE(doc, m_minerData, seed_hash) ||
			!PARSE(doc, m_minerData, median_weight) ||
			!PARSE(doc, m_minerData, already_generated_coins) ||
			!PARSE(doc, m_minerData, difficulty)) {
			LOGWARN(1, "json-full-miner_data failed to parse, skipping it");
			return;
		}

		if (!doc.HasMember("tx_backlog")) {
			LOGWARN(1, "json-full-miner_data doesn't have 'tx_backlog', skipping it");
			return;
		}

		const auto& tx_backlog = doc["tx_backlog"];

		if (!tx_backlog.IsArray()) {
			LOGWARN(1, "'tx_backlog' in json-full-miner_data is not an array, skipping it");
			return;
		}

		m_minerData.tx_backlog.clear();

		const SizeType n = tx_backlog.Size();
		m_minerData.tx_backlog.reserve(n);

		for (SizeType i = 0; i < n; ++i) {
			const auto& v = tx_backlog[i];
			if (PARSE(v, m_tx, id) && PARSE(v, m_tx, weight) && PARSE(v, m_tx, fee)) {
				m_minerData.tx_backlog.push_back(m_tx);
			}
			else {
				LOGWARN(1, "transaction #" << (i + 1) << " in json-full-miner_data `tx_backlog` failed to parse, skipped it");
			}
		}

		m_handler->handle_miner_data(m_minerData);
	}
	else if (strcmp(data, "json-full-chain_main") == 0) {
		if (!doc.IsArray()) {
			LOGWARN(1, "json-full-chain_main is not an object, skipping it");
			return;
		}

		auto arr = doc.GetArray();
		for (Value* i = arr.begin(); i != arr.end(); ++i) {
			if (!PARSE(*i, m_chainmainData, timestamp)) {
				LOGWARN(1, "json-full-chain_main timestamp failed to parse, skipping it");
				continue;
			}

			auto it = i->FindMember("miner_tx");
			if ((it == i->MemberEnd()) || !it->value.IsObject()) {
				LOGWARN(1, "json-full-chain_main miner_tx not found, skipping it");
				continue;
			}

			auto extra_it = it->value.FindMember("extra");
			if ((extra_it == it->value.MemberEnd()) || !extra_it->value.IsString()) {
				LOGWARN(1, "json-full-chain_main extra not found, skipping it");
				continue;
			}

			auto inputs_it = it->value.FindMember("inputs");
			if ((inputs_it == it->value.MemberEnd()) || !inputs_it->value.IsArray()) {
				LOGWARN(1, "json-full-chain_main inputs not found, skipping it");
				continue;
			}

			// Get block reward from miner_tx outputs
			m_chainmainData.reward = 0;

			auto outputs_it = it->value.FindMember("outputs");
			if ((outputs_it != it->value.MemberEnd()) && outputs_it->value.IsArray()) {
				auto outputs = outputs_it->value.GetArray();
				for (SizeType j = 0, n = outputs.Size(); j < n; ++j) {
					if (outputs[j].IsObject()) {
						auto amount_it = outputs[j].FindMember("amount");
						if (amount_it != outputs[j].MemberEnd() && amount_it->value.IsUint64()) {
							m_chainmainData.reward += amount_it->value.GetUint64();
						}
					}
				}
			}
			else {
				LOGWARN(1, "json-full-chain_main outputs not found");
			}

			auto inputs = inputs_it->value.GetArray();
			if ((inputs.Size() == 0) || !inputs[0].IsObject()) {
				LOGWARN(1, "json-full-chain_main inputs is not an array, skipping it");
				continue;
			}

			it = inputs[0].FindMember("gen");
			if ((it == inputs[0].MemberEnd()) || !it->value.IsObject()) {
				LOGWARN(1, "json-full-chain_main gen not found, skipping it");
				continue;
			}

			if (!PARSE(it->value, m_chainmainData, height)) {
				LOGWARN(1, "json-full-chain_main height not found, skipping it");
				continue;
			}

			m_handler->handle_chain_main(m_chainmainData, extra_it->value.GetString());
		}
	}
}

} // namespace p2pool
