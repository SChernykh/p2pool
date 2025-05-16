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
#include "zmq_reader.h"
#include "json_parsers.h"
#include "rapidjson_wrapper.h"

LOG_CATEGORY(ZMQReader)

namespace p2pool {

ZMQReader::ZMQReader(const std::string& address, uint32_t zmq_port, const std::string& proxy, MinerCallbackHandler* handler)
	: m_monitor(nullptr)
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

	char addr_buf[log::Stream::BUF_SIZE + 1];
	addr_buf[0] = '\0';

	std::random_device rd;
	std::mt19937_64 rng(rd());

	for (uint32_t i = 0; i < 100; ++i) {
		const uint32_t port = 49152 + (rng() % 16384);

		try {
			log::Stream s(addr_buf);
			s << "tcp://127.0.0.1:" << port << '\0';
			m_publisher.bind(addr_buf);
			m_publisherPort = static_cast<uint16_t>(port);
			break;
		}
		catch (const std::exception& e) {
			LOGWARN(1, "failed to to bind port " << port << " for ZMQ publisher, error " << e.what());
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}
	}

	if (!m_publisherPort) {
		LOGERR(1, "failed to to bind ZMQ publisher port, aborting");
		throw zmq::error_t(EFSM);
	}

	LOGINFO(5, "listening on tcp://127.0.0.1:" << m_publisherPort << " for internal communications");

	m_subscriber.set(zmq::sockopt::connect_timeout, 1000);

	std::string addr(addr_buf);
	if (!connect(addr, false)) {
		throw zmq::error_t(EFSM);
	}

	if (!m_proxy.empty()) {
		m_subscriber.set(zmq::sockopt::socks_proxy, zmq::const_buffer(m_proxy.c_str(), m_proxy.length()));
	}

	log::Stream s(addr_buf);
	s << "tcp://" << address << ':' << m_zmqPort << '\0';
	addr.assign(addr_buf);

	if (!connect(addr, true)) {
		throw zmq::error_t(EFSM);
	}
	m_address = std::move(addr);

	m_subscriber.set(zmq::sockopt::socks_proxy, zmq::const_buffer());

	m_subscriber.set(zmq::sockopt::subscribe, "json-full-chain_main");
	m_subscriber.set(zmq::sockopt::subscribe, "json-full-miner_data");
	m_subscriber.set(zmq::sockopt::subscribe, "json-minimal-txpool_add");

	const int err = uv_thread_create(&m_worker, run_wrapper, this);
	if (err) {
		LOGERR(1, "failed to start ZMQ worker thread, error " << uv_err_name(err));
		throw zmq::error_t(EMTHREAD);
	}
}

ZMQReader::~ZMQReader()
{
	LOGINFO(1, "stopping");

	stop();
	uv_thread_join(&m_worker);

	delete m_monitor;

	LOGINFO(1, "stopped");
}

void ZMQReader::stop()
{
	if (m_stopped.exchange(true)) {
		return;
	}

	try {
		static constexpr char dummy_msg[] = "json-minimal-txpool_add:[]";
		m_publisher.send(zmq::const_buffer(dummy_msg, sizeof(dummy_msg) - 1));
	}
	catch (const std::exception& e) {
		LOGERR(1, "exception " << e.what());
	}
}

void ZMQReader::monitor_thread(void* arg)
{
	LOGINFO(1, "monitor thread ready");

	set_thread_name("ZMQ monitor");

	ZMQReader* r = reinterpret_cast<ZMQReader*>(arg);

	do {} while (!r->m_stopped && r->m_monitor->m_connected && r->m_monitor->check_event(-1));

	// If not connected anymore, shut down ZMQReader entirely
	r->stop();

	LOGINFO(1, "monitor thread stopped");
}

void ZMQReader::run_wrapper(void* arg)
{
	reinterpret_cast<ZMQReader*>(arg)->run();
	LOGINFO(1, "worker thread stopped");
}

void ZMQReader::run()
{
	m_workerThreadRunning = true;
	ON_SCOPE_LEAVE([this]() { m_workerThreadRunning = false; });

	set_thread_name("ZMQ worker");

	zmq_msg_t message = {};

	try {
		int rc = zmq_msg_init(&message);
		if (rc != 0) {
			throw zmq::error_t(errno);
		}

		const int err = uv_thread_create(&m_monitorThread, monitor_thread, this);
		if (err) {
			LOGERR(1, "failed to start ZMQ monitor thread, error " << uv_err_name(err));
			throw zmq::error_t(EMTHREAD);
		}

		ON_SCOPE_LEAVE([this]() {
			m_monitor->abort();
			uv_thread_join(&m_monitorThread);
		});

		LOGINFO(1, "worker thread ready");

		do {
			rc = zmq_msg_recv(&message, m_subscriber, 0);
			if (rc < 0) {
				throw zmq::error_t(errno);
			}

			if (m_stopped) {
				break;
			}

			parse(reinterpret_cast<char*>(zmq_msg_data(&message)), zmq_msg_size(&message));
		} while (true);
	}
	catch (const std::exception& e) {
		LOGERR(1, "exception " << e.what());
	}

	zmq_msg_close(&message);
}

void ZMQReader::Monitor::on_event_connected(const zmq_event_t&, const char* address)
{
	LOGINFO(1, "connected to " << address);
	m_connected = true;
}

void ZMQReader::Monitor::on_event_disconnected(const zmq_event_t&, const char* address)
{
	LOGERR(1, "disconnected from " << address);
	m_connected = false;
}

bool ZMQReader::connect(const std::string& address, bool keep_monitor)
{
	static uint64_t id = 0;

	if (!id) {
		std::random_device rd;
		id = (static_cast<uint64_t>(rd()) << 32) | static_cast<uint32_t>(rd());
		id >>= 1; // to avoid MAX_UINT64 case
	}

	char buf[64];
	// cppcheck-suppress uninitvar
	log::Stream s(buf);
	s << "inproc://p2pool-connect-mon-" << id << '\0';
	++id;

	using namespace std::chrono;
	const auto start_time = steady_clock::now();

	Monitor* monitor = new Monitor();
	monitor->init(m_subscriber, buf);
	m_subscriber.connect(address);

	while (!monitor->m_connected && monitor->check_event(-1)) {
		if (monitor->m_connected) {
			break;
		}
		if (duration_cast<milliseconds>(steady_clock::now() - start_time).count() >= 1000) {
			LOGERR(1, "failed to connect to " << address);
			delete monitor;
			return false;
		}
	}

	if (keep_monitor) {
		m_monitor = monitor;
	}
	else {
		delete monitor;
	}

	return true;
}

void ZMQReader::parse(char* data, size_t size)
{
	char* value = data;
	const char* end = data + size;

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
	if (doc.Parse(value, end - value).HasParseError()) {
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
