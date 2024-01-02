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

#pragma once

#include "uv_util.h"
#include <zmq.hpp>

namespace p2pool {

class ZMQReader {
public:
	ZMQReader(const std::string& address, uint32_t zmq_port, const std::string& proxy, MinerCallbackHandler* handler);
	~ZMQReader();

	bool is_running() const { return m_workerThreadRunning.load(); }

private:
	struct Monitor : public zmq::monitor_t {
		Monitor() : m_connected(false) {}
		Monitor(const Monitor&) = delete;

		void on_event_connected(const zmq_event_t&, const char* address) ZMQ_OVERRIDE;
		void on_event_disconnected(const zmq_event_t&, const char* address) ZMQ_OVERRIDE;

		std::atomic<bool> m_connected;
	} *m_monitor;

	static void monitor_thread(void* arg);

	uv_thread_t m_monitorThread{};

private:
	void stop();

	static void run_wrapper(void* arg);
	void run();
	bool connect(const std::string& address, bool keep_monitor);

	void parse(char* data, size_t size);

	std::string m_address;
	uint32_t m_zmqPort;
	std::string m_proxy;
	MinerCallbackHandler* m_handler;

	uv_thread_t m_worker{};
	zmq::context_t m_context{ 1 };
	zmq::socket_t m_publisher{ m_context, ZMQ_PUB };
	zmq::socket_t m_subscriber{ m_context, ZMQ_SUB };
	uint16_t m_publisherPort = 0;
	std::atomic<bool> m_stopped{ false };
	std::atomic<bool> m_workerThreadRunning{ false };

	TxMempoolData m_tx;
	MinerData m_minerData;
	ChainMain m_chainmainData;
};

} // namespace p2pool
