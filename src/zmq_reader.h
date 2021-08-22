/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021 SChernykh <https://github.com/SChernykh>
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
	ZMQReader(const char* address, uint32_t rpc_port, uint32_t zmq_port, MinerCallbackHandler* handler);
	~ZMQReader();

private:
	static void run_wrapper(void* arg) { reinterpret_cast<ZMQReader*>(arg)->run(); }
	void run();

	void parse(char* data, size_t size);

	const char* m_address;
	uint32_t m_rpcPort;
	uint32_t m_zmqPort;
	MinerCallbackHandler* m_handler;

	uv_thread_t m_worker{};
	zmq::context_t m_context{ 1 };
	zmq::socket_t m_publisher{ m_context, ZMQ_PUB };
	zmq::socket_t m_subscriber{ m_context, ZMQ_SUB };
	uint16_t m_publisherPort = 37891;
	std::atomic<int> m_finished{ 0 };

	TxMempoolData m_tx;
	MinerData m_minerData;
	ChainMain m_chainmainData;
};

} // namespace p2pool
