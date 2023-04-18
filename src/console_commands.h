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

#pragma once

#include "uv_util.h"
#include "tcp_server.h"

namespace p2pool {

class p2pool;

class ConsoleCommands : public TCPServer<256, 256>
{
public:
	explicit ConsoleCommands(p2pool* pool);
	~ConsoleCommands();

	struct ConsoleClient : public Client
	{
		~ConsoleClient() {}

		static Client* allocate() { return new ConsoleClient(); }

		size_t size() const override { return sizeof(ConsoleClient); }

		bool on_connect() override { return true; };
		bool on_read(char* data, uint32_t size) override { static_cast<ConsoleCommands*>(m_owner)->process_input(m_command, data, size); return true; };

		std::string m_command;
	};

	void on_shutdown() override;

private:
	p2pool* m_pool;

	uv_tty_t m_tty;
	uv_pipe_t m_stdin_pipe;
	uv_stream_t* m_stdin_handle;

	char m_readBuf[64];
	bool m_readBufInUse;

	std::string m_command;

	static void allocCallback(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
	static void stdinReadCallback(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);

	void process_input(std::string& command, char* data, uint32_t size);
};

} // namespace p2pool
