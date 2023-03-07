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

namespace p2pool {

class p2pool;

class ConsoleCommands : public nocopy_nomove
{
public:
	explicit ConsoleCommands(p2pool* pool);
	~ConsoleCommands();

private:
	p2pool* m_pool;

	uv_loop_t m_loop;
	uv_async_t m_shutdownAsync;
	uv_tty_t m_tty;
	uv_pipe_t m_stdin_pipe;
	uv_handle_t* m_stdin_handle;
	uv_thread_t m_loopThread;

	char m_readBuf[64];
	bool m_readBufInUse;

	std::string m_command;

	static void loop(void* data);

	static void on_shutdown(uv_async_t* async)
	{
		ConsoleCommands* pThis = reinterpret_cast<ConsoleCommands*>(async->data);
		uv_close(reinterpret_cast<uv_handle_t*>(&pThis->m_shutdownAsync), nullptr);
		uv_close(reinterpret_cast<uv_handle_t*>(pThis->m_stdin_handle), nullptr);
	}

	static void allocCallback(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
	static void stdinReadCallback(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
};

} // namespace p2pool
