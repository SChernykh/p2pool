/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2022 SChernykh <https://github.com/SChernykh>
 * Copyright (c) 2021 hyc <https://github.com/hyc>
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
#include "console_commands.h"
#include "p2pool.h"
#include "stratum_server.h"
#include "p2p_server.h"
#ifdef WITH_RANDOMX
#include "miner.h"
#endif
#include "side_chain.h"
#include <iostream>

static constexpr char log_category_prefix[] = "ConsoleCommands ";

namespace p2pool {

ConsoleCommands::ConsoleCommands(p2pool* pool)
	: m_pool(pool)
	, m_loop{}
	, m_shutdownAsync{}
	, m_tty{}
	, m_loopThread{}
	, m_readBuf{}
	, m_readBufInUse(false)
{
	if (uv_guess_handle(0) != UV_TTY) {
		LOGERR(1, "tty is not available");
		throw std::exception();
	}

	int err = uv_loop_init(&m_loop);
	if (err) {
		LOGERR(1, "failed to create event loop, error " << uv_err_name(err));
		throw std::exception();
	}

	err = uv_async_init(&m_loop, &m_shutdownAsync, on_shutdown);
	if (err) {
		LOGERR(1, "uv_async_init failed, error " << uv_err_name(err));
		throw std::exception();
	}
	m_shutdownAsync.data = this;

	err = uv_tty_init(&m_loop, &m_tty, 0, 1);
	if (err) {
		LOGERR(1, "uv_tty_init failed, error " << uv_err_name(err));
		throw std::exception();
	}
	m_tty.data = this;

	err = uv_read_start(reinterpret_cast<uv_stream_t*>(&m_tty), allocCallback, stdinReadCallback);
	if (err) {
		LOGERR(1, "uv_read_start failed, error " << uv_err_name(err));
		throw std::exception();
	}

	err = uv_thread_create(&m_loopThread, loop, this);
	if (err) {
		LOGERR(1, "failed to start event loop thread, error " << uv_err_name(err));
		throw std::exception();
	}
}

ConsoleCommands::~ConsoleCommands()
{
	uv_async_send(&m_shutdownAsync);
	uv_thread_join(&m_loopThread);
	LOGINFO(1, "stopped");
}

typedef struct strconst {
	const char *str;
	size_t len;
} strconst;

#define STRCONST(x)	{x, sizeof(x)-1}
#define STRCNULL	{NULL, 0}

typedef void (cmdfunc)(p2pool *pool, const char *args);

typedef struct cmd {
	strconst name;
	const char *arg;
	const char *descr;
	cmdfunc *func;
} cmd;

static cmdfunc do_help, do_status, do_loglevel, do_addpeers, do_droppeers, do_showpeers, do_showworkers, do_showbans, do_outpeers, do_inpeers, do_exit;

#ifdef WITH_RANDOMX
static cmdfunc do_start_mining, do_stop_mining;
#endif

static cmd cmds[] = {
	{ STRCONST("help"), "", "display list of commands", do_help },
	{ STRCONST("status"), "", "display p2pool status", do_status },
	{ STRCONST("loglevel"), "<level>", "set log level", do_loglevel },
	{ STRCONST("addpeers"), "<peeraddr>", "add peer", do_addpeers },
	{ STRCONST("droppeers"), "", "disconnect all peers", do_droppeers },
	{ STRCONST("peers"), "", "show all peers", do_showpeers },
	{ STRCONST("workers"), "", "show all connected workers", do_showworkers },
	{ STRCONST("bans"), "", "show all banned IPs", do_showbans },
	{ STRCONST("outpeers"), "", "set maximum number of outgoing connections", do_outpeers },
	{ STRCONST("inpeers"), "", "set maximum number of incoming connections", do_inpeers },
#ifdef WITH_RANDOMX
	{ STRCONST("start_mining"), "<threads>", "start mining", do_start_mining },
	{ STRCONST("stop_mining"), "", "stop mining", do_stop_mining },
#endif
	{ STRCONST("exit"), "", "terminate p2pool", do_exit },
	{ STRCNULL, NULL, NULL, NULL }
};

static void do_help(p2pool * /* m_pool */, const char * /* args */)
{
	LOGINFO(0, "List of commands");
	for (int i = 0; cmds[i].name.len; ++i) {
		LOGINFO(0, cmds[i].name.str << " " << cmds[i].arg << "\t" << cmds[i].descr);
	}
}

static void do_status(p2pool *m_pool, const char * /* args */)
{
	m_pool->side_chain().print_status();
	if (m_pool->stratum_server()) {
		m_pool->stratum_server()->print_status();
	}
	if (m_pool->p2p_server()) {
		m_pool->p2p_server()->print_status();
	}
#ifdef WITH_RANDOMX
	m_pool->print_miner_status();
#endif
	bkg_jobs_tracker.print_status();
}

static void do_loglevel(p2pool * /* m_pool */, const char *args)
{
	int level = strtol(args, nullptr, 10);
	level = std::min(std::max(level, 0), log::MAX_GLOBAL_LOG_LEVEL);
	log::GLOBAL_LOG_LEVEL = level;
	LOGINFO(0, "log level set to " << level);
}

static void do_addpeers(p2pool *m_pool, const char *args)
{
	if (m_pool->p2p_server()) {
		m_pool->p2p_server()->connect_to_peers(args);
	}
}

static void do_droppeers(p2pool *m_pool, const char * /* args */)
{
	if (m_pool->p2p_server()) {
		m_pool->p2p_server()->drop_connections();
	}
}

static void do_showpeers(p2pool* m_pool, const char* /* args */)
{
	if (m_pool->p2p_server()) {
		m_pool->p2p_server()->show_peers();
	}
}

static void do_showworkers(p2pool* m_pool, const char* /* args */)
{
	if (m_pool->stratum_server()) {
		m_pool->stratum_server()->show_workers();
	}
}

static void do_showbans(p2pool* m_pool, const char* /* args */)
{
	if (m_pool->stratum_server()) {
		m_pool->stratum_server()->print_bans();
	}
	if (m_pool->p2p_server()) {
		m_pool->p2p_server()->print_bans();
	}
}

static void do_outpeers(p2pool* m_pool, const char* args)
{
	if (m_pool->p2p_server()) {
		m_pool->p2p_server()->set_max_outgoing_peers(strtoul(args, nullptr, 10));
		LOGINFO(0, "max outgoing peers set to " << m_pool->p2p_server()->max_outgoing_peers());
	}
}

static void do_inpeers(p2pool* m_pool, const char* args)
{
	if (m_pool->p2p_server()) {
		m_pool->p2p_server()->set_max_incoming_peers(strtoul(args, nullptr, 10));
		LOGINFO(0, "max incoming peers set to " << m_pool->p2p_server()->max_incoming_peers());
	}
}

#ifdef WITH_RANDOMX
static void do_start_mining(p2pool* m_pool, const char* args)
{
	uint32_t threads = strtoul(args, nullptr, 10);
	threads = std::min(std::max(threads, 1u), 64u);
	m_pool->start_mining(threads);
}

static void do_stop_mining(p2pool* m_pool, const char* /*args*/)
{
	m_pool->stop_mining();
}
#endif

static void do_exit(p2pool *m_pool, const char * /* args */)
{
	bkg_jobs_tracker.wait();
	m_pool->stop();
}

void ConsoleCommands::allocCallback(uv_handle_t* handle, size_t /*suggested_size*/, uv_buf_t* buf)
{
	ConsoleCommands* pThis = static_cast<ConsoleCommands*>(handle->data);

	if (pThis->m_readBufInUse) {
		buf->len = 0;
		buf->base = nullptr;
		return;
	}

	buf->len = sizeof(pThis->m_readBuf);
	buf->base = pThis->m_readBuf;
	pThis->m_readBufInUse = true;
}

void ConsoleCommands::stdinReadCallback(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
	ConsoleCommands* pThis = static_cast<ConsoleCommands*>(stream->data);

	if (nread > 0) {
		std::string& command = pThis->m_command;
		command.append(buf->base, nread);

		do {
			size_t k = command.find_first_of("\r\n");
			if (k == std::string::npos) {
				break;
			}
			command[k] = '\0';

			cmd* c = cmds;
			for (; c->name.len; ++c) {
				if (!strncmp(command.c_str(), c->name.str, c->name.len)) {
					const char* args = (c->name.len + 1 <= k) ? (command.c_str() + c->name.len + 1) : "";
					c->func(pThis->m_pool, args);
					break;
				}
			}

			if (!c->name.len) {
				LOGWARN(0, "Unknown command " << command.c_str());
			}

			k = command.find_first_not_of("\r\n", k + 1);
			command.erase(0, k);
		} while (true);
	}
	else if (nread < 0) {
		LOGWARN(4, "read error " << uv_err_name(static_cast<int>(nread)));
	}

	pThis->m_readBufInUse = false;
}

void ConsoleCommands::loop(void* data)
{
	LOGINFO(1, "event loop started");
	ConsoleCommands* pThis = static_cast<ConsoleCommands*>(data);
	uv_run(&pThis->m_loop, UV_RUN_DEFAULT);
	uv_loop_close(&pThis->m_loop);
	LOGINFO(1, "event loop stopped");
}

} // namespace p2pool
