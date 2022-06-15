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

#ifdef HAVE_PTHREAD_CANCEL
#include <pthread.h>
#endif

static constexpr char log_category_prefix[] = "ConsoleCommands ";

namespace p2pool {

bool ConsoleCommands::stopped = false;

ConsoleCommands::ConsoleCommands(p2pool* pool)
	: m_pool(pool)
{
	m_worker = new std::thread(&ConsoleCommands::run, this);
}

ConsoleCommands::~ConsoleCommands()
{
	stopped = true;

#ifdef _WIN32
	TerminateThread(reinterpret_cast<HANDLE>(m_worker->native_handle()), 0);
#elif defined HAVE_PTHREAD_CANCEL
	pthread_cancel(m_worker->native_handle());
#endif

	m_worker->join();
	delete m_worker;

	LOGINFO(1, "stopped");
}

typedef struct strconst {
	const char *str;
	size_t len;
} strconst;

#define STRCONST(x)	{x, sizeof(x)-1}
#define STRCNULL	{NULL, 0}

typedef int (cmdfunc)(p2pool *pool, const char *args);

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

static int do_help(p2pool * /* m_pool */, const char * /* args */)
{
	LOGINFO(0, "List of commands");
	for (int i = 0; cmds[i].name.len; ++i) {
		LOGINFO(0, cmds[i].name.str << " " << cmds[i].arg << "\t" << cmds[i].descr);
	}
	return 0;
}

static int do_status(p2pool *m_pool, const char * /* args */)
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
	return 0;
}

static int do_loglevel(p2pool * /* m_pool */, const char *args)
{
	int level = strtol(args, nullptr, 10);
	level = std::min(std::max(level, 0), log::MAX_GLOBAL_LOG_LEVEL);
	log::GLOBAL_LOG_LEVEL = level;
	LOGINFO(0, "log level set to " << level);
	return 0;
}

static int do_addpeers(p2pool *m_pool, const char *args)
{
	if (m_pool->p2p_server()) {
		m_pool->p2p_server()->connect_to_peers(args);
	}
	return 0;
}

static int do_droppeers(p2pool *m_pool, const char * /* args */)
{
	if (m_pool->p2p_server()) {
		m_pool->p2p_server()->drop_connections();
	}
	return 0;
}

static int do_showpeers(p2pool* m_pool, const char* /* args */)
{
	if (m_pool->p2p_server()) {
		m_pool->p2p_server()->show_peers();
	}
	return 0;
}

static int do_showworkers(p2pool* m_pool, const char* /* args */)
{
	if (m_pool->stratum_server()) {
		m_pool->stratum_server()->show_workers();
	}
	return 0;
}

static int do_showbans(p2pool* m_pool, const char* /* args */)
{
	if (m_pool->stratum_server()) {
		m_pool->stratum_server()->print_bans();
	}
	if (m_pool->p2p_server()) {
		m_pool->p2p_server()->print_bans();
	}
	return 0;
}

static int do_outpeers(p2pool* m_pool, const char* args)
{
	if (m_pool->p2p_server()) {
		m_pool->p2p_server()->set_max_outgoing_peers(strtoul(args, nullptr, 10));
		LOGINFO(0, "max outgoing peers set to " << m_pool->p2p_server()->max_outgoing_peers());
	}
	return 0;
}

static int do_inpeers(p2pool* m_pool, const char* args)
{
	if (m_pool->p2p_server()) {
		m_pool->p2p_server()->set_max_incoming_peers(strtoul(args, nullptr, 10));
		LOGINFO(0, "max incoming peers set to " << m_pool->p2p_server()->max_incoming_peers());
	}
	return 0;
}

#ifdef WITH_RANDOMX
static int do_start_mining(p2pool* m_pool, const char* args)
{
	uint32_t threads = strtoul(args, nullptr, 10);
	threads = std::min(std::max(threads, 1u), 64u);
	m_pool->start_mining(threads);
	return 0;
}

static int do_stop_mining(p2pool* m_pool, const char* /*args*/)
{
	m_pool->stop_mining();
	return 0;
}
#endif

static int do_exit(p2pool *m_pool, const char * /* args */)
{
	bkg_jobs_tracker.wait();
	m_pool->stop();

	return 1;
}

void ConsoleCommands::run()
{
	LOGINFO(1, "started");

	std::string command;
	command.reserve(1024);

	do {
		std::getline(std::cin, command);

		if (std::cin.eof()) {
			LOGINFO(1, "EOF, stopping");
			return;
		}

		if (stopped) {
			LOGINFO(1, "stopping");
			return;
		}

		cmd* c = cmds;
		for (; c->name.len; ++c) {
			if (!strncmp(command.c_str(), c->name.str, c->name.len)) {
				const char *args = command.c_str() + c->name.len + 1;
				if (c->func(m_pool, args)) {
					LOGINFO(1, "exit requested, stopping");
					return;
				}
				break;
			}
		}

		if (!c->name.len) {
			LOGWARN(0, "Unknown command " << command);
		}
	} while (true);
}

} // namespace p2pool
