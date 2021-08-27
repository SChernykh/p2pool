/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021 SChernykh <https://github.com/SChernykh>
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
#include "side_chain.h"
#include <iostream>

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
#else
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

static cmdfunc do_help, do_status, do_loglevel, do_addpeers, do_droppeers, do_exit;

static cmd cmds[] = {
	{ STRCONST("help"), "", "display list of commands", do_help },
	{ STRCONST("status"), "", "display p2pool status", do_status },
	{ STRCONST("loglevel"), "<level>", "set log level", do_loglevel },
	{ STRCONST("addpeers"), "<peeraddr>", "add peer", do_addpeers },
	{ STRCONST("droppeers"), "", "disconnect all peers", do_droppeers },
	{ STRCONST("exit"), "", "terminate p2pool", do_exit },
	{ STRCNULL, NULL, NULL, NULL }
};

static int do_help(p2pool * /* m_pool */, const char * /* args */)
{
	int i;

	LOGINFO(0, "List of commands");
	for (i=0; cmds[i].name.len; i++)
		LOGINFO(0, cmds[i].name.str << " " << cmds[i].arg << "\t" << cmds[i].descr);
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
	bkg_jobs_tracker.print_status();
	return 0;
}

static int do_loglevel(p2pool * /* m_pool */, const char *args)
{
	int level = atoi(args);
	level = std::min(std::max(level, 0), 6);
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
		if (stopped || std::cin.eof()) {
			return;
		}

		int i;
		for (i=0; cmds[i].name.len; i++) {
			if (!strncmp(command.c_str(), cmds[i].name.str, cmds[i].name.len)) {
				const char *args = command.c_str() + cmds[i].name.len + 1;
				int rc = cmds[i].func(m_pool, args);
				if ( rc )
					return;
				break;
			}
		}
		if (!cmds[i].name.len)
			LOGWARN(0, "Unknown command " << command);
	} while (true);
}

} // namespace p2pool
