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

void ConsoleCommands::run()
{
	LOGINFO(1, "started");

	std::string command;
	command.reserve(1024);

	constexpr char status[]    = "status";
	constexpr char loglevel[]  = "loglevel";
	constexpr char addpeers[]  = "addpeers";
	constexpr char droppeers[] = "droppeers";

	do {
		std::getline(std::cin, command);
		if (stopped || std::cin.eof()) {
			return;
		}

		if (command.find(status) == 0) {
			m_pool->side_chain().print_status();
			if (m_pool->stratum_server()) {
				m_pool->stratum_server()->print_status();
			}
			if (m_pool->p2p_server()) {
				m_pool->p2p_server()->print_status();
			}
			continue;
		}

		if (command.find(loglevel) == 0) {
			int level = atoi(command.c_str() + sizeof(loglevel));
			level = std::min(std::max(level, 0), 5);
			log::GLOBAL_LOG_LEVEL = level;
			LOGINFO(0, "log level set to " << level);
			continue;
		}

		if (command.find(addpeers) == 0) {
			if (m_pool->p2p_server()) {
				m_pool->p2p_server()->connect_to_peers(command.c_str() + sizeof(addpeers));
			}
			continue;
		}

		if (command.find(droppeers) == 0) {
			if (m_pool->p2p_server()) {
				m_pool->p2p_server()->drop_connections();
			}
			continue;
		}

		LOGWARN(0, "Unknown command " << command);
	} while (true);
}

} // namespace p2pool
