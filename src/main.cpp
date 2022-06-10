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
#include "crypto.h"
#include "p2pool.h"
#include "stratum_server.h"
#include "p2p_server.h"
#include <curl/curl.h>

void p2pool_usage()
{
	printf("P2Pool %s\n"
		"\nUsage:\n\n" \
		"--wallet             Wallet address to mine to. Subaddresses and integrated addresses are not supported!\n"
		"--host               IP address of your Monero node, default is 127.0.0.1\n"
		"--rpc-port           monerod RPC API port number, default is 18081\n"
		"--zmq-port           monerod ZMQ pub port number, default is 18083 (same port as in monerod's \"--zmq-pub\" command line parameter)\n"
		"--stratum            Comma-separated list of IP:port for stratum server to listen on\n"
		"--p2p                Comma-separated list of IP:port for p2p server to listen on\n"
		"--addpeers           Comma-separated list of IP:port of other p2pool nodes to connect to\n"
		"--light-mode         Don't allocate RandomX dataset, saves 2GB of RAM\n"
		"--loglevel           Verbosity of the log, integer number between 0 and %d\n"
		"--config             Name of the p2pool config file\n"
		"--data-api           Path to the p2pool JSON data (use it in tandem with an external web-server)\n"
		"--local-api          Enable /local/ path in api path for Stratum Server and built-in miner statistics\n"
		"--stratum-api        An alias for --local-api\n"
		"--no-cache           Disable p2pool.cache\n"
		"--no-color           Disable colors in console output\n"
		"--no-randomx         Disable internal RandomX hasher: p2pool will use RPC calls to monerod to check PoW hashes\n"
		"--out-peers N        Maximum number of outgoing connections for p2p server (any value between 10 and 1000)\n"
		"--in-peers N         Maximum number of incoming connections for p2p server (any value between 10 and 1000)\n"
		"--start-mining N     Start built-in miner using N threads (any value between 1 and 64)\n"
		"--mini               Connect to p2pool-mini sidechain. Note that it will also change default p2p port from %d to %d\n"
		"--no-autodiff        Disable automatic difficulty adjustment for miners connected to stratum\n"
		"--rpc-login          Specify username[:password] required for Monero RPC server\n"
		"--on-share-found     Path of file to run when share is found\n"
		"--help               Show this help message\n\n"
		"Example command line:\n\n"
		"%s --host 127.0.0.1 --rpc-port 18081 --zmq-port 18083 --wallet YOUR_WALLET_ADDRESS --stratum 0.0.0.0:%d --p2p 0.0.0.0:%d\n\n",
		p2pool::VERSION,
		p2pool::log::MAX_GLOBAL_LOG_LEVEL,
		p2pool::DEFAULT_P2P_PORT,
		p2pool::DEFAULT_P2P_PORT_MINI,
#ifdef _WIN32
		"p2pool.exe"
#else
		"./p2pool"
#endif
		, p2pool::DEFAULT_STRATUM_PORT
		, p2pool::DEFAULT_P2P_PORT
	);
}

void memory_tracking_start();
void memory_tracking_stop();

int main(int argc, char* argv[])
{
	if (argc == 1) {
		p2pool_usage();
		return 0;
	}

	for (int i = 1; i < argc; ++i) {
		if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "/help") || !strcmp(argv[i], "-h") || !strcmp(argv[i], "/h")) {
			p2pool_usage();
			return 0;
		}
	}

	memory_tracking_start();

	p2pool::init_crypto_cache();

	int result = static_cast<int>(curl_global_init_mem(CURL_GLOBAL_ALL, p2pool::malloc_hook, p2pool::free_hook, p2pool::realloc_hook, p2pool::strdup_hook, p2pool::calloc_hook));
	if (result != CURLE_OK) {
		return result;
	}

	try {
		p2pool::p2pool pool(argc, argv);
		result = pool.run();
	}
	catch (...) {
		result = 1;
	}

	curl_global_cleanup();

	p2pool::destroy_crypto_cache();

	memory_tracking_stop();

	return result;
}
