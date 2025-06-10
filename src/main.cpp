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
#include "crypto.h"
#include "p2pool.h"
#include "stratum_server.h"
#include "p2p_server.h"
#include <curl/curl.h>

#ifdef WITH_GRPC

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4574)
#endif

#include <grpc/grpc.h>

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif // WITH_GRPC

#include <filesystem>

#ifdef WITH_RANDOMX
#include "randomx.h"
#endif

#if defined(_WIN32) && defined(_MSC_VER) && !defined(NDEBUG)

#include <DbgHelp.h>

#pragma comment(lib, "Dbghelp.lib")

#endif

void p2pool_usage()
{
	printf("P2Pool %s\n"
		"\nUsage:\n\n" \
		"--wallet              Wallet address to mine to. Subaddresses and integrated addresses are not supported!\n"
		"--host                IP address of your Monero node, default is 127.0.0.1\n"
		"--rpc-port            monerod RPC API port number, default is 18081\n"
		"--zmq-port            monerod ZMQ pub port number, default is 18083 (same port as in monerod's \"--zmq-pub\" command line parameter)\n"
		"--stratum             Comma-separated list of IP:port for stratum server to listen on\n"
		"--p2p                 Comma-separated list of IP:port for p2p server to listen on\n"
		"--addpeers            Comma-separated list of IP:port of other p2pool nodes to connect to\n"
		"--stratum-ban-time N  Number of seconds to ban misbehaving stratum client, default is %u\n"
		"--light-mode          Don't allocate RandomX dataset, saves 2GB of RAM\n"
		"--loglevel            Verbosity of the log, integer number between 0 and %d\n"
		"--data-dir            Path to store general p2pool files (log, cache, peer data, etc.), default is current directory\n"
		"--sidechain-config    Name of the p2pool sidechain parameters file (only use it if you run your own sidechain)\n"
		"--data-api            Path to the p2pool JSON data (use it in tandem with an external web-server). Not affected by --data-dir setting!\n"
		"--local-api           Enable /local/ path in api path for Stratum Server and built-in miner statistics\n"
		"--stratum-api         An alias for --local-api\n"
		"--no-cache            Disable p2pool.cache\n"
		"--no-color            Disable colors in console output\n"
#ifdef WITH_RANDOMX
		"--no-randomx          Disable internal RandomX hasher: p2pool will use RPC calls to monerod to check PoW hashes\n"
#endif
		"--out-peers N         Maximum number of outgoing connections for p2p server (any value between 10 and 450)\n"
		"--in-peers N          Maximum number of incoming connections for p2p server (any value between 10 and 450)\n"
		"--start-mining N      Start built-in miner using N threads (any value between 1 and 64)\n"
		"--mini                Connect to p2pool-mini sidechain. Note that it will also change default p2p port from %d to %d\n"
		"--nano                Connect to p2pool-nano sidechain. Note that it will also change default p2p port from %d to %d\n"
		"--no-autodiff         Disable automatic difficulty adjustment for miners connected to stratum (WARNING: incompatible with Nicehash and MRR)\n"
		"--rpc-login           Specify username[:password] required for Monero RPC server\n"
		"--socks5              Specify IP:port of a SOCKS5 proxy to use for outgoing connections\n"
		"--no-dns              Disable DNS queries, use only IP addresses to connect to peers (seed node DNS will be unavailable too)\n"
		"--p2p-external-port   Port number that your router uses for mapping to your local p2p port. Use it if you are behind a NAT and still want to accept incoming connections\n"
#ifdef WITH_UPNP
		"--no-upnp             Disable UPnP port forwarding\n"
		"--no-igd              An alias for --no-upnp\n"
		"--upnp-stratum        Port forward Stratum port (it's not forwarded by default)\n"
#endif
		"--merge-mine          IP:port and wallet address for another blockchain to merge mine with\n"
		"--version             Print p2pool's version and build details\n"
#ifdef WITH_TLS
		"--tls-cert file       Load TLS certificate chain from \"file\" in the PEM format\n"
		"--tls-cert-key file   Load TLS certificate private key from \"file\" in the PEM format\n"
		"--rpc-ssl             Enable SSL on RPC connections to the Monero node\n"
		"--rpc-ssl-fingerprint base64-encoded fingerprint of the Monero node's certificate (optional, use it for certificate pinning)\n"
#endif
		"--no-stratum-http     Disable HTTP on Stratum ports\n"
		"--help                Show this help message\n\n"
		"Example command line:\n\n"
		"%s --host 127.0.0.1 --rpc-port 18081 --zmq-port 18083 --wallet YOUR_WALLET_ADDRESS --stratum 0.0.0.0:%d --p2p 0.0.0.0:%d\n\n",
		p2pool::VERSION,
		static_cast<uint32_t>(p2pool::DEFAULT_STRATUM_BAN_TIME),
		p2pool::log::MAX_GLOBAL_LOG_LEVEL,
		p2pool::DEFAULT_P2P_PORT,
		p2pool::DEFAULT_P2P_PORT_MINI,
		p2pool::DEFAULT_P2P_PORT,
		p2pool::DEFAULT_P2P_PORT_NANO,
#ifdef _WIN32
		"p2pool.exe"
#else
		"./p2pool"
#endif
		, p2pool::DEFAULT_STRATUM_PORT
		, p2pool::DEFAULT_P2P_PORT
	);
}

void p2pool_version()
{
	printf("P2Pool %s\n", p2pool::VERSION);
}

int p2pool_test()
{
	printf("Self-test started\n");

#ifdef WITH_RANDOMX
	const char myKey[] = "test key 000";
	const char myInput[] = "This is a test";
	char hash[RANDOMX_HASH_SIZE];

	const randomx_flags flags = randomx_get_flags() | RANDOMX_FLAG_FULL_MEM;
	randomx_cache* myCache = randomx_alloc_cache(flags | RANDOMX_FLAG_LARGE_PAGES);
	if (!myCache) {
		myCache = randomx_alloc_cache(flags);
		if (!myCache) {
			printf("Cache allocation failed\n");
			return 1;
		}
	}
	printf("RandomX cache allocated\n");

	randomx_init_cache(myCache, myKey, sizeof(myKey) - 1);
	printf("RandomX cache initialized\n");

	randomx_dataset* myDataset = randomx_alloc_dataset(flags | RANDOMX_FLAG_LARGE_PAGES);
	if (!myDataset) {
		myDataset = randomx_alloc_dataset(flags);
		if (!myDataset) {
			printf("Dataset allocation failed\n");
			return 1;
		}
	}
	printf("RandomX dataset allocated\n");

	{
		const uint32_t numThreads = std::max(std::thread::hardware_concurrency(), 1U);
		const uint32_t numItems = randomx_dataset_item_count();

		std::vector<std::thread> threads;
		threads.reserve(numThreads);

		for (uint32_t i = 1; i < numThreads; ++i) {
			const uint32_t a = (numItems * i) / numThreads;
			const uint32_t b = (numItems * (i + 1)) / numThreads;

			threads.emplace_back([myDataset, myCache, a, b]() { randomx_init_dataset(myDataset, myCache, a, b - a); });
		}
		randomx_init_dataset(myDataset, myCache, 0, numItems / numThreads);

		for (std::thread& t : threads) {
			t.join();
		}
	}
	printf("RandomX dataset initialized\n");

	randomx_release_cache(myCache);

	randomx_vm* myMachine = randomx_create_vm(flags | RANDOMX_FLAG_LARGE_PAGES, nullptr, myDataset);
	if (!myMachine) {
		myMachine = randomx_create_vm(flags, nullptr, myDataset);
		if (!myMachine) {
			printf("Failed to create a virtual machine");
			return 1;
		}
	}
	printf("RandomX VM created\n");

	memset(hash, 0, sizeof(hash));
	memcpy(hash, myInput, sizeof(myInput));

	for (int i = 0; i < 100; ++i) {
		printf("RandomX: calculating hash %d...", i);
		randomx_calculate_hash(myMachine, &hash, sizeof(hash), hash);
		printf("done\n");
	}

	char buf[RANDOMX_HASH_SIZE * 2 + 1] = {};
	p2pool::log::Stream s(buf);
	s << p2pool::log::hex_buf(hash, RANDOMX_HASH_SIZE) << '\0';

	constexpr char expected_hash[] = "3b5ecc2bb14f467161a04fe476b541194fba82dbbbfc7c320961f922a0294dee";

	if (memcmp(buf, expected_hash, RANDOMX_HASH_SIZE * 2) != 0) {
		printf("Invalid hash calculated: expected %s, got %s\n", expected_hash, buf);
		return 1;
	}

	randomx_destroy_vm(myMachine);
	randomx_release_dataset(myDataset);
#endif

	printf("Self-test passed\n");
	return 0;
}

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

		if (!strcmp(argv[i], "--version") || !strcmp(argv[i], "/version") || !strcmp(argv[i], "-v") || !strcmp(argv[i], "/v")) {
			p2pool_version();
			return 0;
		}

		if (!strcmp(argv[i], "--test")) {
			return p2pool_test();
		}

		if ((strcmp(argv[i], "--data-dir") == 0) && (i + 1 < argc)) {
			std::string path = argv[++i];

			if (!path.empty() && (path.back() != '/')
#ifdef _WIN32
				&& (path.back() != '\\')
#endif
				) {
				path.append(1, '/');
			}

			p2pool::DATA_DIR = std::move(path);

			// Try to create it if it doesn't exist
			if (!p2pool::DATA_DIR.empty()) {
				std::error_code err;
				std::filesystem::create_directories(p2pool::DATA_DIR, err);
			}
		}
	}

#if defined(_WIN32) && defined(_MSC_VER) && !defined(NDEBUG)
	SymInitialize(GetCurrentProcess(), NULL, TRUE);
#endif

	memory_tracking_start();

	// Create default loop here
	uv_default_loop();

	p2pool::log::start();

	p2pool::init_crypto_cache();

	int result = static_cast<int>(curl_global_init_mem(CURL_GLOBAL_ALL, p2pool::malloc_hook, p2pool::free_hook, p2pool::realloc_hook, p2pool::strdup_hook, p2pool::calloc_hook));
	if (result != CURLE_OK) {
		return result;
	}

#ifdef WITH_GRPC
	grpc_init();
#endif

	try {
		p2pool::p2pool pool(argc, argv);
		result = pool.run();
	}
	catch (...) {
		result = 1;
	}

#ifdef WITH_GRPC
	grpc_shutdown();
#endif

	curl_global_cleanup();

	p2pool::destroy_crypto_cache();

	p2pool::log::stop();

	uv_loop_close(uv_default_loop());

#if ((UV_VERSION_MAJOR > 1) || ((UV_VERSION_MAJOR == 1) && (UV_VERSION_MINOR >= 38)))
	uv_library_shutdown();
#endif

	if (!memory_tracking_stop()) {
		result = 1;
	}

#if defined(_WIN32) && defined(_MSC_VER) && !defined(NDEBUG)
	SymCleanup(GetCurrentProcess());
#endif

	return result;
}
