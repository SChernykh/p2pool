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
#include "p2pool.h"
#include "zmq_reader.h"
#include "mempool.h"
#include "json_rpc_request.h"
#include "rapidjson/document.h"
#include "json_parsers.h"
#include "pow_hash.h"
#include "block_template.h"
#include "side_chain.h"
#include "stratum_server.h"
#include "p2p_server.h"
#ifdef WITH_RANDOMX
#include "miner.h"
#endif
#include "params.h"
#include "console_commands.h"
#include "crypto.h"
#include "p2pool_api.h"
#include "pool_block.h"
#include "keccak.h"
#include "merkle.h"
#include "merge_mining_client.h"
#include <thread>
#include <fstream>
#include <numeric>

LOG_CATEGORY(P2Pool)

constexpr int BLOCK_HEADERS_REQUIRED = 720;

constexpr uint64_t SEEDHASH_EPOCH_BLOCKS = 2048;
constexpr uint64_t SEEDHASH_EPOCH_LAG = 64;

constexpr char FOUND_BLOCKS_FILE[] = "p2pool.blocks";

namespace p2pool {

p2pool::p2pool(int argc, char* argv[])
	: m_stopped(false)
	, m_updateSeed(true)
	, m_submitBlockData{}
	, m_zmqLastActive(0)
	, m_startTime(seconds_since_epoch())
	, m_lastMinerDataReceived(0)
{
	LOGINFO(1, log::LightCyan() << VERSION);

	Params* p = new Params(argc, argv);

	if (!p->valid()) {
		LOGERR(1, "Invalid or missing command line. Try \"p2pool --help\".");
		delete p;
		throw std::exception();
	}

	m_params = p;

#ifdef WITH_UPNP
	if (p->m_upnp) {
		init_upnp();
	}
#endif

	for (Params::Host& h : p->m_hosts) {
		if (!h.init_display_name(*p)) {
			throw std::exception();
		}
	}

	m_currentHostIndex = 0;

	m_hostPing.resize(p->m_hosts.size());

	hash pub, sec, eph_public_key;
	generate_keys(pub, sec);

	uint8_t view_tag;
	if (!p->m_wallet.get_eph_public_key(sec, 0, eph_public_key, view_tag)) {
		LOGERR(1, "Invalid wallet address: get_eph_public_key failed");
		throw std::exception();
	}

	const NetworkType type = p->m_wallet.type();

	if (type == NetworkType::Testnet) {
		LOGWARN(1, "Mining to a testnet wallet address");
	}
	else if (type == NetworkType::Stagenet) {
		LOGWARN(1, "Mining to a stagenet wallet address");
	}

	int err = uv_async_init(uv_default_loop_checked(), &m_submitBlockAsync, on_submit_block);
	if (err) {
		LOGERR(1, "uv_async_init failed, error " << uv_err_name(err));
		throw std::exception();
	}
	m_submitBlockAsync.data = this;

	err = uv_async_init(uv_default_loop_checked(), &m_submitAuxBlockAsync, on_submit_aux_block);
	if (err) {
		LOGERR(1, "uv_async_init failed, error " << uv_err_name(err));
		throw std::exception();
	}
	m_submitAuxBlockAsync.data = this;

	err = uv_async_init(uv_default_loop_checked(), &m_blockTemplateAsync, on_update_block_template);
	if (err) {
		LOGERR(1, "uv_async_init failed, error " << uv_err_name(err));
		throw std::exception();
	}
	m_blockTemplateAsync.data = this;

	err = uv_async_init(uv_default_loop_checked(), &m_stopAsync, on_stop);
	if (err) {
		LOGERR(1, "uv_async_init failed, error " << uv_err_name(err));
		throw std::exception();
	}
	m_stopAsync.data = this;

	err = uv_async_init(uv_default_loop_checked(), &m_reconnectToHostAsync, on_reconnect_to_host);
	if (err) {
		LOGERR(1, "uv_async_init failed, error " << uv_err_name(err));
		throw std::exception();
	}
	m_reconnectToHostAsync.data = this;

	uv_rwlock_init_checked(&m_mainchainLock);
	uv_rwlock_init_checked(&m_minerDataLock);
	uv_rwlock_init_checked(&m_ZMQReaderLock);
	uv_rwlock_init_checked(&m_mergeMiningClientsLock);
	uv_rwlock_init_checked(&m_auxIdLock);
	uv_mutex_init_checked(&m_foundBlocksLock);
#ifdef WITH_RANDOMX
	uv_mutex_init_checked(&m_minerLock);
#endif
	uv_mutex_init_checked(&m_submitBlockDataLock);
	uv_mutex_init_checked(&m_submitAuxBlockDataLock);

	m_api = p->m_apiPath.empty() ? nullptr : new p2pool_api(p->m_apiPath, p->m_localStats);

	if (p->m_localStats && !m_api) {
		LOGERR(1, "--local-api and --stratum-api command line parameters can't be used without --data-api");
		throw std::exception();
	}

	m_sideChain = new SideChain(this, type, p->m_mini ? "mini" : nullptr);

	if (p->m_p2pAddresses.empty()) {
		const int p2p_port = m_sideChain->is_mini() ? DEFAULT_P2P_PORT_MINI : DEFAULT_P2P_PORT;

		char buf[48] = {};
		log::Stream s(buf);
		s << "[::]:" << p2p_port << ",0.0.0.0:" << p2p_port;

		p->m_p2pAddresses = buf;
	}

#ifdef WITH_RANDOMX
	if (p->m_disableRandomX) {
		m_hasher = new RandomX_Hasher_RPC(this);
	}
	else {
		m_hasher = new RandomX_Hasher(this);
	}
#else
	m_hasher = new RandomX_Hasher_RPC(this);
#endif

	m_blockTemplate = new BlockTemplate(m_sideChain, m_hasher);
	m_mempool = new Mempool();

	try {
		m_consoleCommands = new ConsoleCommands(this);
	}
	catch (...) {
		LOGERR(1, "Couldn't start console commands handler");
		m_consoleCommands = nullptr;
	}
}

p2pool::~p2pool()
{
#ifdef WITH_UPNP
	if (m_params->m_upnp) {
		destroy_upnp();
	}
#endif

	{
		WriteLock lock(m_mergeMiningClientsLock);

		for (const IMergeMiningClient* c : m_mergeMiningClients) {
			delete c;
		}
		m_mergeMiningClients.clear();
	}

	uv_rwlock_destroy(&m_mainchainLock);
	uv_rwlock_destroy(&m_minerDataLock);
	uv_rwlock_destroy(&m_ZMQReaderLock);
	uv_rwlock_destroy(&m_mergeMiningClientsLock);
	uv_rwlock_destroy(&m_auxIdLock);
	uv_mutex_destroy(&m_foundBlocksLock);
#ifdef WITH_RANDOMX
	uv_mutex_destroy(&m_minerLock);
#endif
	uv_mutex_destroy(&m_submitBlockDataLock);
	uv_mutex_destroy(&m_submitAuxBlockDataLock);

	delete m_api;
	delete m_sideChain;
	delete m_hasher;
	delete m_blockTemplate;
	delete m_mempool;
	delete m_params;
}

void p2pool::update_host_ping(const std::string& display_name, double ping)
{
	if (ping < 100) {
		LOGINFO(1, display_name << " ping is " << ping << " ms");
	}
	else {
		LOGWARN(1, display_name << " ping is " << ping << " ms, this is too high for an efficient mining. Try to use a different node, or your own local node.");
	}

	const std::vector<Params::Host>& v = m_params->m_hosts;

	for (size_t i = 0, n = v.size(); i < n; ++i) {
		if (v[i].m_displayName == display_name) {
			m_hostPing[i] = ping;
			return;
		}
	}
}

void p2pool::print_hosts() const
{
	const Params::Host& host = current_host();

	for (size_t i = 0, n = m_params->m_hosts.size(); i < n; ++i) {
		const Params::Host& h = m_params->m_hosts[i];

		char buf[64] = {};
		if (m_hostPing[i] > 0.0) {
			log::Stream s(buf);
			s << " (" << m_hostPing[i] << " ms)";
		}

		if (h.m_displayName == host.m_displayName) {
			LOGINFO(0, log::LightCyan() << "-> " << h.m_displayName << static_cast<const char*>(buf));
		}
		else {
			LOGINFO(0, "   " << h.m_displayName << static_cast<const char*>(buf));
		}
	}
}

bool p2pool::calculate_hash(const void* data, size_t size, uint64_t height, const hash& seed, hash& result, bool force_light_mode)
{
	return m_hasher->calculate(data, size, height, seed, result, force_light_mode);
}

uint64_t p2pool::get_seed_height(uint64_t height)
{
	if (LIKELY(height > SEEDHASH_EPOCH_LAG)) {
		return (height - SEEDHASH_EPOCH_LAG - 1) & ~(SEEDHASH_EPOCH_BLOCKS - 1);
	}
	return 0;
}

bool p2pool::get_seed(uint64_t height, hash& seed) const
{
	ReadLock lock(m_mainchainLock);

	auto it = m_mainchainByHeight.find(get_seed_height(height));
	if (it == m_mainchainByHeight.end()) {
		return false;
	}

	seed = it->second.id;
	return true;
}

#ifdef WITH_RANDOMX
void p2pool::print_miner_status()
{
	MutexLock lock(m_minerLock);

	if (m_miner) {
		m_miner->print_status();
	}
}
#endif

void p2pool::print_merge_mining_status() const
{
	ReadLock lock(m_mergeMiningClientsLock);

	for (const IMergeMiningClient* client : m_mergeMiningClients) {
		client->print_status();
	}
}

void p2pool::handle_tx(TxMempoolData& tx)
{
	if (!tx.weight || !tx.fee) {
		LOGWARN(1, "invalid transaction: tx id = " << tx.id << ", size = " << tx.blob_size << ", weight = " << tx.weight << ", fee = " << static_cast<double>(tx.fee) / 1e6 << " um");
		return;
	}

	m_mempool->add(tx);

	LOGINFO(5,
		"new tx id = " << log::LightBlue() << tx.id << log::NoColor() <<
		", size = " << log::Gray() << tx.blob_size << log::NoColor() <<
		", weight = " << log::Gray() << tx.weight << log::NoColor() <<
		", fee = " << log::Gray() << static_cast<double>(tx.fee) / 1e6 << " um");

	if (tx.fee >= HIGH_FEE_VALUE) {
		LOGINFO(4, "high fee tx received: " << log::LightBlue() << tx.id << log::NoColor() << ", " << log::XMRAmount(tx.fee) << " - updating block template");
		update_block_template_async();
	}

#if TEST_MEMPOOL_PICKING_ALGORITHM
	m_blockTemplate->update(miner_data(), *m_mempool, &m_params->m_wallet);
#endif

	m_zmqLastActive = seconds_since_epoch();
}

void p2pool::handle_miner_data(MinerData& data)
{
#if TEST_MEMPOOL_PICKING_ALGORITHM
	if (m_mempool->m_transactions.size() < data.tx_backlog.size()) {
		m_mempool->swap(data.tx_backlog);
	}
#else
	m_mempool->swap(data.tx_backlog);
#endif

	{
		WriteLock lock(m_mainchainLock);

		ChainMain& c0 = m_mainchainByHeight[data.height];
		c0.height = data.height;
		c0.difficulty = data.difficulty;

		ChainMain& c1 = m_mainchainByHeight[data.height - 1];
		c1.height = data.height - 1;
		c1.id = data.prev_id;

		m_mainchainByHash[c1.id] = c1;

		cleanup_mainchain_data(data.height);
	}

	data.tx_backlog.clear();
	data.time_received = std::chrono::high_resolution_clock::now();
	{
		WriteLock lock(m_minerDataLock);
		data.aux_chains = m_minerData.aux_chains;
		data.aux_nonce = m_minerData.aux_nonce;
		m_minerData = data;
	}
	m_updateSeed = true;
	update_median_timestamp();
	update_aux_data(hash());

	const Params::Host& host = current_host();

	LOGINFO(2,
		"new miner data\n---------------------------------------------------------------------------------------------------------------" <<
		"\nhost                    = " << host.m_displayName <<
		"\nmajor_version           = " << data.major_version <<
		"\nheight                  = " << data.height <<
		"\nprev_id                 = " << log::LightBlue() << data.prev_id << log::NoColor() <<
		"\nseed_hash               = " << log::LightBlue() << data.seed_hash << log::NoColor() <<
		"\ndifficulty              = " << data.difficulty <<
		"\nmedian_weight           = " << data.median_weight <<
		"\nalready_generated_coins = " << data.already_generated_coins <<
		"\ntransactions            = " << m_mempool->size() <<
		"\n---------------------------------------------------------------------------------------------------------------"
	);

	// Tx secret keys from all miners change every block, so cache can be cleared here
	if (m_sideChain->precalcFinished()) {
		// Clear all cache entries older than the previous miner data
		clear_crypto_cache(m_lastMinerDataReceived);
	}

	m_lastMinerDataReceived = seconds_since_epoch();

	if (!is_main_thread()) {
		update_block_template_async();
	}
	else {
		update_block_template();
	}

	m_zmqLastActive = seconds_since_epoch();

	if (m_serversStarted.load()) {
		std::vector<uint64_t> missing_heights;
		{
			WriteLock lock(m_mainchainLock);

			for (uint64_t h = data.height; h && (h + BLOCK_HEADERS_REQUIRED > data.height); --h) {
				auto it = m_mainchainByHeight.find(h);
				if ((it == m_mainchainByHeight.end()) || it->second.difficulty.empty()) {
					LOGWARN(3, "Mainchain data for height " << h << " is missing, requesting it from monerod again");
					missing_heights.push_back(h);
				}
			}
		}

		for (uint64_t h : missing_heights) {
			char buf[log::Stream::BUF_SIZE + 1] = {};
			log::Stream s(buf);
			s << "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"get_block_header_by_height\",\"params\":{\"height\":" << h << "}}\0";

			JSONRPCRequest::call(host.m_address, host.m_rpcPort, buf, host.m_rpcLogin, m_params->m_socks5Proxy,
				[this, h](const char* data, size_t size, double)
				{
					ChainMain block;
					if (!parse_block_header(data, size, block)) {
						LOGERR(1, "couldn't download block header for height " << h);
					}
				},
				[h](const char* data, size_t size, double)
				{
					if (size > 0) {
						LOGERR(1, "couldn't download block header for height " << h << ", error " << log::const_buf(data, size));
					}
				});
		}
	}
}

const char* BLOCK_FOUND = "\n\
-----------------------------------------------------------------------------------------------\n\
| ######   #        #######   #####   #    #      #######  #######  #     #  #     #  ######  |\n\
| #     #  #        #     #  #     #  #   #       #        #     #  #     #  ##    #  #     # |\n\
| #     #  #        #     #  #        #  #        #        #     #  #     #  # #   #  #     # |\n\
| ######   #        #     #  #        ###         #####    #     #  #     #  #  #  #  #     # |\n\
| #     #  #        #     #  #        #  #        #        #     #  #     #  #   # #  #     # |\n\
| #     #  #        #     #  #     #  #   #       #        #     #  #     #  #    ##  #     # |\n\
| ######   #######  #######   #####   #    #      #        #######   #####   #     #  ######  |\n\
-----------------------------------------------------------------------------------------------";

void p2pool::handle_chain_main(ChainMain& data, const char* extra)
{
	{
		WriteLock lock(m_mainchainLock);

		ChainMain& c = m_mainchainByHeight[data.height];
		c.height = data.height;
		c.timestamp = data.timestamp;
		c.reward = data.reward;

		// data.id not filled in here, but c.id should be available. Copy it to data.id for logging
		data.id = c.id;

		m_mainchainByHash[c.id] = c;
	}
	update_median_timestamp();

	root_hash merkle_root;
	if (extra) {
		const size_t n = strlen(extra);
		if (n >= HASH_SIZE * 2) {
			const char* s = extra + n - HASH_SIZE * 2;
			for (size_t i = 0; i < HASH_SIZE; ++i) {
				uint8_t d[2];
				if (!from_hex(s[i * 2], d[0]) || !from_hex(s[i * 2 + 1], d[1])) {
					merkle_root = {};
					break;
				}
				merkle_root.h[i] = (d[0] << 4) | d[1];
			}
		}
	}

	LOGINFO(2, "new main chain block: height = " << log::Gray() << data.height << log::NoColor() <<
		", id = " << log::LightBlue() << data.id << log::NoColor() <<
		", timestamp = " << log::Gray() << data.timestamp << log::NoColor() << 
		", reward = " << log::Gray() << log::XMRAmount(data.reward));

	if (!merkle_root.empty()) {
		const PoolBlock* block = side_chain().find_block_by_merkle_root(merkle_root);
		if (block) {
			const Wallet& w = params().m_wallet;

			const char* who = (block->m_minerWallet == w) ? "you" : "someone else in this p2pool";
			LOGINFO(0, log::LightGreen() << "BLOCK FOUND: main chain block at height " << data.height << " was mined by " << who << BLOCK_FOUND);

			const uint64_t payout = block->get_payout(w);
			if (payout) {
				LOGINFO(0, log::LightCyan() << "Your wallet " << log::LightGreen() << w << log::LightCyan() << " got a payout of " << log::LightGreen() << log::XMRAmount(payout) << log::LightCyan() << " in block " << log::LightGreen() << data.height);
			}
			else {
				LOGINFO(0, log::LightCyan() << "Your wallet " << log::LightYellow() << w << log::LightCyan() << " didn't get a payout in block " << log::LightYellow() << data.height << log::LightCyan() << " because you had no shares in PPLNS window");
			}

			api_update_block_found(&data, block);
		}
		else {
			side_chain().watch_mainchain_block(data, merkle_root);
		}
	}

	api_update_network_stats();

	m_zmqLastActive = seconds_since_epoch();
}

void p2pool::update_aux_data(const hash& chain_id)
{
	MinerData data;
	std::vector<hash> aux_id;

	{
		ReadLock lock(m_mergeMiningClientsLock);

		if (!m_mergeMiningClients.empty()) {
			data.aux_chains.reserve(m_mergeMiningClients.size());

			aux_id.reserve(m_mergeMiningClients.size() + 1);

			IMergeMiningClient::ChainParameters params;

			for (const IMergeMiningClient* c : m_mergeMiningClients) {
				if (c->get_params(params)) {
					data.aux_chains.emplace_back(params.aux_id, params.aux_hash, params.aux_diff);
					aux_id.emplace_back(params.aux_id);
				}
			}
			aux_id.emplace_back(m_sideChain->consensus_hash());
		}
	}

	if (!aux_id.empty()) {
		WriteLock lock(m_auxIdLock);

		if (aux_id == m_auxId) {
			data.aux_nonce = m_auxNonce;
		}
		else if (find_aux_nonce(aux_id, data.aux_nonce)) {
			m_auxId = std::move(aux_id);
			m_auxNonce = data.aux_nonce;
		}
		else {
			LOGERR(1, "Failed to find the aux nonce for merge mining. Merge mining will be off this round.");
			data.aux_chains.clear();
		}
	}

	{
		WriteLock lock(m_minerDataLock);

		if ((m_minerData.aux_nonce == data.aux_nonce) && (m_minerData.aux_chains == data.aux_chains)) {
			return;
		}

		m_minerData.aux_chains = data.aux_chains;
		m_minerData.aux_nonce = data.aux_nonce;
		LOGINFO(5, "update_aux_data: n_aux_chains = " << m_minerData.aux_chains.size() << ", aux_nonce = " << m_minerData.aux_nonce);
	}

	if (!chain_id.empty()) {
		LOGINFO(4, "New aux data from chain " << chain_id);
		if (!is_main_thread()) {
			update_block_template_async();
		}
		else {
			update_block_template();
		}
	}
}

void p2pool::submit_block_async(uint32_t template_id, uint32_t nonce, uint32_t extra_nonce)
{
	{
		MutexLock lock(m_submitBlockDataLock);

		m_submitBlockData.template_id = template_id;
		m_submitBlockData.nonce = nonce;
		m_submitBlockData.extra_nonce = extra_nonce;
		m_submitBlockData.blob.clear();
	}

	// If p2pool is stopped, m_submitBlockAsync is most likely already closed
	if (m_stopped) {
		LOGWARN(0, "p2pool is shutting down, but a block was found. Trying to submit it anyway!");
		submit_block();
		return;
	}

	const int err = uv_async_send(&m_submitBlockAsync);
	if (err) {
		LOGERR(1, "uv_async_send failed, error " << uv_err_name(err));
	}
}

void p2pool::submit_block_async(std::vector<uint8_t>&& blob)
{
	{
		MutexLock lock(m_submitBlockDataLock);

		m_submitBlockData.template_id = 0;
		m_submitBlockData.nonce = 0;
		m_submitBlockData.extra_nonce = 0;
		m_submitBlockData.blob = std::move(blob);
	}

	// If p2pool is stopped, m_submitBlockAsync is most likely already closed
	if (m_stopped) {
		LOGWARN(0, "p2pool is shutting down, but a block was found. Trying to submit it anyway!");
		submit_block();
		return;
	}

	const int err = uv_async_send(&m_submitBlockAsync);
	if (err) {
		LOGERR(1, "uv_async_send failed, error " << uv_err_name(err));
	}
}

void p2pool::submit_aux_block_async(const std::vector<SubmitAuxBlockData>& aux_blocks)
{
	{
		MutexLock lock(m_submitAuxBlockDataLock);
		m_submitAuxBlockData.insert(m_submitAuxBlockData.end(), aux_blocks.begin(), aux_blocks.end());
	}

	// If p2pool is stopped, m_submitAuxBlockAsync is most likely already closed
	if (m_stopped) {
		LOGWARN(0, "p2pool is shutting down, but a block was found. Trying to submit it anyway!");
		submit_aux_block();
		return;
	}

	const int err = uv_async_send(&m_submitAuxBlockAsync);
	if (err) {
		LOGERR(1, "uv_async_send failed, error " << uv_err_name(err));
	}
}

void p2pool::submit_aux_block() const
{
	std::vector<SubmitAuxBlockData> submit_data;
	{
		MutexLock lock(m_submitAuxBlockDataLock);
		m_submitAuxBlockData.swap(submit_data);
	}

	for (size_t i = 0; i < submit_data.size(); ++i) {
		const hash chain_id = submit_data[i].chain_id;
		const uint32_t template_id = submit_data[i].template_id;
		const uint32_t nonce = submit_data[i].nonce;
		const uint32_t extra_nonce = submit_data[i].extra_nonce;

		LOGINFO(3, "submit_aux_block: template id = " << template_id << ", chain_id = " << chain_id << ", nonce = " << nonce << ", extra_nonce = " << extra_nonce);

		size_t nonce_offset = 0;
		size_t extra_nonce_offset = 0;
		size_t merkle_root_offset = 0;
		root_hash merge_mining_root;
		const BlockTemplate* block_tpl = nullptr;

		std::vector<uint8_t> blob = m_blockTemplate->get_block_template_blob(template_id, extra_nonce, nonce_offset, extra_nonce_offset, merkle_root_offset, merge_mining_root, &block_tpl);

		uint8_t hashing_blob[128] = {};
		uint64_t height = 0;
		difficulty_type diff, aux_diff, sidechain_diff;
		hash seed_hash;

		m_blockTemplate->get_hashing_blob(template_id, extra_nonce, hashing_blob, height, diff, aux_diff, sidechain_diff, seed_hash, nonce_offset);

		if (blob.empty()) {
			LOGWARN(3, "submit_aux_block: block template blob not found");
			return;
		}

		uint8_t* p = blob.data();
		memcpy(p + nonce_offset, &nonce, NONCE_SIZE);
		memcpy(p + extra_nonce_offset, &extra_nonce, EXTRA_NONCE_SIZE);
		memcpy(p + merkle_root_offset, merge_mining_root.h, HASH_SIZE);

		ReadLock lock(m_mergeMiningClientsLock);

		IMergeMiningClient::ChainParameters chain_params;

		for (IMergeMiningClient* c : m_mergeMiningClients) {
			if (!c->get_params(chain_params)) {
				continue;
			}

			if (chain_id == chain_params.aux_id) {
				std::vector<hash> proof;
				uint32_t path;

				if (m_blockTemplate->get_aux_proof(template_id, extra_nonce, chain_params.aux_hash, proof, path)) {
					if (pool_block_debug()) {
						const MinerData data = miner_data();
						const uint32_t n_aux_chains = static_cast<uint32_t>(data.aux_chains.size() + 1);
						const uint32_t index = get_aux_slot(chain_params.aux_id, data.aux_nonce, n_aux_chains);

						if (!verify_merkle_proof(chain_params.aux_hash, proof, index, n_aux_chains, merge_mining_root)) {
							LOGERR(0, "submit_aux_block: verify_merkle_proof (1) failed for chain_id " << chain_id);
						}
						if (!verify_merkle_proof(chain_params.aux_hash, proof, path, merge_mining_root)) {
							LOGERR(0, "submit_aux_block: verify_merkle_proof (2) failed for chain_id " << chain_id);
						}
					}

					c->submit_solution(block_tpl, hashing_blob, nonce_offset, seed_hash, blob, proof, path);
				}
				else {
					LOGWARN(3, "submit_aux_block: failed to get merkle proof for chain_id " << chain_id);
				}

				break;
			}
		}
	}
}

bool init_signals(p2pool* pool, bool init);

void p2pool::on_stop(uv_async_t* async)
{
	p2pool* pool = reinterpret_cast<p2pool*>(async->data);

	delete pool->m_consoleCommands;

	if (pool->m_api) {
		pool->m_api->on_stop();
	}

	uv_close(reinterpret_cast<uv_handle_t*>(&pool->m_submitBlockAsync), nullptr);
	uv_close(reinterpret_cast<uv_handle_t*>(&pool->m_submitAuxBlockAsync), nullptr);
	uv_close(reinterpret_cast<uv_handle_t*>(&pool->m_blockTemplateAsync), nullptr);
	uv_close(reinterpret_cast<uv_handle_t*>(&pool->m_stopAsync), nullptr);
	uv_close(reinterpret_cast<uv_handle_t*>(&pool->m_reconnectToHostAsync), nullptr);

	init_signals(pool, false);

	uv_loop_t* loop = uv_default_loop_checked();
	delete GetLoopUserData(loop, false);
	loop->data = nullptr;
}

void p2pool::submit_block() const
{
	SubmitBlockData submit_data;
	{
		MutexLock lock(m_submitBlockDataLock);
		submit_data = m_submitBlockData;
	}

	const uint64_t height = m_blockTemplate->height();
	const difficulty_type diff = m_blockTemplate->difficulty();

	size_t nonce_offset = 0;
	size_t extra_nonce_offset = 0;
	size_t merkle_root_offset = 0;
	hash merge_mining_root;
	const BlockTemplate* block_tpl = nullptr;

	bool is_external = false;

	if (submit_data.blob.empty()) {
		submit_data.blob = m_blockTemplate->get_block_template_blob(submit_data.template_id, submit_data.extra_nonce, nonce_offset, extra_nonce_offset, merkle_root_offset, merge_mining_root, &block_tpl);

		LOGINFO(0, log::LightGreen() << "submit_block: height = " << height
			<< ", template id = " << submit_data.template_id
			<< ", nonce = " << submit_data.nonce
			<< ", extra_nonce = " << submit_data.extra_nonce
			<< ", mm_root = " << merge_mining_root);

		if (submit_data.blob.empty()) {
			LOGERR(0, "submit_block: couldn't find block template with id " << submit_data.template_id);
			return;
		}
	}
	else {
		LOGINFO(0, log::LightGreen() << "submit_block: height = " << height << ", external blob (" << submit_data.blob.size() << " bytes)");
		is_external = true;
	}

	std::string request;
	request.reserve(submit_data.blob.size() * 2 + 128);

	request = "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"submit_block\",\"params\":[\"";

	const uint32_t template_id = submit_data.template_id;
	const uint32_t nonce = submit_data.nonce;
	const uint32_t extra_nonce = submit_data.extra_nonce;

	for (size_t i = 0; i < submit_data.blob.size(); ++i) {
		uint8_t b;
		if (nonce_offset && nonce_offset <= i && i < nonce_offset + sizeof(submit_data.nonce)) {
			b = submit_data.nonce & 255;
			submit_data.nonce >>= 8;
		}
		else if (extra_nonce_offset && extra_nonce_offset <= i && i < extra_nonce_offset + sizeof(submit_data.extra_nonce)) {
			b = submit_data.extra_nonce & 255;
			submit_data.extra_nonce >>= 8;
		}
		else if (merkle_root_offset && merkle_root_offset <= i && i < merkle_root_offset + HASH_SIZE) {
			b = merge_mining_root.h[i - merkle_root_offset];
		}
		else {
			b = submit_data.blob[i];
		}
		request.append(1, "0123456789abcdef"[b >> 4]);
		request.append(1, "0123456789abcdef"[b & 15]);
	}
	request.append("\"]}");

	const Params::Host& host = current_host();

	JSONRPCRequest::call(host.m_address, host.m_rpcPort, request, host.m_rpcLogin, m_params->m_socks5Proxy,
		[height, diff, template_id, nonce, extra_nonce, merge_mining_root, is_external](const char* data, size_t size, double)
		{
			rapidjson::Document doc;
			if (doc.Parse(data, size).HasParseError() || !doc.IsObject()) {
				LOGERR(0, "submit_block: invalid JSON response from daemon");
				return;
			}

			if (doc.HasMember("error")) {
				auto& err = doc["error"];

				if (!err.IsObject()) {
					LOGERR(0, "submit_block: invalid JSON reponse from daemon: 'error' is not an object");
					return;
				}

				const char* error_msg = nullptr;

				auto it = err.FindMember("message");
				if (it != err.MemberEnd() && it->value.IsString()) {
					error_msg = it->value.GetString();
				}

				if (is_external) {
					LOGWARN(3, "submit_block (external blob): daemon returned error: " << (error_msg ? error_msg : "unknown error"));
				}
				else {
					LOGERR(0, "submit_block: daemon returned error: '" << (error_msg ? error_msg : "unknown error") << "', template id = " << template_id << ", nonce = " << nonce << ", extra_nonce = " << extra_nonce << ", mm_root = " << merge_mining_root);
				}
				return;
			}

			auto it = doc.FindMember("result");
			if (it != doc.MemberEnd() && it->value.IsObject()) {
				auto& result = it->value;
				auto it2 = result.FindMember("status");
				if (it2 != result.MemberEnd() && it2->value.IsString() && (strcmp(it2->value.GetString(), "OK") == 0)) {
					LOGINFO(0, log::LightGreen() << "submit_block: BLOCK ACCEPTED at height " << height << " and difficulty = " << diff);
					return;
				}
			}

			LOGWARN(0, "submit_block: daemon sent unrecognizable reply: " << log::const_buf(data, size));
		},
		[is_external](const char* data, size_t size, double)
		{
			if (size > 0) {
				if (is_external) {
					LOGWARN(3, "submit_block (external blob): RPC request failed, error " << log::const_buf(data, size));
				}
				else {
					LOGERR(0, "submit_block: RPC request failed, error " << log::const_buf(data, size));
				}
			}
		});
}

bool p2pool::submit_sidechain_block(uint32_t template_id, uint32_t nonce, uint32_t extra_nonce)
{
	LOGINFO(3, "submit_sidechain_block: template id = " << template_id << ", nonce = " << nonce << ", extra_nonce = " << extra_nonce);
	return m_blockTemplate->submit_sidechain_block(template_id, nonce, extra_nonce);
}

void p2pool::update_block_template_async(bool is_alternative_block)
{
	// If p2pool is stopped, m_blockTemplateAsync is most likely already closed
	if (m_stopped) {
		return;
	}

	if (is_alternative_block) {
		m_isAlternativeBlock = true;
	}

	const int err = uv_async_send(&m_blockTemplateAsync);
	if (err) {
		LOGERR(1, "uv_async_send failed, error " << uv_err_name(err));
	}
}

void p2pool::update_block_template()
{
	MinerData data = miner_data();

	if (m_updateSeed.exchange(false)) {
		m_hasher->set_seed_async(data.seed_hash);
	}
	m_blockTemplate->update(data, *m_mempool, &m_params->m_wallet);
	stratum_on_block();
	api_update_pool_stats();

#ifdef WITH_RANDOMX
	if (m_isAlternativeBlock.exchange(false)) {
		MutexLock lock(m_minerLock);

		if (m_miner) {
			m_miner->reset_share_counters();
		}
	}
#endif
}

void p2pool::download_block_headers(uint64_t current_height)
{
	const uint64_t seed_height = get_seed_height(current_height);
	const uint64_t prev_seed_height = (seed_height > SEEDHASH_EPOCH_BLOCKS) ? (seed_height - SEEDHASH_EPOCH_BLOCKS) : 0;

	char buf[log::Stream::BUF_SIZE + 1] = {};
	log::Stream s(buf);

	const Params::Host& host = current_host();

	// First download 2 RandomX seeds
	const uint64_t seed_heights[2] = { prev_seed_height, seed_height };
	for (uint64_t height : seed_heights) {
		s.m_pos = 0;
		s << "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"get_block_header_by_height\",\"params\":{\"height\":" << height << "}}\0";

		JSONRPCRequest::call(host.m_address, host.m_rpcPort, buf, host.m_rpcLogin, m_params->m_socks5Proxy,
			[this, prev_seed_height, height](const char* data, size_t size, double)
			{
				ChainMain block;
				if (parse_block_header(data, size, block)) {
					if (height == prev_seed_height) {
						// Do it synchronously to make sure stratum and p2p don't start before it's finished
						m_hasher->set_old_seed(block.id);
					}
				}
				else {
					LOGERR(1, "fatal error: couldn't download block header for seed height " << height);
					PANIC_STOP();
				}
			},
			[height](const char* data, size_t size, double)
			{
				if (size > 0) {
					LOGERR(1, "fatal error: couldn't download block header for seed height " << height << ", error " << log::const_buf(data, size));
					PANIC_STOP();
				}
			});
	}

	const uint64_t start_height = (current_height > BLOCK_HEADERS_REQUIRED) ? (current_height - BLOCK_HEADERS_REQUIRED) : 0;

	s.m_pos = 0;
	s << "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"get_block_headers_range\",\"params\":{\"start_height\":" << start_height << ",\"end_height\":" << current_height - 1 << "}}\0";

	JSONRPCRequest::call(host.m_address, host.m_rpcPort, buf, host.m_rpcLogin, m_params->m_socks5Proxy,
		[this, start_height, current_height, host](const char* data, size_t size, double)
		{
			if (parse_block_headers_range(data, size) == current_height - start_height) {
				update_median_timestamp();
				if (m_serversStarted.exchange(1) == 0) {
					m_stratumServer = new StratumServer(this);
					m_p2pServer = new P2PServer(this);
#ifdef WITH_RANDOMX
					if (m_params->m_minerThreads) {
						start_mining(m_params->m_minerThreads);
					}
#endif
					{
						WriteLock lock(m_ZMQReaderLock);

						try {
							m_ZMQReader = new ZMQReader(host.m_address, host.m_zmqPort, m_params->m_socks5Proxy, this);
							m_zmqLastActive = seconds_since_epoch();
						}
						catch (const std::exception& e) {
							LOGERR(1, "Couldn't start ZMQ reader: exception " << e.what());
							PANIC_STOP();
						}
					}

					api_update_network_stats();
					get_miner_data();

					// Get ping times for all other hosts
					for (const Params::Host& h : m_params->m_hosts) {
						const std::string& name = h.m_displayName;
						if (name != host.m_displayName) {
							JSONRPCRequest::call(h.m_address, h.m_rpcPort, "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"get_version\"}", h.m_rpcLogin, m_params->m_socks5Proxy,
								[this, name](const char*, size_t, double tcp_ping) { update_host_ping(name, tcp_ping); },
								[](const char*, size_t, double) {});
						}
					}

					{
						WriteLock lock(m_mergeMiningClientsLock);

						m_mergeMiningClients.clear();

						for (const auto& h : m_params->m_mergeMiningHosts) {
							IMergeMiningClient* c = IMergeMiningClient::create(this, h.m_host, h.m_wallet);
							if (c) {
								m_mergeMiningClients.push_back(c);
							}
						}
					}

					m_startupFinished = true;
				}
			}
			else {
				LOGERR(1, "Couldn't download block headers for heights " << start_height << " - " << current_height - 1);
				download_block_headers(current_height);
			}
		},
		[this, start_height, current_height](const char* data, size_t size, double)
		{
			if (size > 0) {
				LOGERR(1, "Couldn't download block headers for heights " << start_height << " - " << current_height - 1 << ", error " << log::const_buf(data, size));
				download_block_headers(current_height);
			}
		});
}

bool p2pool::chainmain_get_by_hash(const hash& id, ChainMain& data) const
{
	ReadLock lock(m_mainchainLock);

	auto it = m_mainchainByHash.find(id);
	if (it == m_mainchainByHash.end()) {
		return false;
	}

	data = it->second;
	return true;
}

bool p2pool::get_timestamps(uint64_t (&timestamps)[TIMESTAMP_WINDOW]) const
{
	ReadLock lock(m_mainchainLock);

	if (m_mainchainByHeight.size() < TIMESTAMP_WINDOW) {
		return false;
	}

	auto it = m_mainchainByHeight.end();

	for (int i = 0; i < TIMESTAMP_WINDOW; ++i) {
		--it;
		timestamps[i] = it->second.timestamp;
	}

	return true;
}

void p2pool::update_median_timestamp()
{
	uint64_t timestamps[TIMESTAMP_WINDOW];
	if (!get_timestamps(timestamps))
	{
		WriteLock lock(m_minerDataLock);
		m_minerData.median_timestamp = 0;
		return;
	}

	std::sort(timestamps, timestamps + TIMESTAMP_WINDOW);

	// Shift it +1 block compared to Monero's code because we don't have the latest block yet when we receive new miner data
	const uint64_t ts = (timestamps[TIMESTAMP_WINDOW / 2] + timestamps[TIMESTAMP_WINDOW / 2 + 1]) / 2;
	LOGINFO(4, "median timestamp updated to " << log::Gray() << ts);

	WriteLock lock(m_minerDataLock);
	m_minerData.median_timestamp = ts;
}

void p2pool::stratum_on_block()
{
#ifdef WITH_RANDOMX
	{
		MutexLock lock(m_minerLock);

		if (m_miner) {
			m_miner->on_block(*m_blockTemplate);
		}
	}
#endif

	if (m_stratumServer) {
		m_stratumServer->on_block(*m_blockTemplate);
	}
}

void p2pool::get_info()
{
	const Params::Host& host = current_host();

	JSONRPCRequest::call(host.m_address, host.m_rpcPort, "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"get_info\"}", host.m_rpcLogin, m_params->m_socks5Proxy,
		[this](const char* data, size_t size, double)
		{
			parse_get_info_rpc(data, size);
		},
		[this, host](const char* data, size_t size, double)
		{
			if (size > 0) {
				LOGWARN(1, "get_info RPC request to host " << host.m_displayName << " failed: error " << log::const_buf(data, size) << ", trying again in 1 second");
				if (!m_stopped) {
					std::this_thread::sleep_for(std::chrono::milliseconds(1000));
					switch_host();
					get_info();
				}
			}
		});
}

void p2pool::load_found_blocks()
{
	if (!m_api || m_stopped) {
		return;
	}

	std::ifstream f(FOUND_BLOCKS_FILE);
	if (!f.is_open()) {
		return;
	}

	while (f.good()) {
		time_t timestamp;
		f >> timestamp;
		if (!f.good()) break;

		uint64_t height;
		f >> height;
		if (!f.good()) break;

		hash id;
		f >> id;
		if (!f.good()) break;

		difficulty_type block_difficulty;
		f >> block_difficulty;
		if (!f.good()) break;

		difficulty_type cumulative_difficulty;
		f >> cumulative_difficulty;
		if (!f.good() && !f.eof()) break;

		m_foundBlocks.emplace_back(timestamp, height, id, block_difficulty, cumulative_difficulty);
	}

	api_update_block_found(nullptr, nullptr);
}

void p2pool::parse_get_info_rpc(const char* data, size_t size)
{
	if (m_stopped) {
		return;
	}

	rapidjson::Document doc;
	doc.Parse(data, size);

	if (doc.HasParseError() || !doc.IsObject() || !doc.HasMember("result")) {
		LOGWARN(1, "get_info RPC response is invalid (\"result\" not found), trying again in 1 second");
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		get_info();
		return;
	}

	const auto& result = doc["result"];

	struct {
		bool busy_syncing, synchronized, mainnet, testnet, stagenet;
	} info;

	if (!PARSE(result, info, busy_syncing) ||
		!PARSE(result, info, synchronized) ||
		!PARSE(result, info, mainnet) ||
		!PARSE(result, info, testnet) ||
		!PARSE(result, info, stagenet)) {
		LOGWARN(1, "get_info RPC response is invalid, trying again in 1 second");
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		get_info();
		return;
	}

	if (info.busy_syncing || !info.synchronized) {
		LOGINFO(1, "monerod is " << (info.busy_syncing ? "busy syncing" : "not synchronized") << ", trying again in 1 second");
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		get_info();
		return;
	}

	NetworkType monero_network = NetworkType::Invalid;

	if (info.mainnet)  monero_network = NetworkType::Mainnet;
	if (info.testnet)  monero_network = NetworkType::Testnet;
	if (info.stagenet) monero_network = NetworkType::Stagenet;

	const NetworkType sidechain_network = m_sideChain->network_type();

	if (monero_network != sidechain_network) {
		LOGERR(1, "monerod is on " << monero_network << ", but you're mining to a " << sidechain_network << " sidechain");
		PANIC_STOP();
	}

	get_version();
}

void p2pool::get_version()
{
	const Params::Host& host = current_host();

	JSONRPCRequest::call(host.m_address, host.m_rpcPort, "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"get_version\"}", host.m_rpcLogin, m_params->m_socks5Proxy,
		[this](const char* data, size_t size, double)
		{
			parse_get_version_rpc(data, size);
		},
		[this](const char* data, size_t size, double)
		{
			if (size > 0) {
				LOGWARN(1, "get_version RPC request failed: error " << log::const_buf(data, size) << ", trying again in 1 second");
				if (!m_stopped) {
					std::this_thread::sleep_for(std::chrono::milliseconds(1000));
					get_version();
				}
			}
		});
}

void p2pool::parse_get_version_rpc(const char* data, size_t size)
{
	if (m_stopped) {
		return;
	}

	rapidjson::Document doc;
	doc.Parse(data, size);

	if (doc.HasParseError() || !doc.IsObject() || !doc.HasMember("result")) {
		LOGWARN(1, "get_version RPC response is invalid (\"result\" not found), trying again in 1 second");
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		get_version();
		return;
	}

	const auto& result = doc["result"];

	std::string status;
	uint64_t version;

	if (!parseValue(result, "status", status) || !parseValue(result, "version", version)) {
		LOGWARN(1, "get_version RPC response is invalid, trying again in 1 second");
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		get_version();
		return;
	}

	if (status != "OK") {
		LOGWARN(1, "get_version RPC failed, trying again in 1 second");
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		get_version();
		return;
	}

	constexpr uint64_t major = 3;
	constexpr uint64_t minor = 10;
	constexpr uint64_t required = (major << 16) | minor;

	if (version < required) {
		const uint64_t version_hi = version >> 16;
		const uint64_t version_lo = version & 65535;
		const uint64_t required_version_hi = required >> 16;
		const uint64_t required_version_lo = required & 65535;
		LOGERR(1, "monerod RPC v" << version_hi << '.' << version_lo << " is incompatible, update to RPC >= v" << required_version_hi << '.' << required_version_lo << " (Monero v0.18.0.0 or newer)");
		PANIC_STOP();
	}

	get_miner_data();
}

void p2pool::get_miner_data(bool retry)
{
	if (m_getMinerDataPending) {
		return;
	}
	m_getMinerDataPending = true;

	const Params::Host& host = current_host();

	JSONRPCRequest::call(host.m_address, host.m_rpcPort, "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"get_miner_data\"}", host.m_rpcLogin, m_params->m_socks5Proxy,
		[this, host](const char* data, size_t size, double tcp_ping)
		{
			parse_get_miner_data_rpc(data, size);
			update_host_ping(host.m_displayName, tcp_ping);
		},
		[this, host, retry](const char* data, size_t size, double)
		{
			if (size > 0) {
				LOGWARN(1, "get_miner_data RPC request to host " << host.m_displayName << " failed: error " << log::const_buf(data, size) << (retry ? ", trying again in 1 second" : ""));
				if (!m_stopped && retry) {
					std::this_thread::sleep_for(std::chrono::milliseconds(1000));
					m_getMinerDataPending = false;
					get_miner_data();
					return;
				}
			}
			m_getMinerDataPending = false;
		});
}

void p2pool::parse_get_miner_data_rpc(const char* data, size_t size)
{
	if (m_stopped) {
		return;
	}

	hash h;
	keccak(reinterpret_cast<const uint8_t*>(data), static_cast<int>(size), h.h);
	if (h == m_getMinerDataHash) {
		LOGWARN(4, "Received a duplicate get_miner_data RPC response, ignoring it");
		return;
	}
	m_getMinerDataHash = h;

	rapidjson::Document doc;
	doc.Parse(data, size);

	if (doc.HasParseError() || !doc.IsObject() || !doc.HasMember("result")) {
		LOGWARN(1, "get_miner_data RPC response is invalid, skipping it");
		return;
	}

	MinerData minerData;

	const auto& result = doc["result"];

	if (!PARSE(result, minerData, major_version) ||
		!PARSE(result, minerData, height) ||
		!PARSE(result, minerData, prev_id) ||
		!PARSE(result, minerData, seed_hash) ||
		!PARSE(result, minerData, median_weight) ||
		!PARSE(result, minerData, already_generated_coins) ||
		!PARSE(result, minerData, difficulty)) {
		LOGWARN(1, "get_miner_data RPC response failed to parse, skipping it");
		return;
	}

	auto it = result.FindMember("tx_backlog");

	if ((it != result.MemberEnd()) && it->value.IsArray()) {
		const auto& tx_backlog = it->value.GetArray();
		for (rapidjson::SizeType i = 0, n = tx_backlog.Size(); i < n; ++i) {
			const auto& tx = tx_backlog[i];

			if (!tx.IsObject()) {
				continue;
			}

			TxMempoolData tx_data;
			if (PARSE(tx, tx_data, id) && PARSE(tx, tx_data, weight) && PARSE(tx, tx_data, fee)) {
				tx_data.blob_size = 0;
				minerData.tx_backlog.emplace_back(std::move(tx_data));
			}
		}
	}

	handle_miner_data(minerData);
	if (m_serversStarted.load() == 0) {
		download_block_headers(minerData.height);
	}
}

bool p2pool::parse_block_header(const char* data, size_t size, ChainMain& c)
{
	rapidjson::Document doc;
	if (doc.Parse(data, size).HasParseError() || !doc.IsObject()) {
		LOGERR(1, "parse_block_header: invalid JSON response from daemon");
		return false;
	}

	auto it = doc.FindMember("result");
	if (it == doc.MemberEnd() || !it->value.IsObject()) {
		LOGERR(1, "parse_block_header: invalid JSON response from daemon : 'result' is not found or not an object");
		return false;
	}

	auto it2 = it->value.FindMember("block_header");
	if (it2 == it->value.MemberEnd() || !it2->value.IsObject()) {
		LOGERR(1, "parse_block_header: invalid JSON response from daemon: 'block_header' is not found or not an object");
		return false;
	}

	const auto& v = it2->value;

	if (!parseValue(v, "difficulty", c.difficulty.lo) || !parseValue(v, "difficulty_top64", c.difficulty.hi)) {
		LOGERR(1, "parse_block_header: invalid JSON response from daemon: failed to parse difficulty");
		return false;
	}

	if (!PARSE(v, c, height) || !PARSE(v, c, timestamp) || !PARSE(v, c, reward) || !parseValue(v, "hash", c.id)) {
		LOGERR(1, "parse_block_header: invalid JSON response from daemon: failed to parse 'block_header'");
		return false;
	}

	{
		WriteLock lock(m_mainchainLock);
		m_mainchainByHeight[c.height] = c;
		m_mainchainByHash[c.id] = c;
	}

	LOGINFO(4, "parsed block header for height " << c.height);
	return true;
}

uint32_t p2pool::parse_block_headers_range(const char* data, size_t size)
{
	rapidjson::Document doc;
	if (doc.Parse(data, size).HasParseError() || !doc.IsObject()) {
		LOGERR(1, "parse_block_headers_range: invalid JSON response from daemon");
		return 0;
	}

	auto it = doc.FindMember("result");
	if (it == doc.MemberEnd() || !it->value.IsObject()) {
		LOGERR(1, "parse_block_headers_range: invalid JSON response from daemon: 'result' is not found or not an object");
		return 0;
	}

	auto it2 = it->value.FindMember("headers");
	if (it2 == it->value.MemberEnd() || !it2->value.IsArray()) {
		LOGERR(1, "parse_block_headers_range: invalid JSON response from daemon: 'headers' is not found or not an array");
		return 0;
	}

	uint32_t num_headers_parsed = 0;

	WriteLock lock(m_mainchainLock);

	auto headers = it2->value.GetArray();
	uint64_t min_height = std::numeric_limits<uint64_t>::max();
	uint64_t max_height = 0;
	for (auto i = headers.begin(); i != headers.end(); ++i) {
		if (!i->IsObject()) {
			continue;
		}

		ChainMain c;

		if (!parseValue(*i, "difficulty", c.difficulty.lo) || !parseValue(*i, "difficulty_top64", c.difficulty.hi)) {
			continue;
		}

		if (PARSE(*i, c, height) && PARSE(*i, c, timestamp) && PARSE(*i, c, reward) && parseValue(*i, "hash", c.id)) {
			min_height = std::min(min_height, c.height);
			max_height = std::max(max_height, c.height);
			m_mainchainByHeight[c.height] = c;
			m_mainchainByHash[c.id] = c;
			++num_headers_parsed;
		}
	}

	LOGINFO(4, "parsed " << num_headers_parsed << " block headers for heights " << min_height << " - " << max_height);
	return num_headers_parsed;
}

void p2pool::api_update_network_stats()
{
	if (!m_api || m_stopped) {
		return;
	}

	hash prev_id;
	{
		ReadLock lock(m_minerDataLock);
		prev_id = m_minerData.prev_id;
	}

	ChainMain mainnet_tip;
	{
		ReadLock lock(m_mainchainLock);
		mainnet_tip = m_mainchainByHash[prev_id];
	}

	m_api->set(p2pool_api::Category::NETWORK, "stats",
		[mainnet_tip](log::Stream& s)
		{
			s << "{\"difficulty\":" << mainnet_tip.difficulty
				<< ",\"hash\":\"" << mainnet_tip.id
				<< "\",\"height\":" << mainnet_tip.height
				<< ",\"reward\":" << mainnet_tip.reward
				<< ",\"timestamp\":" << mainnet_tip.timestamp << "}";
		});

	api_update_stats_mod();
}

void p2pool::api_update_pool_stats()
{
	if (!m_api || m_stopped) {
		return;
	}

	const PoolBlock* tip = m_sideChain->chainTip();
	const uint64_t bottom_height = m_sideChain->bottom_height(tip);
	const uint64_t pplns_window_size = (tip && bottom_height) ? (tip->m_sidechainHeight - bottom_height + 1U) : m_sideChain->chain_window_size();

	uint64_t t;
	const difficulty_type diff = m_sideChain->difficulty();
	const uint64_t height = tip ? tip->m_sidechainHeight : 0;
	const uint64_t hashrate = udiv128(diff.hi, diff.lo, m_sideChain->block_time(), &t);
	const uint64_t miners = std::max<uint64_t>(m_sideChain->miner_count(), m_p2pServer ? m_p2pServer->peer_list_size() : 0U);
	const difficulty_type total_hashes = m_sideChain->total_hashes();

	const auto& s = m_blockTemplate->shares();
	const difficulty_type pplns_weight = std::accumulate(s.begin(), s.end(), difficulty_type(), [](const auto& a, const auto& b) { return a + b.m_weight; });

	time_t last_block_found_time = 0;
	uint64_t last_block_found_height = 0;
	uint64_t total_blocks_found = 0;

	{
		MutexLock lock(m_foundBlocksLock);
		if (!m_foundBlocks.empty()) {
			total_blocks_found = m_foundBlocks.size();
			last_block_found_time = m_foundBlocks.back().timestamp;
			last_block_found_height = m_foundBlocks.back().height;
		}
	}

	m_api->set(p2pool_api::Category::POOL, "stats",
		[hashrate, miners, &total_hashes, last_block_found_time, last_block_found_height, total_blocks_found, &pplns_weight, pplns_window_size, diff, height](log::Stream& s)
		{
			s << "{\"pool_list\":[\"pplns\"],\"pool_statistics\":{\"hashRate\":" << hashrate
				<< ",\"miners\":" << miners
				<< ",\"totalHashes\":" << total_hashes
				<< ",\"lastBlockFoundTime\":" << last_block_found_time
				<< ",\"lastBlockFound\":" << last_block_found_height
				<< ",\"totalBlocksFound\":" << total_blocks_found
				<< ",\"pplnsWeight\":" << pplns_weight
				<< ",\"pplnsWindowSize\":" << pplns_window_size
				<< ",\"sidechainDifficulty\":" << diff
				<< ",\"sidechainHeight\":" << height
				<< "}}";
		});

	api_update_stats_mod();
}

void p2pool::api_update_stats_mod()
{
	if (!m_api || m_stopped) {
		return;
	}

	hash prev_id;
	{
		ReadLock lock(m_minerDataLock);
		prev_id = m_minerData.prev_id;
	}

	ChainMain mainnet_tip;
	{
		ReadLock lock(m_mainchainLock);
		mainnet_tip = m_mainchainByHash[prev_id];
	}

	time_t last_block_found_time = 0;
	uint64_t last_block_found_height = 0;
	hash last_block_found_hash;
	difficulty_type last_block_total_hashes;

	{
		MutexLock lock(m_foundBlocksLock);
		if (!m_foundBlocks.empty()) {
			const FoundBlock& b = m_foundBlocks.back();
			last_block_found_time = b.timestamp;
			last_block_found_height = b.height;
			last_block_found_hash = b.id;
			last_block_total_hashes = b.total_hashes;
		}
	}

	char last_block_found_buf[log::Stream::BUF_SIZE + 1];
	// cppcheck-suppress uninitvar
	log::Stream s(last_block_found_buf);
	s << last_block_found_hash << '\0';
	memcpy(last_block_found_buf + 4, "...", 4);

	const uint64_t miners = std::max<uint64_t>(m_sideChain->miner_count(), m_p2pServer ? m_p2pServer->peer_list_size() : 0U);

	uint64_t t;
	const difficulty_type& diff = m_sideChain->difficulty();
	const uint64_t hashrate = udiv128(diff.hi, diff.lo, m_sideChain->block_time(), &t);

	const difficulty_type total_hashes = m_sideChain->total_hashes();
	if (total_hashes < last_block_total_hashes) {
		return;
	}

	const uint64_t round_hashes = total_hashes.lo - last_block_total_hashes.lo;
	const int stratum_port = DEFAULT_STRATUM_PORT;

	m_api->set(p2pool_api::Category::GLOBAL, "stats_mod",
		[&mainnet_tip, last_block_found_time, &last_block_found_buf, last_block_found_height, miners, hashrate, round_hashes, stratum_port](log::Stream& s)
		{
			s << "{\"config\":{\"ports\":[{\"port\":" << stratum_port << ",\"tls\":false}],\"fee\":0,\"minPaymentThreshold\":300000000},\"network\":{\"height\":"
				<< mainnet_tip.height << "},\"pool\":{\"stats\":{\"lastBlockFound\":\""
				<< last_block_found_time << "000\"},\"blocks\":[\""
				<< static_cast<char*>(last_block_found_buf) << static_cast<char*>(last_block_found_buf) + HASH_SIZE * 2 - 4 << ':'
				<< last_block_found_time << "\",\""
				<< last_block_found_height << "\"],\"miners\":"
				<< miners << ",\"hashrate\":"
				<< hashrate << ",\"roundHashes\":"
				<< round_hashes << "}}";
		});
}

void p2pool::cleanup_mainchain_data(uint64_t height)
{
	// Expects m_mainchainLock to be already locked here
	// Deletes everything older than 720 blocks, except for the 3 latest RandomX seed heights

	constexpr uint64_t PRUNE_DISTANCE = BLOCK_HEADERS_REQUIRED;
	const uint64_t seed_height = get_seed_height(height);
	const std::array<uint64_t, 3> seed_heights{ seed_height, seed_height - SEEDHASH_EPOCH_BLOCKS, seed_height - SEEDHASH_EPOCH_BLOCKS * 2 };

	for (auto it = m_mainchainByHeight.begin(); it != m_mainchainByHeight.end();) {
		const uint64_t h = it->first;
		if (h + PRUNE_DISTANCE >= height) {
			break;
		}

		if (std::find(seed_heights.begin(), seed_heights.end(), h) == seed_heights.end()) {
			m_mainchainByHash.erase(it->second.id);
			it = m_mainchainByHeight.erase(it);
		}
		else {
			++it;
		}
	}
}

void p2pool::api_update_block_found(const ChainMain* data, const PoolBlock* block)
{
	if (!m_api || m_stopped) {
		return;
	}

	const time_t cur_time = time(nullptr);
	const difficulty_type total_hashes = block ? block->m_cumulativeDifficulty : m_sideChain->total_hashes();
	difficulty_type diff;

	if (data && get_difficulty_at_height(data->height, diff)) {
		std::ofstream f(FOUND_BLOCKS_FILE, std::ios::app);
		if (f.is_open()) {
			f << cur_time << ' ' << data->height << ' ' << data->id << ' ' << diff << ' ' << total_hashes << '\n';
			f.flush();
			f.close();
		}
	}

	std::vector<FoundBlock> found_blocks;
	{
		MutexLock lock(m_foundBlocksLock);
		if (data) {
			m_foundBlocks.emplace_back(cur_time, data->height, data->id, diff, total_hashes);
		}
		found_blocks.assign(m_foundBlocks.end() - std::min<size_t>(m_foundBlocks.size(), 51), m_foundBlocks.end());
	}

	m_api->set(p2pool_api::Category::POOL, "blocks",
		[&found_blocks](log::Stream& s)
		{
			s << '[';
			bool first = true;
			for (auto i = found_blocks.rbegin(); i != found_blocks.rend(); ++i) {
				if (!first) {
					s << ',';
				}
				s << "{\"height\":" << i->height << ','
					<< "\"hash\":\"" << i->id << "\","
					<< "\"difficulty\":" << i->block_diff << ','
					<< "\"totalHashes\":" << i->total_hashes << ','
					<< "\"ts\":" << i->timestamp << '}';
				first = false;
			}
			s << ']';
		});

	api_update_stats_mod();
}

bool p2pool::get_difficulty_at_height(uint64_t height, difficulty_type& diff)
{
	ReadLock lock(m_mainchainLock);

	auto it = m_mainchainByHeight.find(height);
	if (it == m_mainchainByHeight.end()) {
		return false;
	}

	diff = it->second.difficulty;
	return true;
}

#ifdef WITH_RANDOMX
void p2pool::start_mining(uint32_t threads)
{
	stop_mining();

	MutexLock lock(m_minerLock);
	m_miner = new Miner(this, threads);
}

void p2pool::stop_mining()
{
	MutexLock lock(m_minerLock);

	if (m_miner) {
		delete m_miner;
		m_miner = nullptr;
	}
}
#endif

static void on_signal(uv_signal_t* handle, int signum)
{
	p2pool* pool = reinterpret_cast<p2pool*>(handle->data);

	switch (signum) {
	case SIGHUP:
		LOGINFO(1, "caught SIGHUP");
		break;
	case SIGINT:
		LOGINFO(1, "caught SIGINT");
		break;
	case SIGTERM:
		LOGINFO(1, "caught SIGTERM");
		break;
#ifdef SIGBREAK
	case SIGBREAK:
		LOGINFO(1, "caught SIGBREAK");
		break;
#endif
#ifdef SIGUSR1
	case SIGUSR1:
		log::reopen();
		return;
#endif
	default:
		LOGINFO(1, "caught signal " << signum);
	}

	LOGINFO(1, "stopping");

	uv_signal_stop(handle);
	pool->stop();
}

bool init_signals(p2pool* pool, bool init)
{
#ifdef SIGPIPE
	signal(SIGPIPE, SIG_IGN);
#endif

	constexpr int signal_names[] = {
		SIGHUP,
		SIGINT,
		SIGTERM,
#ifdef SIGBREAK
		SIGBREAK,
#endif
#ifdef SIGUSR1
		SIGUSR1,
#endif
	};

	static uv_signal_t signals[array_size(signal_names)];

	if (!init) {
		for (size_t i = 0; i < array_size(signals); ++i) {
			uv_signal_stop(&signals[i]);
			uv_close(reinterpret_cast<uv_handle_t*>(&signals[i]), nullptr);
		}
		return true;
	}

	for (size_t i = 0; i < array_size(signal_names); ++i) {
		uv_signal_init(uv_default_loop_checked(), &signals[i]);
		signals[i].data = pool;
		const int rc = uv_signal_start(&signals[i], on_signal, signal_names[i]);
		if (rc != 0) {
			LOGERR(1, "failed to initialize signal, error " << rc);
			return false;
		}
	}

	return true;
}

void p2pool::stop()
{
	// Can be called only once
	if (m_stopped.exchange(true) == false) {
		uv_async_send(&m_stopAsync);
	}
}

bool p2pool::zmq_running() const
{
	ReadLock lock(m_ZMQReaderLock);
	return m_ZMQReader && m_ZMQReader->is_running();
}

const Params::Host& p2pool::switch_host()
{
	const std::vector<Params::Host>& v = m_params->m_hosts;
	return v[++m_currentHostIndex % v.size()];
}

void p2pool::reconnect_to_host()
{
	// If p2pool is stopped, m_reconnectToHostAsync is most likely already closed
	if (m_stopped) {
		return;
	}

	if (!is_main_thread()) {
		uv_async_send(&m_reconnectToHostAsync);
		return;
	}

	const Params::Host& new_host = switch_host();

	WriteLock lock(m_ZMQReaderLock);

	delete m_ZMQReader;
	m_ZMQReader = nullptr;

	try {
		ZMQReader* new_reader = new ZMQReader(new_host.m_address, new_host.m_zmqPort, m_params->m_socks5Proxy, this);
		m_zmqLastActive = seconds_since_epoch();
		m_ZMQReader = new_reader;
	}
	catch (const std::exception& e) {
		LOGERR(1, "Couldn't restart ZMQ reader: exception " << e.what());
	}

	if (m_ZMQReader) {
		get_miner_data(false);
	}
}

int p2pool::run()
{
	if (!m_params->valid()) {
		LOGERR(1, "Invalid or missing command line. Try \"p2pool --help\".");
		return 1;
	}

	if (!init_signals(this, true)) {
		LOGERR(1, "failed to initialize signal handlers");
		return 1;
	}

	// Init default loop user data before running it
	uv_loop_t* loop = uv_default_loop_checked();
	loop->data = nullptr;
	GetLoopUserData(loop);

	try {
		get_info();
		load_found_blocks();
		const int rc = uv_run(uv_default_loop_checked(), UV_RUN_DEFAULT);
		LOGINFO(1, "uv_run exited, result = " << rc);

		WriteLock lock(m_ZMQReaderLock);

		delete m_ZMQReader;
		m_ZMQReader = nullptr;
	}
	catch (const std::exception& e) {
		LOGERR(1, "exception " << e.what());
		PANIC_STOP();
	}

	m_stopped = true;

	bkg_jobs_tracker.wait();

#ifdef WITH_RANDOMX
	delete m_miner;
#endif
	delete m_stratumServer;
	delete m_p2pServer;

	LOGINFO(1, "stopped");
	return 0;
}

} // namespace p2pool
