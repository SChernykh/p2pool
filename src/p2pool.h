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
#include <map>

namespace p2pool {

struct Params;
class RandomX_Hasher;
class BlockTemplate;
class Mempool;
class SideChain;
class StratumServer;
class P2PServer;
class ConsoleCommands;
class p2pool_api;

class p2pool : public MinerCallbackHandler
{
public:
	p2pool(int argc, char* argv[]);
	~p2pool();

	int run();

	bool stopped() const { return m_stopped; }
	void stop();

	const Params& params() const { return *m_params; }
	BlockTemplate& block_template() { return *m_blockTemplate; }
	SideChain& side_chain() { return *m_sideChain; }
	const MinerData& miner_data() const { return m_minerData; }

	p2pool_api* api() const { return m_api; }

	RandomX_Hasher* hasher() const { return m_hasher; }
	bool calculate_hash(const void* data, size_t size, const hash& seed, hash& result);
	static uint64_t get_seed_height(uint64_t height);
	bool get_seed(uint64_t height, hash& seed) const;

	StratumServer* stratum_server() const { return m_stratumServer; }
	P2PServer* p2p_server() const { return m_p2pServer; }

	virtual void handle_tx(TxMempoolData& tx) override;
	virtual void handle_miner_data(MinerData& data) override;
	virtual void handle_chain_main(ChainMain& data, const char* extra) override;

	void submit_block_async(uint32_t template_id, uint32_t nonce, uint32_t extra_nonce);
	void submit_block_async(const std::vector<uint8_t>& blob);
	void submit_sidechain_block(uint32_t template_id, uint32_t nonce, uint32_t extra_nonce);

	void update_block_template_async();
	void update_block_template();

	void download_block_headers(uint64_t current_height);

	bool chainmain_get_by_hash(const hash& id, ChainMain& data) const;

	void api_update_block_found(const ChainMain* data);

	bool get_difficulty_at_height(uint64_t height, difficulty_type& diff);

	time_t zmq_last_active() const { return m_zmqLastActive; }
	time_t start_time() const { return m_startTime; }

private:
	p2pool(const p2pool&) = delete;
	p2pool(p2pool&&) = delete;

	static void on_submit_block(uv_async_t* async) { reinterpret_cast<p2pool*>(async->data)->submit_block(); }
	static void on_update_block_template(uv_async_t* async) { reinterpret_cast<p2pool*>(async->data)->update_block_template(); }
	static void on_stop(uv_async_t*);

	void submit_block() const;

	bool m_stopped;

	Params* m_params;

	p2pool_api* m_api;
	SideChain* m_sideChain;
	RandomX_Hasher* m_hasher;
	BlockTemplate* m_blockTemplate;
	MinerData m_minerData;
	bool m_updateSeed;
	Mempool* m_mempool;

	mutable uv_rwlock_t m_mainchainLock;
	std::map<uint64_t, ChainMain> m_mainchainByHeight;
	unordered_map<hash, ChainMain> m_mainchainByHash;

	enum { TIMESTAMP_WINDOW = 60 };
	bool get_timestamps(uint64_t (&timestamps)[TIMESTAMP_WINDOW]) const;
	void update_median_timestamp();

	void stratum_on_block();

	void get_info();
	void load_found_blocks();
	void parse_get_info_rpc(const char* data, size_t size);

	void get_version();
	void parse_get_version_rpc(const char* data, size_t size);

	void get_miner_data();
	void parse_get_miner_data_rpc(const char* data, size_t size);

	bool parse_block_header(const char* data, size_t size, ChainMain& result);
	uint32_t parse_block_headers_range(const char* data, size_t size);

	void api_update_network_stats();
	void api_update_pool_stats();
	void api_update_stats_mod();

	struct FoundBlock
	{
		FORCEINLINE FoundBlock(time_t _t, uint64_t _h, const hash& _id, const difficulty_type& _block_diff, const difficulty_type& _total_hashes)
			: timestamp(_t)
			, height(_h)
			, id(_id)
			, block_diff(_block_diff)
			, total_hashes(_total_hashes)
		{}

		time_t timestamp;
		uint64_t height;
		hash id;
		difficulty_type block_diff;
		difficulty_type total_hashes;
	};

	uv_mutex_t m_foundBlocksLock;
	std::vector<FoundBlock> m_foundBlocks;

	std::atomic<uint32_t> m_serversStarted{ 0 };
	StratumServer* m_stratumServer = nullptr;
	P2PServer* m_p2pServer = nullptr;

	ConsoleCommands* m_consoleCommands;

	struct SubmitBlockData
	{
		uint32_t template_id = 0;
		uint32_t nonce = 0;
		uint32_t extra_nonce = 0;
		std::vector<uint8_t> blob;
	};

	mutable uv_mutex_t m_submitBlockDataLock;
	SubmitBlockData m_submitBlockData;

	uv_async_t m_submitBlockAsync;
	uv_async_t m_blockTemplateAsync;
	uv_async_t m_stopAsync;

	time_t m_zmqLastActive;
	time_t m_startTime;
};

} // namespace p2pool
