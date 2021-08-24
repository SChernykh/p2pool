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
#include <unordered_map>

namespace p2pool {

struct Params;
class RandomX_Hasher;
class BlockTemplate;
class Mempool;
class SideChain;
class StratumServer;
class P2PServer;
class ConsoleCommands;

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

	RandomX_Hasher* hasher() const { return m_hasher; }
	bool calculate_hash(const void* data, size_t size, const hash& seed, hash& result);
	static uint64_t get_seed_height(uint64_t height);
	bool get_seed(uint64_t height, hash& seed) const;

	StratumServer* stratum_server() const { return m_stratumServer; }
	P2PServer* p2p_server() const { return m_p2pServer; }

	virtual void handle_tx(TxMempoolData& tx) override;
	virtual void handle_miner_data(MinerData& data) override;
	virtual void handle_chain_main(ChainMain& data, const char* extra) override;

	void submit_block(uint32_t template_id, uint32_t nonce, uint32_t extra_nonce) const;
	void submit_sidechain_block(uint32_t template_id, uint32_t nonce, uint32_t extra_nonce);
	void update_block_template_async();

	void download_block_headers(uint64_t current_height);

	bool chainmain_get_by_hash(const hash& id, ChainMain& data) const;

private:
	p2pool(const p2pool&) = delete;
	p2pool(p2pool&&) = delete;

	bool m_stopped;

	Params* m_params;

	SideChain* m_sideChain;
	RandomX_Hasher* m_hasher;
	BlockTemplate* m_blockTemplate;
	MinerData m_minerData;
	Mempool* m_mempool;

	mutable uv_rwlock_t m_mainchainLock;
	std::map<uint64_t, ChainMain> m_mainchainByHeight;
	std::unordered_map<hash, ChainMain> m_mainchainByHash;

	enum { TIMESTAMP_WINDOW = 60 };
	bool get_timestamps(uint64_t (&timestamps)[TIMESTAMP_WINDOW]) const;
	void update_median_timestamp();

	void stratum_on_block();

	void get_miner_data();
	void parse_get_miner_data_rpc(const char* data, size_t size);

	bool parse_block_header(const char* data, size_t size, ChainMain& result);
	uint32_t parse_block_headers_range(const char* data, size_t size);

	std::atomic<uint32_t> m_serversStarted{ 0 };
	StratumServer* m_stratumServer = nullptr;
	P2PServer* m_p2pServer = nullptr;

	ConsoleCommands* m_consoleCommands;
};

} // namespace p2pool
