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
#include "block_cache.h"
#include "pool_block.h"
#include "p2p_server.h"

static constexpr char log_category_prefix[] = "BlockCache ";

static constexpr uint32_t BLOCK_SIZE = 96 * 1024;
static constexpr uint32_t NUM_BLOCKS = 5120;
static constexpr uint32_t CACHE_SIZE = BLOCK_SIZE * NUM_BLOCKS;
static constexpr char cache_name[] = "p2pool.cache";

namespace p2pool {

struct BlockCache::Impl
{
#ifdef _WIN32
	Impl()
	{
		m_file = CreateFile(cache_name, GENERIC_ALL, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL);
		if (m_file == INVALID_HANDLE_VALUE) {
			LOGERR(1, "couldn't open " << cache_name << ", error " << static_cast<uint32_t>(GetLastError()));
			return;
		}

		if (SetFilePointer(m_file, CACHE_SIZE, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
			LOGERR(1, "SetFilePointer failed, error " << static_cast<uint32_t>(GetLastError()));
			CloseHandle(m_file);
			m_file = INVALID_HANDLE_VALUE;
			return;
		}

		if (!SetEndOfFile(m_file)) {
			LOGERR(1, "SetEndOfFile failed, error " << static_cast<uint32_t>(GetLastError()));
			CloseHandle(m_file);
			m_file = INVALID_HANDLE_VALUE;
			return;
		}

		m_map = CreateFileMapping(m_file, NULL, PAGE_READWRITE, 0, CACHE_SIZE, NULL);
		if (!m_map) {
			LOGERR(1, "CreateFileMapping failed, error " << static_cast<uint32_t>(GetLastError()));
			CloseHandle(m_file);
			m_file = INVALID_HANDLE_VALUE;
			return;
		}

		m_data = reinterpret_cast<uint8_t*>(MapViewOfFile(m_map, FILE_MAP_ALL_ACCESS, 0, 0, 0));
		if (!m_data) {
			LOGERR(1, "MapViewOfFile failed, error " << static_cast<uint32_t>(GetLastError()));
			CloseHandle(m_map);
			CloseHandle(m_file);
			m_map = 0;
			m_file = INVALID_HANDLE_VALUE;
		}
	}

	~Impl()
	{
		if (m_data) UnmapViewOfFile(m_data);
		if (m_map) CloseHandle(m_map);
		if (m_file != INVALID_HANDLE_VALUE) CloseHandle(m_file);
	}

	void flush()
	{
		if (m_data && (m_flushRunning.exchange(1) == 0)) {
			FlushViewOfFile(m_data, 0);
			FlushFileBuffers(m_file);
			m_flushRunning.store(0);
		}
	}

	HANDLE m_file = INVALID_HANDLE_VALUE;
	HANDLE m_map = 0;

#else
	// TODO: Linux version is not implemented yet
	void flush() {}
#endif

	uint8_t* m_data = nullptr;
	std::atomic<uint32_t> m_flushRunning{ 0 };
};

BlockCache::BlockCache()
	: m_impl(new Impl())
{
}

BlockCache::~BlockCache()
{
	delete m_impl;
}

void BlockCache::store(const PoolBlock& block)
{
	if (!m_impl->m_data) {
		return;
	}

	uint8_t* data = m_impl->m_data + (static_cast<size_t>(block.m_sidechainHeight % NUM_BLOCKS) * BLOCK_SIZE);

	const size_t n1 = block.m_mainChainData.size();
	const size_t n2 = block.m_sideChainData.size();

	*reinterpret_cast<uint32_t*>(data) = static_cast<uint32_t>(n1 + n2);
	memcpy(data + sizeof(uint32_t), block.m_mainChainData.data(), n1);
	memcpy(data + sizeof(uint32_t) + n1, block.m_sideChainData.data(), n2);
}

void BlockCache::load_all(SideChain& side_chain, P2PServer& server)
{
	if (!m_impl->m_data) {
		return;
	}

	LOGINFO(1, "loading cached blocks");

	PoolBlock block;
	uint32_t blocks_loaded = 0;

	for (uint64_t i = 0; i < NUM_BLOCKS; ++i) {
		const uint8_t* data = m_impl->m_data + i * BLOCK_SIZE;
		const uint32_t n = *reinterpret_cast<const uint32_t*>(data);

		if (!n || (n + sizeof(uint32_t) > BLOCK_SIZE)) {
			continue;
		}

		block.deserialize(data + sizeof(uint32_t), n, side_chain);
		server.add_cached_block(block);
		++blocks_loaded;
	}

	LOGINFO(1, "loaded " << blocks_loaded << " cached blocks");
}

void BlockCache::flush()
{
	m_impl->flush();
}

} // namespace p2pool
