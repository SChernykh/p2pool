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
#include "block_cache.h"
#include "pool_block.h"
#include "p2p_server.h"
#include "side_chain.h"

LOG_CATEGORY(BlockCache)

static constexpr uint32_t BLOCK_SIZE = 96 * 1024;
static constexpr uint32_t NUM_BLOCKS = 4608;
static constexpr uint32_t CACHE_SIZE = BLOCK_SIZE * NUM_BLOCKS;
static constexpr char cache_name[] = "p2pool.cache";

namespace p2pool {

struct BlockCache::Impl : public nocopy_nomove
{
#if defined(__linux__) || defined(__unix__) || defined(_POSIX_VERSION) || defined(__MACH__)

	Impl()
	{
		m_fd = open(cache_name, O_RDWR | O_CREAT, static_cast<mode_t>(0600));
		if (m_fd == -1) {
			LOGERR(1, "couldn't open/create " << cache_name);
			return;
		}

		int result = lseek(m_fd, static_cast<off_t>(CACHE_SIZE) - 1, SEEK_SET);
		if (result == -1) {
			LOGERR(1, "lseek failed");
			close(m_fd);
			m_fd = -1;
			return;
		}

		result = write(m_fd, "", 1);
		if (result != 1) {
			LOGERR(1, "write failed");
			close(m_fd);
			m_fd = -1;
			return;
		}

		void* map = mmap(0, CACHE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, m_fd, 0);
		if (map == MAP_FAILED) {
			LOGERR(1, "mmap failed");
			close(m_fd);
			m_fd = -1;
			return;
		}

		m_data = reinterpret_cast<uint8_t*>(map);
	}

	~Impl()
	{
		if (m_data) munmap(m_data, CACHE_SIZE);
		if (m_fd != -1) close(m_fd);
	}

	void flush()
	{
		if (m_data) {
			msync(m_data, CACHE_SIZE, MS_SYNC);
		}
	}

	int m_fd = -1;

#elif defined(_WIN32)

	Impl()
		: m_file(CreateFile(cache_name, GENERIC_ALL, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_HIDDEN, NULL))
		, m_map(0)
	{
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
		if (m_data) {
			FlushViewOfFile(m_data, 0);
			FlushFileBuffers(m_file);
		}
	}

	HANDLE m_file;
	HANDLE m_map;

#else
	// Not implemented on other platforms
	void flush() { m_data = nullptr; }
#endif

	uint8_t* m_data = nullptr;
};

BlockCache::BlockCache()
	: m_impl(new Impl())
	, m_flushRunning(0)
	, m_storeIndex(0)
	, m_loadingStarted(0)
{
}

BlockCache::~BlockCache()
{
	delete m_impl;
}

void BlockCache::store(const PoolBlock& block)
{
	const std::vector<uint8_t> mainchain_data = block.serialize_mainchain_data();
	const std::vector<uint8_t> sidechain_data = block.serialize_sidechain_data();

	const size_t n1 = mainchain_data.size();
	const size_t n2 = sidechain_data.size();

	if (!m_impl->m_data || (sizeof(uint32_t) + n1 + n2 > BLOCK_SIZE)) {
		return;
	}

	uint8_t* data = m_impl->m_data + (static_cast<size_t>((m_storeIndex++) % NUM_BLOCKS) * BLOCK_SIZE);

	*reinterpret_cast<uint32_t*>(data) = static_cast<uint32_t>(n1 + n2);
	memcpy(data + sizeof(uint32_t), mainchain_data.data(), n1);
	memcpy(data + sizeof(uint32_t) + n1, sidechain_data.data(), n2);
}

void BlockCache::load_all(const SideChain& side_chain, P2PServer& server)
{
	if (!m_impl->m_data) {
		return;
	}

	// Can be only called once
	if (m_loadingStarted.exchange(1)) {
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

		if (block.deserialize(data + sizeof(uint32_t), n, side_chain, uv_default_loop_checked(), false) == 0) {
			server.add_cached_block(block);
			++blocks_loaded;
		}
	}

	LOGINFO(1, "loaded " << blocks_loaded << " cached blocks");
}

void BlockCache::flush()
{
	if (m_flushRunning.exchange(1)) {
		m_impl->flush();
		m_flushRunning.store(0);
	}
}

} // namespace p2pool
