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

#pragma once

#include "uv_util.h"

namespace p2pool {

class p2pool_api
{
public:
	p2pool_api(const std::string& api_path, const bool local_stats);
	~p2pool_api();

	enum class Category {
		GLOBAL,
		NETWORK,
		POOL,
		LOCAL,
	};

	// cppcheck-suppress functionConst
	void on_stop();

	template<typename T>
	void set(const Category& category, const char* filename, T&& callback) { dump_to_file_async_internal(category, filename, DumpFileCallback<T>(std::move(callback))); }

private:
	void create_dir(const std::string& path);

	static void on_dump_to_file(uv_async_t* async) { reinterpret_cast<p2pool_api*>(async->data)->dump_to_file(); }

	struct DumpFileWork {
		uv_fs_t open_req;
		uv_fs_t write_req;
		uv_fs_t close_req;

		std::string name;
		std::vector<char> buf;
	};

	struct DumpFileCallbackBase
	{
		virtual ~DumpFileCallbackBase() {}
		virtual void operator()(log::Stream&) = 0;
	};

	template<typename T>
	struct DumpFileCallback : public DumpFileCallbackBase
	{
		explicit FORCEINLINE DumpFileCallback(T&& callback) : m_callback(std::move(callback)) {}
		void operator()(log::Stream& s) override { m_callback(s); }

	private:
		DumpFileCallback& operator=(DumpFileCallback&&) = delete;

		T m_callback;
	};

	void dump_to_file_async_internal(const Category& category, const char* filename, DumpFileCallbackBase&& callback);
	void dump_to_file();
	static void on_fs_open(uv_fs_t* req);
	static void on_fs_write(uv_fs_t* req);
	static void on_fs_close(uv_fs_t* req);

	std::string m_apiPath;
	std::string m_networkPath;
	std::string m_poolPath;
	std::string m_localPath;

	uv_mutex_t m_dumpDataLock;
	unordered_map<std::string, std::vector<char>> m_dumpData;

	uv_async_t m_dumpToFileAsync;
};

} // namespace p2pool
