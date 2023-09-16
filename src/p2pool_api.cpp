/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2023 SChernykh <https://github.com/SChernykh>
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
#include "p2pool_api.h"

#ifdef _MSC_VER
#include <direct.h>
#else
#include <sys/stat.h>
#endif

LOG_CATEGORY(P2Pool API)

namespace p2pool {

p2pool_api::p2pool_api(const std::string& api_path, const bool local_stats)
	: m_apiPath(api_path)
	, m_counter(0)
{
	if (m_apiPath.empty()) {
		LOGERR(1, "api path is empty");
		PANIC_STOP();
	}

	if ((m_apiPath.back() != '/')
#ifdef _WIN32
		&& (m_apiPath.back() != '\\')
#endif
		) {
		m_apiPath += '/';
	}

	struct stat buf;
	if (stat(m_apiPath.c_str(), &buf) != 0) {
		LOGERR(1, "path " << m_apiPath << " doesn't exist");
		PANIC_STOP();
	}

	int result = uv_async_init(uv_default_loop_checked(), &m_dumpToFileAsync, on_dump_to_file);
	if (result) {
		LOGERR(1, "uv_async_init failed, error " << uv_err_name(result));
		PANIC_STOP();
	}
	m_dumpToFileAsync.data = this;

	uv_mutex_init_checked(&m_dumpDataLock);

	m_networkPath = m_apiPath + "network/";
	m_poolPath = m_apiPath + "pool/";
	m_localPath = m_apiPath + "local/";

	create_dir(m_networkPath);
	create_dir(m_poolPath);

	if (local_stats) {
		create_dir(m_localPath);
	}
}

p2pool_api::~p2pool_api()
{
	uv_mutex_destroy(&m_dumpDataLock);
}

void p2pool_api::create_dir(const std::string& path)
{
#ifdef _MSC_VER
	int result = _mkdir(path.c_str());
#else
	int result = mkdir(path.c_str()
#ifndef _WIN32
		, 0775
#endif
	);
#endif

	if (result < 0) {
		result = errno;
		if (result != EEXIST) {
			LOGERR(1, "mkdir(" << path << ") failed, error " << result);
			PANIC_STOP();
		}
	}
}

void p2pool_api::on_stop()
{
	MutexLock lock(m_dumpDataLock);
	uv_close(reinterpret_cast<uv_handle_t*>(&m_dumpToFileAsync), nullptr);
}

void p2pool_api::dump_to_file_async_internal(Category category, const char* filename, Callback<void, log::Stream&>::Base&& callback)
{
	std::vector<char> buf(1024);
	log::Stream s(buf.data(), buf.size());
	callback(s);

	// If the buffer was too small, try again with big enough buffer
	if (s.m_spilled) {
		// Assume that the second call will use no more than 2X bytes
		buf.resize((static_cast<ptrdiff_t>(s.m_pos) + s.m_spilled) * 2 + 1);
		s.reset(buf.data(), buf.size());
		callback(s);
	}

	buf.resize(s.m_pos);

	std::string path;

	switch (category) {
	case Category::GLOBAL:  path = m_apiPath     + filename; break;
	case Category::NETWORK: path = m_networkPath + filename; break;
	case Category::POOL:    path = m_poolPath    + filename; break;
	case Category::LOCAL:   path = m_localPath   + filename; break;
	}

	MutexLock lock(m_dumpDataLock);
	m_dumpData[path] = std::move(buf);

	if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(&m_dumpToFileAsync))) {
		uv_async_send(&m_dumpToFileAsync);
	}
}

void p2pool_api::dump_to_file()
{
	unordered_map<std::string, std::vector<char>> data;
	{
		MutexLock lock(m_dumpDataLock);
		data = std::move(m_dumpData);
	}

	char buf[log::Stream::BUF_SIZE + 1];
	buf[0] = '\0';

	for (auto& it : data) {
		log::Stream s(buf);
		s << it.first << m_counter << '\0';

		DumpFileWork* work = new DumpFileWork{ {}, 0, it.first, buf, std::move(it.second) };
		work->req.data = work;
		++m_counter;

		const int flags = O_WRONLY | O_CREAT | O_TRUNC
#ifdef O_BINARY
			| O_BINARY
#endif
			;

		const int result = uv_fs_open(uv_default_loop_checked(), &work->req, work->tmp_name.c_str(), flags, 0644, on_fs_open);
		if (result < 0) {
			LOGWARN(4, "failed to open " << work->tmp_name << ", error " << uv_err_name(result));
			delete work;
		}
	}
}

void p2pool_api::on_fs_open(uv_fs_t* req)
{
	DumpFileWork* work = reinterpret_cast<DumpFileWork*>(req->data);
	work->fd = static_cast<int>(req->result);
	uv_fs_req_cleanup(req);

	if (work->fd < 0) {
		LOGWARN(4, "failed to open " << work->tmp_name << ", error " << uv_err_name(work->fd));
		delete work;
		return;
	}

	uv_buf_t buf[1];
	buf[0].base = work->buf.data();
	buf[0].len = static_cast<uint32_t>(work->buf.size());

	int result = uv_fs_write(uv_default_loop_checked(), &work->req, static_cast<uv_file>(work->fd), buf, 1, -1, on_fs_write);
	if (result < 0) {
		LOGWARN(4, "failed to write to " << work->tmp_name << ", error " << uv_err_name(result));

		result = uv_fs_close(uv_default_loop_checked(), &work->req, static_cast<uv_file>(work->fd), on_fs_error_cleanup);
		if (result < 0) {
			LOGWARN(4, "failed to close " << work->tmp_name << ", error " << uv_err_name(result));
			delete work;
		}
	}
}

void p2pool_api::on_fs_write(uv_fs_t* req)
{
	DumpFileWork* work = reinterpret_cast<DumpFileWork*>(req->data);
	int result = static_cast<int>(req->result);
	uv_fs_req_cleanup(req);

	if (result < 0) {
		LOGWARN(4, "failed to write to " << work->tmp_name << ", error " << uv_err_name(result));
	}
	else if (result && (static_cast<size_t>(result) < work->buf.size())) {
		work->buf.erase(work->buf.begin(), work->buf.begin() + result);

		uv_buf_t buf[1];
		buf[0].base = work->buf.data();
		buf[0].len = static_cast<uint32_t>(work->buf.size());

		result = uv_fs_write(uv_default_loop_checked(), &work->req, static_cast<uv_file>(work->fd), buf, 1, -1, on_fs_write);
		if (result < 0) {
			LOGWARN(4, "failed to write to " << work->tmp_name << ", error " << uv_err_name(result));

			result = uv_fs_close(uv_default_loop_checked(), &work->req, static_cast<uv_file>(work->fd), on_fs_error_cleanup);
			if (result < 0) {
				LOGWARN(4, "failed to close " << work->tmp_name << ", error " << uv_err_name(result));
				delete work;
			}
		}

		return;
	}

	result = uv_fs_close(uv_default_loop_checked(), &work->req, static_cast<uv_file>(work->fd), on_fs_close);
	if (result < 0) {
		LOGWARN(4, "failed to close " << work->tmp_name << ", error " << uv_err_name(result));
		delete work;
	}
}

void p2pool_api::on_fs_close(uv_fs_t* req)
{
	DumpFileWork* work = reinterpret_cast<DumpFileWork*>(req->data);
	int result = static_cast<int>(req->result);
	uv_fs_req_cleanup(req);

	if (result < 0) {
		LOGWARN(4, "failed to close " << work->tmp_name << ", error " << uv_err_name(result));
	}

	result = uv_fs_rename(uv_default_loop_checked(), &work->req, work->tmp_name.c_str(), work->name.c_str(), on_fs_rename);
	if (result < 0) {
		LOGWARN(4, "failed to rename " << work->tmp_name << " to " << work->name << ", error " << uv_err_name(result));

		result = uv_fs_unlink(uv_default_loop_checked(), &work->req, work->tmp_name.c_str(), on_fs_error_cleanup);
		if (result < 0) {
			LOGWARN(4, "failed to delete " << work->tmp_name << ", error " << uv_err_name(result));
			delete work;
		}
	}
}

void p2pool_api::on_fs_rename(uv_fs_t* req)
{
	DumpFileWork* work = reinterpret_cast<DumpFileWork*>(req->data);
	int result = static_cast<int>(req->result);
	uv_fs_req_cleanup(req);

	if (result < 0) {
		LOGWARN(4, "failed to rename " << work->tmp_name << " to " << work->name << ", error " << uv_err_name(result));

		result = uv_fs_unlink(uv_default_loop_checked(), &work->req, work->tmp_name.c_str(), on_fs_error_cleanup);
		if (result < 0) {
			LOGWARN(4, "failed to delete " << work->tmp_name << ", error " << uv_err_name(result));
			delete work;
		}

		return;
	}

	delete work;
}

void p2pool_api::on_fs_error_cleanup(uv_fs_t* req)
{
	DumpFileWork* work = reinterpret_cast<DumpFileWork*>(req->data);
	int result = static_cast<int>(req->result);
	uv_fs_req_cleanup(req);

	if (result < 0) {
		LOGWARN(4, "failed to cleanup after previous errors " << work->tmp_name << ", error " << uv_err_name(result));
	}

	delete work;
}

} // namespace p2pool
