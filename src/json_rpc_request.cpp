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
#include "uv_util.h"
#include "json_rpc_request.h"
#include <curl/curl.h>

static constexpr char log_category_prefix[] = "JSONRPCRequest ";

namespace p2pool {
namespace JSONRPCRequest {

struct CurlContext
{
	CurlContext(const std::string& address, int port, const std::string& req, const std::string& auth, CallbackBase* cb, CallbackBase* close_cb, uv_loop_t* loop);
	~CurlContext();

	static int socket_func(CURL* easy, curl_socket_t s, int action, void* userp, void* socketp)
	{
		CurlContext* ctx = reinterpret_cast<CurlContext*>(socketp ? socketp : userp);
		return ctx->on_socket(easy, s, action);
	}

	static int timer_func(CURLM* multi, long timeout_ms, void* ctx)
	{
		return reinterpret_cast<CurlContext*>(ctx)->on_timer(multi, timeout_ms);
	}

	static size_t write_func(const void* buffer, size_t size, size_t count, void* ctx)
	{
		return reinterpret_cast<CurlContext*>(ctx)->on_write(buffer, size, count);
	}

	int on_socket(CURL* easy, curl_socket_t s, int action);
	int on_timer(CURLM* multi, long timeout_ms);

	static void on_timeout(uv_handle_t* req);

	size_t on_write(const void* buffer, size_t size, size_t count);

	static void curl_perform(uv_poll_t* req, int status, int events);
	void check_multi_info();

	static void on_close(uv_handle_t* h);

	uv_poll_t m_pollHandle;
	curl_socket_t m_socket;

	CallbackBase* m_callback;
	CallbackBase* m_closeCallback;

	uv_loop_t* m_loop;
	uv_timer_t m_timer;
	uv_async_t m_async;
	CURLM* m_multiHandle;
	CURL* m_handle;

	std::string m_url;
	std::string m_req;
	std::string m_auth;

	std::vector<char> m_response;
	std::string m_error;
};

CurlContext::CurlContext(const std::string& address, int port, const std::string& req, const std::string& auth, CallbackBase* cb, CallbackBase* close_cb, uv_loop_t* loop)
	: m_pollHandle{}
	, m_socket{}
	, m_callback(cb)
	, m_closeCallback(close_cb)
	, m_loop(loop)
	, m_timer{}
	, m_async{}
	, m_multiHandle(nullptr)
	, m_handle(nullptr)
	, m_req(req)
	, m_auth(auth)
{
	{
		char buf[log::Stream::BUF_SIZE + 1];
		buf[0] = '\0';

		log::Stream s(buf);
		s << "http://" << address << ':' << port;

		if (!m_req.empty() && (m_req.front() == '/')) {
			s << m_req.c_str() << '\0';
			m_req.clear();
		}
		else {
			s << "/json_rpc\0";
		}

		m_url = buf;
	}

	int err = uv_timer_init(m_loop, &m_timer);
	if (err) {
		LOGERR(1, "uv_timer_init failed, error " << uv_err_name(err));
		throw std::runtime_error("uv_timer_init failed");
	}
	m_timer.data = this;

	err = uv_async_init(m_loop, &m_async, reinterpret_cast<uv_async_cb>(on_timeout));
	if (err) {
		LOGERR(1, "uv_async_init failed, error " << uv_err_name(err));
		uv_close(reinterpret_cast<uv_handle_t*>(&m_timer), nullptr);
		throw std::runtime_error("uv_async_init failed");
	}
	m_async.data = this;

	m_multiHandle = curl_multi_init();
	if (!m_multiHandle) {
		constexpr char msg[] = "curl_multi_init() failed";
		LOGERR(1, msg);
		uv_close(reinterpret_cast<uv_handle_t*>(&m_async), nullptr);
		uv_close(reinterpret_cast<uv_handle_t*>(&m_timer), nullptr);
		throw std::runtime_error(msg);
	}

	curl_multi_setopt(m_multiHandle, CURLMOPT_SOCKETFUNCTION, socket_func);
	curl_multi_setopt(m_multiHandle, CURLMOPT_SOCKETDATA, this);
	
	curl_multi_setopt(m_multiHandle, CURLMOPT_TIMERFUNCTION, timer_func);
	curl_multi_setopt(m_multiHandle, CURLMOPT_TIMERDATA, this);

	m_handle = curl_easy_init();
	if (!m_handle) {
		constexpr char msg[] = "curl_easy_init() failed";
		LOGERR(1, msg);
		curl_multi_cleanup(m_multiHandle);
		uv_close(reinterpret_cast<uv_handle_t*>(&m_async), nullptr);
		uv_close(reinterpret_cast<uv_handle_t*>(&m_timer), nullptr);
		throw std::runtime_error(msg);
	}

	curl_easy_setopt(m_handle, CURLOPT_WRITEFUNCTION, write_func);
	curl_easy_setopt(m_handle, CURLOPT_WRITEDATA, this);

	curl_easy_setopt(m_handle, CURLOPT_URL, m_url.c_str());
	curl_easy_setopt(m_handle, CURLOPT_POSTFIELDS, m_req.c_str());
	curl_easy_setopt(m_handle, CURLOPT_CONNECTTIMEOUT, 1);
	curl_easy_setopt(m_handle, CURLOPT_TIMEOUT, 10);

	if (!m_auth.empty()) {
		curl_easy_setopt(m_handle, CURLOPT_HTTPAUTH, CURLAUTH_DIGEST | CURLAUTH_ONLY);
		curl_easy_setopt(m_handle, CURLOPT_USERPWD, m_auth.c_str());
	}

	CURLMcode curl_err = curl_multi_add_handle(m_multiHandle, m_handle);
	if (curl_err != CURLM_OK) {
		LOGERR(1, "curl_multi_add_handle failed, error " << curl_multi_strerror(curl_err));
		curl_easy_cleanup(m_handle);
		curl_multi_cleanup(m_multiHandle);
		uv_close(reinterpret_cast<uv_handle_t*>(&m_async), nullptr);
		uv_close(reinterpret_cast<uv_handle_t*>(&m_timer), nullptr);
		throw std::runtime_error("curl_multi_add_handle failed");
	}
}

CurlContext::~CurlContext()
{
	if (m_error.empty() && !m_response.empty()) {
		(*m_callback)(m_response.data(), m_response.size());
	}
	delete m_callback;

	(*m_closeCallback)(m_error.c_str(), m_error.length());
	delete m_closeCallback;
}

int CurlContext::on_socket(CURL* /*easy*/, curl_socket_t s, int action)
{
	switch (action) {
	case CURL_POLL_IN:
	case CURL_POLL_OUT:
	case CURL_POLL_INOUT:
		{
			if (!m_socket) {
				m_socket = s;
				curl_multi_assign(m_multiHandle, s, this);
			}
			else if (m_socket != s) {
				LOGERR(1, "This code can't work with multiple parallel requests. Fix the code!");
			}

			int events = 0;
			if (action != CURL_POLL_IN)  events |= UV_WRITABLE;
			if (action != CURL_POLL_OUT) events |= UV_READABLE;

			if (!m_pollHandle.data) {
				uv_poll_init_socket(m_loop, &m_pollHandle, s);
				m_pollHandle.data = this;
			}

			uv_poll_start(&m_pollHandle, events, curl_perform);
		}
		break;

	case CURL_POLL_REMOVE:
	default:
		curl_multi_assign(m_multiHandle, s, nullptr);
		uv_poll_stop(&m_pollHandle);
		uv_close(reinterpret_cast<uv_handle_t*>(&m_async), on_close);
		uv_close(reinterpret_cast<uv_handle_t*>(&m_timer), on_close);
		uv_close(reinterpret_cast<uv_handle_t*>(&m_pollHandle), on_close);
		break;
	}

	return 0;
}

int CurlContext::on_timer(CURLM* /*multi*/, long timeout_ms)
{
	if (timeout_ms < 0) {
		uv_timer_stop(&m_timer);
		return 0;
	}

	if (timeout_ms == 0) {
		// 0 ms timeout, but we can't just call on_timeout() here - we have to kick the UV loop
		uv_async_send(&m_async);
		return 0;
	}

	uv_timer_start(&m_timer, reinterpret_cast<uv_timer_cb>(on_timeout), timeout_ms, 0);
	return 0;
}

void CurlContext::on_timeout(uv_handle_t* req)
{
	CurlContext* ctx = reinterpret_cast<CurlContext*>(req->data);

	int running_handles;
	curl_multi_socket_action(ctx->m_multiHandle, CURL_SOCKET_TIMEOUT, 0, &running_handles);
	ctx->check_multi_info();
}

size_t CurlContext::on_write(const void* buffer, size_t size, size_t count)
{
	const char* p = reinterpret_cast<const char*>(buffer);
	m_response.insert(m_response.end(), p, p + size * count);
	return count;
}

void CurlContext::curl_perform(uv_poll_t* req, int status, int events)
{
	int flags = 0;
	if (status < 0) {
		flags |= CURL_CSELECT_ERR;
		LOGERR(1, "uv_poll_start returned error " << uv_err_name(status));
	}
	else {
		if (events & UV_READABLE) flags |= CURL_CSELECT_IN;
		if (events & UV_WRITABLE) flags |= CURL_CSELECT_OUT;
	}

	CurlContext* ctx = reinterpret_cast<CurlContext*>(req->data);

	int running_handles;
	curl_multi_socket_action(ctx->m_multiHandle, ctx->m_socket, flags, &running_handles);
	ctx->check_multi_info();
}

void CurlContext::check_multi_info()
{
	int pending;
	while (CURLMsg* message = curl_multi_info_read(m_multiHandle, &pending)) {
		if (message->msg == CURLMSG_DONE) {
			if ((message->data.result != CURLE_OK) || m_response.empty()) {
				m_error = m_response.empty() ? "empty response" : curl_easy_strerror(message->data.result);
			}

			long http_code = 0;
			curl_easy_getinfo(message->easy_handle, CURLINFO_RESPONSE_CODE, &http_code);

			if (http_code != 200) {
				char buf[32] = {};
				log::Stream s(buf);
				s << "HTTP error " << static_cast<int>(http_code) << '\0';
				m_error = buf;
			}

			curl_multi_remove_handle(m_multiHandle, m_handle);
			curl_easy_cleanup(m_handle);
			curl_multi_cleanup(m_multiHandle);
			return;
		}
	}
}

void CurlContext::on_close(uv_handle_t* h)
{
	CurlContext* ctx = reinterpret_cast<CurlContext*>(h->data);
	h->data = nullptr;

	if (ctx->m_timer.data || ctx->m_async.data || ctx->m_pollHandle.data) {
		return;
	}

	delete ctx;
}

void Call(const std::string& address, int port, const std::string& req, const std::string& auth, CallbackBase* cb, CallbackBase* close_cb, uv_loop_t* loop)
{
	CallOnLoop(loop,
		[=]()
		{
			try {
				new CurlContext(address, port, req, auth, cb, close_cb, loop);
			}
			catch (const std::exception& e) {
				const char* msg = e.what();
				(*close_cb)(msg, strlen(msg));
			}
		});
}

} // namespace JSONRPCRequest
} // namespace p2pool
