/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2025 SChernykh <https://github.com/SChernykh>
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

LOG_CATEGORY(JSONRPCRequest)

namespace p2pool {
namespace JSONRPCRequest {

struct CurlContext : public nocopy_nomove
{
	CurlContext(const std::string& address, int port, const std::string& req, const std::string& auth, const std::string& proxy, bool ssl, const std::string& ssl_fingerprint, CallbackBase* cb, CallbackBase* close_cb, uv_loop_t* loop);
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

	void shutdown();

	std::vector<std::pair<curl_socket_t, uv_poll_t*>> m_pollHandles;

	CallbackBase* m_callback;
	CallbackBase* m_closeCallback;

	uv_loop_t* m_loop;
	uv_timer_t m_timer;
	CURLM* m_multiHandle;
	CURL* m_handle;

	std::string m_url;
	std::string m_req;

	std::vector<char> m_response;
	std::string m_error;

	curl_slist* m_headers;

	uint64_t m_startTime;
	uint64_t m_connectedTime;

	std::string m_proxy;
};

CurlContext::CurlContext(const std::string& address, int port, const std::string& req, const std::string& auth, const std::string& proxy, bool ssl, const std::string& ssl_fingerprint, CallbackBase* cb, CallbackBase* close_cb, uv_loop_t* loop)
	: m_callback(cb)
	, m_closeCallback(close_cb)
	, m_loop(loop)
	, m_timer{}
	, m_multiHandle(nullptr)
	, m_handle(nullptr)
	, m_req(req)
	, m_headers(nullptr)
	, m_startTime(0)
	, m_connectedTime(0)
	, m_proxy(proxy)
{
	m_pollHandles.reserve(2);

	{
		char buf[log::Stream::BUF_SIZE + 1];
		buf[0] = '\0';

		const char* protocol = "http://";

#ifdef WITH_TLS
		if (ssl) {
			protocol = "https://";
		}
#else
		(void)ssl;
		(void)ssl_fingerprint;
#endif

		const bool is_v6 = (address.find(':') != std::string::npos);

		log::Stream s(buf);
		s << protocol << (is_v6 ? "[" : "") << address << (is_v6 ? "]:" : ":") << port;

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

	m_multiHandle = curl_multi_init();
	if (!m_multiHandle) {
		static constexpr char msg[] = "curl_multi_init() failed";
		LOGERR(1, msg);
		uv_close(reinterpret_cast<uv_handle_t*>(&m_timer), nullptr);
		throw std::runtime_error(msg);
	}

#define curl_multi_setopt_checked(...) \
	do { \
		const CURLMcode r = curl_multi_setopt(__VA_ARGS__); \
		if (r != CURLM_OK) { \
			static constexpr char msg[] = "curl_multi_setopt(" #__VA_ARGS__ ") failed"; \
			LOGERR(1, msg << ": " << curl_multi_strerror(r)); \
			throw std::runtime_error(msg); \
		} \
	} while (0)

	curl_multi_setopt_checked(m_multiHandle, CURLMOPT_SOCKETFUNCTION, socket_func);
	curl_multi_setopt_checked(m_multiHandle, CURLMOPT_SOCKETDATA, this);
	
	curl_multi_setopt_checked(m_multiHandle, CURLMOPT_TIMERFUNCTION, timer_func);
	curl_multi_setopt_checked(m_multiHandle, CURLMOPT_TIMERDATA, this);

	m_handle = curl_easy_init();
	if (!m_handle) {
		static constexpr char msg[] = "curl_easy_init() failed";
		LOGERR(1, msg);
		curl_multi_cleanup(m_multiHandle);
		uv_close(reinterpret_cast<uv_handle_t*>(&m_timer), nullptr);
		throw std::runtime_error(msg);
	}

#define curl_easy_setopt_checked(...) \
	do { \
		const CURLcode r = curl_easy_setopt(__VA_ARGS__); \
		if (r != CURLE_OK) { \
			static constexpr char msg[] = "curl_easy_setopt(" #__VA_ARGS__ ") failed"; \
			LOGERR(1, msg << ": " << curl_easy_strerror(r)); \
			throw std::runtime_error(msg); \
		} \
	} while (0)

	curl_easy_setopt_checked(m_handle, CURLOPT_BUFFERSIZE, 102400L);

	curl_easy_setopt_checked(m_handle, CURLOPT_WRITEFUNCTION, write_func);
	curl_easy_setopt_checked(m_handle, CURLOPT_WRITEDATA, this);

#ifdef DEV_TEST_SYNC
	const int timeout = 10;
#else
	const int timeout = proxy.empty() ? 1 : 5;
#endif

	curl_easy_setopt_checked(m_handle, CURLOPT_URL, m_url.c_str());
	curl_easy_setopt_checked(m_handle, CURLOPT_POSTFIELDS, m_req.c_str());
	curl_easy_setopt_checked(m_handle, CURLOPT_CONNECTTIMEOUT, timeout);
	curl_easy_setopt_checked(m_handle, CURLOPT_TIMEOUT, timeout * 10);

	m_headers = curl_slist_append(m_headers, "Content-Type: application/json");
	if (m_headers) {
		curl_easy_setopt_checked(m_handle, CURLOPT_HTTPHEADER, m_headers);
	}

	if (!auth.empty()) {
		curl_easy_setopt_checked(m_handle, CURLOPT_HTTPAUTH, CURLAUTH_DIGEST | CURLAUTH_ONLY);
		curl_easy_setopt_checked(m_handle, CURLOPT_USERPWD, auth.c_str());
	}

	if (!proxy.empty()) {
		if (is_localhost(address)) {
			LOGINFO(5, "not using proxy to connect to localhost address " << log::Gray() << address);
		}
		else {
			curl_easy_setopt_checked(m_handle, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5_HOSTNAME);
			curl_easy_setopt_checked(m_handle, CURLOPT_PROXY, proxy.c_str());
		}
	}

#ifdef WITH_TLS
	curl_easy_setopt_checked(m_handle, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt_checked(m_handle, CURLOPT_SSL_VERIFYHOST, 0L);

	if (!ssl_fingerprint.empty()) {
		char buf[64] = {};

		log::Stream s(buf);
		s << "sha256//" << ssl_fingerprint;

		curl_easy_setopt_checked(m_handle, CURLOPT_PINNEDPUBLICKEY, buf);
	}
#endif

	CURLMcode curl_err = curl_multi_add_handle(m_multiHandle, m_handle);
	if (curl_err != CURLM_OK) {
		LOGERR(1, "curl_multi_add_handle failed: " << curl_multi_strerror(curl_err));
		curl_easy_cleanup(m_handle);
		curl_multi_cleanup(m_multiHandle);
		uv_close(reinterpret_cast<uv_handle_t*>(&m_timer), nullptr);
		throw std::runtime_error("curl_multi_add_handle failed");
	}

	m_startTime = microseconds_since_epoch();
}

CurlContext::~CurlContext()
{
	double tcp_ping = 0.0;

	if (m_error.empty() && !m_response.empty()) {
		const uint64_t t = (m_proxy.empty() && m_connectedTime) ? m_connectedTime : microseconds_since_epoch();
		tcp_ping = static_cast<double>(t - m_startTime) / 1000.0;
		(*m_callback)(m_response.data(), m_response.size(), tcp_ping);
	}
	delete m_callback;

	if (m_response.empty()) {
		if (m_error.empty()) {
			m_error = "empty response";
		}
		else {
			m_error += " (empty response)";
		}
	}

	(*m_closeCallback)(m_error.c_str(), m_error.length(), tcp_ping);
	delete m_closeCallback;

	curl_slist_free_all(m_headers);
}

int CurlContext::on_socket(CURL* /*easy*/, curl_socket_t s, int action)
{
	auto it = std::find_if(m_pollHandles.begin(), m_pollHandles.end(), [s](const auto& value) { return value.first == s; });

	switch (action) {
	case CURL_POLL_IN:
	case CURL_POLL_OUT:
	case CURL_POLL_INOUT:
		{
			uv_poll_t* h = nullptr;

			if (it != m_pollHandles.end()) {
				h = it->second;
			}
			else {
				h = new uv_poll_t{};

				// cppcheck-suppress nullPointer
				h->data = this;

				const int result = uv_poll_init_socket(m_loop, h, s);
				if (result < 0) {
					LOGERR(1, "uv_poll_init_socket failed: " << uv_err_name(result));
					delete h;
					h = nullptr;
				}
				else {
					m_pollHandles.emplace_back(s, h);
				}
			}

			if (h) {
				const CURLMcode err = curl_multi_assign(m_multiHandle, s, this);
				if (err != CURLM_OK) {
					LOGERR(1, "curl_multi_assign(action = " << action << ") failed: " << curl_multi_strerror(err));
				}

				int events = 0;
				if (action != CURL_POLL_IN)  events |= UV_WRITABLE;
				if (action != CURL_POLL_OUT) events |= UV_READABLE;

				const int result = uv_poll_start(h, events, curl_perform);
				if (result < 0) {
					LOGERR(1, "uv_poll_start failed with error " << uv_err_name(result));
				}
			}
			else {
				LOGERR(1, "failed to start polling on socket " << static_cast<int>(s));
			}
		}
		break;

	case CURL_POLL_REMOVE:
	default:
		{
			if (it != m_pollHandles.end()) {
				uv_poll_t* h = it->second;
				m_pollHandles.erase(it);

				uv_poll_stop(h);
				uv_close(reinterpret_cast<uv_handle_t*>(h), [](uv_handle_t* h) { delete reinterpret_cast<uv_poll_t*>(h); });
			}

			const CURLMcode err = curl_multi_assign(m_multiHandle, s, nullptr);
			if (err != CURLM_OK) {
				LOGERR(1, "curl_multi_assign(action = " << action << ") failed: " << curl_multi_strerror(err));
			}
		}
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

	const int result = uv_timer_start(&m_timer, reinterpret_cast<uv_timer_cb>(on_timeout), timeout_ms, 0);
	if (result < 0) {
		LOGERR(1, "uv_timer_start failed with error " << uv_err_name(result));
		return -1;
	}

	return 0;
}

void CurlContext::on_timeout(uv_handle_t* req)
{
	CurlContext* ctx = reinterpret_cast<CurlContext*>(req->data);

	int running_handles = 0;
	const CURLMcode err = curl_multi_socket_action(ctx->m_multiHandle, CURL_SOCKET_TIMEOUT, 0, &running_handles);
	if (err != CURLM_OK) {
		LOGERR(1, "curl_multi_socket_action failed: " << curl_multi_strerror(err));
	}

	ctx->check_multi_info();

	if (running_handles == 0) {
		ctx->shutdown();
	}
}

size_t CurlContext::on_write(const void* buffer, size_t size, size_t count)
{
	if (!m_connectedTime) {
		m_connectedTime = microseconds_since_epoch();
	}

	const size_t realsize = size * count;
	const char* p = reinterpret_cast<const char*>(buffer);
	m_response.insert(m_response.end(), p, p + realsize);
	return realsize;
}

void CurlContext::curl_perform(uv_poll_t* req, int status, int events)
{
	CurlContext* ctx = reinterpret_cast<CurlContext*>(req->data);

	int flags = 0;
	if (status < 0) {
		flags |= CURL_CSELECT_ERR;
		LOGERR(1, "uv_poll_start returned error " << uv_err_name(status));
	}
	else {
		if (events & UV_READABLE) flags |= CURL_CSELECT_IN;
		if (events & UV_WRITABLE) {
			flags |= CURL_CSELECT_OUT;
			if (!ctx->m_connectedTime) {
				ctx->m_connectedTime = microseconds_since_epoch();
			}
		}
	}

	int running_handles = 0;
	auto it = std::find_if(ctx->m_pollHandles.begin(), ctx->m_pollHandles.end(), [req](const auto& value) { return value.second == req; });
	if (it != ctx->m_pollHandles.end()) {
		const CURLMcode err = curl_multi_socket_action(ctx->m_multiHandle, it->first, flags, &running_handles);
		if (err != CURLM_OK) {
			LOGERR(1, "curl_multi_socket_action failed: " << curl_multi_strerror(err));
		}
	}

	ctx->check_multi_info();

	if (running_handles == 0) {
		ctx->shutdown();
	}
}

void CurlContext::check_multi_info()
{
	int pending;
	while (CURLMsg* message = curl_multi_info_read(m_multiHandle, &pending)) {
		if (message->msg == CURLMSG_DONE) {
			if (message->data.result != CURLE_OK) {
				m_error = curl_easy_strerror(message->data.result);
			}
			else {
				long http_code = 0;
				curl_easy_getinfo(message->easy_handle, CURLINFO_RESPONSE_CODE, &http_code);

				if (http_code != 200) {
					char buf[32] = {};
					log::Stream s(buf);
					s << "HTTP error " << static_cast<int>(http_code) << '\0';
					m_error = buf;
				}
				else if (m_response.empty()) {
					m_error = "empty response";
				}
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

	if (ctx->m_timer.data) {
		return;
	}

	delete ctx;
}

void CurlContext::shutdown()
{
	for (const auto& p : m_pollHandles) {
		uv_poll_stop(p.second);
		uv_close(reinterpret_cast<uv_handle_t*>(p.second), [](uv_handle_t* h) { delete reinterpret_cast<uv_poll_t*>(h); });
	}
	m_pollHandles.clear();

	if (m_timer.data && !uv_is_closing(reinterpret_cast<uv_handle_t*>(&m_timer))) {
		uv_close(reinterpret_cast<uv_handle_t*>(&m_timer), on_close);
	}
}

void Call(const std::string& address, int port, const std::string& req, const std::string& auth, const std::string& proxy, bool ssl, const std::string& ssl_fingerprint, CallbackBase* cb, CallbackBase* close_cb, uv_loop_t* loop)
{
	if (!loop) {
		loop = uv_default_loop();
	}

	const bool result = CallOnLoop(loop,
		[=]()
		{
			try {
				new CurlContext(address, port, req, auth, proxy, ssl, ssl_fingerprint, cb, close_cb, loop);
			}
			catch (const std::exception& e) {
				const char* msg = e.what();
				(*close_cb)(msg, strlen(msg), 0.0);
				delete cb;
				delete close_cb;
			}
		});

	if (!result) {
		static constexpr char err[] = "CallOnLoop failed";
		LOGERR(1, err);
		(*close_cb)(err, sizeof(err) - 1, 0.0);
		delete cb;
		delete close_cb;
	}
}

} // namespace JSONRPCRequest
} // namespace p2pool
