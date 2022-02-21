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
#include "uv_util.h"
#include "json_rpc_request.h"
#include "llhttp.h"
#include <string>

static constexpr char log_category_prefix[] = "JSONRPCRequest ";

namespace p2pool {

JSONRPCRequest::JSONRPCRequest(const char* address, int port, const char* req, CallbackBase* cb, CallbackBase* close_cb, uv_loop_t* loop)
	: m_socket{}
	, m_connect{}
	, m_write{}
	, m_callback(cb)
	, m_closeCallback(close_cb)
	, m_contentLength(0)
	, m_contentLengthHeader(false)
	, m_readBufInUse(false)
	, m_valid(true)
{
	m_readBuf[0] = '\0';

	uv_tcp_init(loop ? loop : uv_default_loop_checked(), &m_socket);
	uv_tcp_nodelay(&m_socket, 1);

	sockaddr_storage addr;
	if (uv_ip4_addr(address, port, reinterpret_cast<sockaddr_in*>(&addr)) != 0) {
		const int err = uv_ip6_addr(address, port, reinterpret_cast<sockaddr_in6*>(&addr));
		if (err) {
			LOGERR(1, "invalid IP address " << address << " or port " << port);
			m_valid = false;
			return;
		}
	}

	m_socket.data = this;
	m_connect.data = this;
	m_write.data = this;

	const char* uri = "/json_rpc";

	size_t len = req ? strlen(req) : 0;
	if (!len) {
		LOGERR(1, "Empty JSONRPCRequest, fix the code!");
		m_valid = false;
		return;
	}

	if (req[0] == '/') {
		uri = req;
		len = 0;
	}

	m_request.reserve(std::max<size_t>(len + 128, log::Stream::BUF_SIZE + 1));
	m_request.resize(log::Stream::BUF_SIZE + 1);

	log::Stream s(m_request.data());
	s << "POST " << uri << " HTTP/1.1\nContent-Type: application/json\nContent-Length: " << len << "\n\n";

	m_request.resize(s.m_pos);
	m_request.insert(m_request.end(), req, req + len);

	m_response.reserve(sizeof(m_readBuf));

	const int err = uv_tcp_connect(&m_connect, &m_socket, reinterpret_cast<const sockaddr*>(&addr), on_connect);
	if (err) {
		LOGERR(1, "failed to initiate tcp connection to " << address << ", error " << uv_err_name(err));
		m_valid = false;
	}
}

void JSONRPCRequest::on_connect(uv_connect_t* req, int status)
{
	JSONRPCRequest* pThis = static_cast<JSONRPCRequest*>(req->data);

	if (status != 0) {
		pThis->m_error = uv_err_name(status);
		LOGERR(1, "failed to connect, error " << pThis->m_error);
		pThis->close();
		return;
	}

	uv_buf_t buf[1];
	buf[0].base = pThis->m_request.data();
	buf[0].len = static_cast<uint32_t>(pThis->m_request.size());

	uv_write(&pThis->m_write, reinterpret_cast<uv_stream_t*>(&pThis->m_socket), buf, 1, on_write);
}

void JSONRPCRequest::on_write(uv_write_t* handle, int status)
{
	JSONRPCRequest* pThis = static_cast<JSONRPCRequest*>(handle->data);

	if (status != 0) {
		pThis->m_error = uv_err_name(status);
		LOGERR(1, "failed to send request, error " << pThis->m_error);
		pThis->close();
		return;
	}

	uv_read_start(reinterpret_cast<uv_stream_t*>(&pThis->m_socket), on_alloc, on_read);
}

void JSONRPCRequest::on_alloc(uv_handle_t* handle, size_t /*suggested_size*/, uv_buf_t* buf)
{
	JSONRPCRequest* pThis = static_cast<JSONRPCRequest*>(handle->data);

	if (pThis->m_readBufInUse) {
		LOGERR(1, "read buffer is already in use");
	}

	buf->len = sizeof(pThis->m_readBuf);
	buf->base = pThis->m_readBuf;
	pThis->m_readBufInUse = true;
}

void JSONRPCRequest::on_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
	JSONRPCRequest* pThis = static_cast<JSONRPCRequest*>(stream->data);
	pThis->m_readBufInUse = false;

	if (nread > 0) {
		pThis->on_read(buf->base, nread);
	}
	else if (nread < 0) {
		if (nread != UV_EOF){
			pThis->m_error = uv_err_name(static_cast<int>(nread));
			LOGERR(1, "failed to read response, error " << pThis->m_error);
		}
		pThis->close();
	}
}

void JSONRPCRequest::on_read(const char* data, size_t size)
{
	m_response.append(data, size);

	static constexpr char headers_end[] = "\r\n\r\n";
	if (m_response.find(headers_end) == std::string::npos) {
		return;
	}

	llhttp_settings_t settings{};

	settings.on_status = [](llhttp_t*, const char* at, size_t length)
	{
		if ((length == 2) && (!memcmp(at, "Ok", 2) || !memcmp(at, "OK", 2))) {
			return 0;
		}
		return -1;
	};

	settings.on_header_field = [](llhttp_t* parser, const char* at, size_t length)
	{
		JSONRPCRequest* pThis = static_cast<JSONRPCRequest*>(parser->data);
		static const char header[] = "Content-Length";
		pThis->m_contentLengthHeader = ((length == sizeof(header) - 1) && (memcmp(at, header, length) == 0));
		return 0;
	};

	settings.on_header_value = [](llhttp_t* parser, const char* at, size_t length)
	{
		JSONRPCRequest* pThis = static_cast<JSONRPCRequest*>(parser->data);
		if (pThis->m_contentLengthHeader) {
			uint32_t k = 0;
			for (const char* p = at; p < at + length; ++p) {
				if ('0' <= *p && *p <= '9') {
					k = k * 10 + (*p - '0');
				}
				else {
					return -1;
				}
			}
			if (!k) {
				return -1;
			}
			pThis->m_contentLength = k;
		}
		return 0;
	};

	settings.on_body = [](llhttp_t* parser, const char* at, size_t length)
	{
		JSONRPCRequest* pThis = static_cast<JSONRPCRequest*>(parser->data);
		if (pThis->m_contentLength && (length >= pThis->m_contentLength) && pThis->m_callback) {
			(*pThis->m_callback)(at, length);
			delete pThis->m_callback;
			pThis->m_callback = nullptr;
		}
		return 0;
	};

	llhttp_t parser;
	llhttp_init(&parser, HTTP_RESPONSE, &settings);

	parser.data = this;

	const llhttp_errno result = llhttp_execute(&parser, m_response.c_str(), m_response.length());
	if (result != HPE_OK) {
		m_error = "failed to parse response";
		LOGERR(1, m_error << ", result = " << static_cast<int>(result));
		close();
		return;
	}

	if (!m_callback) {
		close();
	}
}

void JSONRPCRequest::close()
{
	uv_handle_t* h = reinterpret_cast<uv_handle_t*>(&m_socket);
	if (!uv_is_closing(h)) {
		uv_close(h, on_close);
	}
}

void JSONRPCRequest::on_close(uv_handle_t* handle)
{
	JSONRPCRequest* req = static_cast<JSONRPCRequest*>(handle->data);
	if (req->m_closeCallback) {
		(*req->m_closeCallback)(req->m_error.c_str(), req->m_error.length());
	}
	delete req;
}

JSONRPCRequest::~JSONRPCRequest()
{
	delete m_callback;
	delete m_closeCallback;
}

} // namespace p2pool
