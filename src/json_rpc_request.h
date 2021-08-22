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

namespace p2pool {

class JSONRPCRequest
{
public:
	template<typename T>
	static FORCEINLINE void call(const char* address, int port, const char* req, T&& cb)
	{
		// It will be deleted in one of the tcp callbacks eventually
		new JSONRPCRequest(address, port, req, new Callback<T>(std::move(cb)));
	}

private:
	struct CallbackBase
	{
		virtual ~CallbackBase() {}
		virtual void operator()(const char* data, size_t size) = 0;
	};

	template<typename T>
	struct Callback : public CallbackBase
	{
		explicit FORCEINLINE Callback(T&& cb) : m_cb(std::move(cb)) {}
		void operator()(const char* data, size_t size) override { m_cb(data, size); }

	private:
		Callback& operator=(Callback&&) = delete;
		T m_cb;
	};

	JSONRPCRequest(const char* address, int port, const char* req, CallbackBase* cb);
	~JSONRPCRequest();

	static void on_connect(uv_connect_t* req, int status);
	static void on_write(uv_write_t* handle, int status);
	static void on_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
	static void on_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
	void on_read(const char* data, size_t size);
	void close();
	static void on_close(uv_handle_t* handle);

	uv_tcp_t m_socket;
	uv_connect_t m_connect;
	uv_write_t m_write;

	CallbackBase* m_callback;
	uint32_t m_contentLength;
	bool m_contentLengthHeader;

	std::vector<char> m_request;
	std::string m_response;
	char m_readBuf[65536];
	bool m_readBufInUse;
};

} // namespace p2pool
