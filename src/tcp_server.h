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

#pragma once

#include "uv_util.h"
#include <map>

namespace p2pool {

class TCPServer : public nocopy_nomove
{
public:
	struct Client;
	typedef Client* (*allocate_client_callback)();

	TCPServer(int default_backlog, allocate_client_callback allocate_new_client);
	virtual ~TCPServer();

	bool connect_to_peer(bool is_v6, const char* ip, int port);

	void drop_connections_async() { if (m_finished.load() == 0) { uv_async_send(&m_dropConnectionsAsync); } }
	void shutdown_tcp();
	virtual void print_status();

	uv_loop_t* get_loop() { return &m_loop; }

	virtual int external_listen_port() const { return m_listenPort; }

	bool connect_to_peer(bool is_v6, const raw_ip& ip, int port);
	virtual void on_connect_failed(bool /*is_v6*/, const raw_ip& /*ip*/, int /*port*/) {}

	void ban(bool is_v6, raw_ip ip, uint64_t seconds);
	virtual void print_bans();

	struct Client
	{
		Client(char* read_buf, size_t size);
		virtual ~Client() {}

		virtual size_t size() const = 0;

		virtual void reset();
		virtual bool on_connect() = 0;
		virtual bool on_read(char* data, uint32_t size) = 0;
		bool on_proxy_handshake(char* data, uint32_t size);
		virtual void on_read_failed(int /*err*/) {}
		virtual void on_disconnected() {}

		static void on_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
		static void on_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
		static void on_write(uv_write_t* req, int status);

		void close();
		void ban(uint64_t seconds);

		void init_addr_string();

		char* m_readBuf;
		uint32_t m_readBufSize;

		TCPServer* m_owner;

		// Used to maintain connected clients list
		Client* m_prev;
		Client* m_next;

		uv_tcp_t m_socket;

		bool m_isV6;
		bool m_isIncoming;
		bool m_readBufInUse;
		bool m_isClosing;
		uint32_t m_numRead;

		raw_ip m_addr;
		int m_port;
		char m_addrString[72];

		enum class Socks5ProxyState {
			Default,
			MethodSelectionSent,
			ConnectRequestSent,
		} m_socks5ProxyState;

		std::atomic<uint32_t> m_resetCounter;
	};

	struct WriteBuf
	{
		uv_write_t m_write = {};
		Client* m_client = nullptr;
		void* m_data = nullptr;
		size_t m_dataCapacity = 0;
	};

	std::multimap<size_t, WriteBuf*> m_writeBuffers;

	WriteBuf* get_write_buffer(size_t size_hint);
	void return_write_buffer(WriteBuf* buf);

	template<typename T>
	FORCEINLINE static void parse_address_list(const std::string& address_list, T&& callback)
	{
		return parse_address_list_internal(address_list, Callback<void, bool, const std::string&, const std::string&, int>::Derived<T>(std::move(callback)));
	}

	template<typename T>
	FORCEINLINE bool send(Client* client, T&& callback) { return send_internal(client, Callback<size_t, uint8_t*, size_t>::Derived<T>(std::move(callback))); }

private:
	static void on_new_connection(uv_stream_t* server, int status);
	static void on_connection_close(uv_handle_t* handle);
	static void on_connection_error(uv_handle_t* handle);
	static void on_connect(uv_connect_t* req, int status);
	void on_new_client(uv_stream_t* server);
	void on_new_client(uv_stream_t* server, Client* client);

	bool connect_to_peer(Client* client);

	bool send_internal(Client* client, Callback<size_t, uint8_t*, size_t>::Base&& callback);

	allocate_client_callback m_allocateNewClient;

	void close_sockets(bool listen_sockets);
	static void error_invalid_ip(const std::string& address);

	std::vector<uv_tcp_t*> m_listenSockets6;
	std::vector<uv_tcp_t*> m_listenSockets;

protected:
	virtual const char* get_log_category() const;

	std::vector<uint8_t> m_callbackBuf;
	int m_defaultBacklog;

	uv_thread_t m_loopThread;
	std::atomic<bool> m_loopThreadRunning;

	static void loop(void* data);

	static void parse_address_list_internal(const std::string& address_list, Callback<void, bool, const std::string&, const std::string&, int>::Base&& callback);
	void start_listening(const std::string& listen_addresses, bool upnp);
	bool start_listening(bool is_v6, const std::string& ip, int port, std::string address = std::string());

#ifdef WITH_UPNP
	int m_portMapping;
#endif

	std::string m_socks5Proxy;
	bool m_socks5ProxyV6;
	raw_ip m_socks5ProxyIP;
	int m_socks5ProxyPort;

	std::atomic<int> m_finished;
	int m_listenPort;

	uv_loop_t m_loop;

#ifdef P2POOL_DEBUGGING
	void check_event_loop_thread(const char *func) const;
#else
	static FORCEINLINE void check_event_loop_thread(const char*) {}
#endif

	std::vector<Client*> m_preallocatedClients;

	Client* get_client();
	void return_client(Client* c);

	Client* m_connectedClientsList;
	std::atomic<uint32_t> m_numConnections;
	std::atomic<uint32_t> m_numIncomingConnections;

	uv_mutex_t m_bansLock;
	unordered_map<raw_ip, std::chrono::steady_clock::time_point> m_bans;

	bool is_banned(bool is_v6, raw_ip ip);

	unordered_set<raw_ip> m_pendingConnections;

	uv_async_t m_dropConnectionsAsync;
	static void on_drop_connections(uv_async_t* async) { reinterpret_cast<TCPServer*>(async->data)->close_sockets(false); }

	virtual void on_shutdown() = 0;

	uv_async_t m_shutdownAsync;
	uv_prepare_t m_shutdownPrepare;
	uv_timer_t m_shutdownTimer;
	uint32_t m_shutdownCountdown;
	uint32_t m_numHandles;

	static void on_shutdown(uv_async_t* async);
};

} // namespace p2pool
