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

namespace p2pool {

template<size_t READ_BUF_SIZE, size_t WRITE_BUF_SIZE>
class TCPServer : public nocopy_nomove
{
public:
	struct Client;
	typedef Client* (*allocate_client_callback)();

	explicit TCPServer(allocate_client_callback allocate_new_client);
	virtual ~TCPServer();

	template<typename T>
	void parse_address_list(const std::string& address_list, T callback);

	bool connect_to_peer(bool is_v6, const char* ip, int port);

	void drop_connections() { uv_async_send(&m_dropConnectionsAsync); }
	void shutdown_tcp();
	virtual void print_status();

	uv_loop_t* get_loop() { return &m_loop; }

	int listen_port() const { return m_listenPort; }

	bool connect_to_peer(bool is_v6, const raw_ip& ip, int port);
	virtual void on_connect_failed(bool is_v6, const raw_ip& ip, int port);

	void ban(const raw_ip& ip, uint64_t seconds);

	struct Client
	{
		Client();
		virtual ~Client();

		virtual void reset();
		virtual bool on_connect() = 0;
		virtual bool on_read(char* data, uint32_t size) = 0;
		virtual void on_read_failed(int /*err*/) {}
		virtual void on_disconnected() {}

		static void on_alloc(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
		static void on_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
		static void on_write(uv_write_t* req, int status);

		void close();
		void ban(uint64_t seconds);

		void init_addr_string(bool is_v6, const sockaddr_storage* peer_addr);

		TCPServer* m_owner;

		// Used to maintain connected clients list
		Client* m_prev;
		Client* m_next;

		uv_tcp_t m_socket;
		uv_connect_t m_connectRequest;

		bool m_isV6;
		bool m_isIncoming;
		raw_ip m_addr;
		int m_port;
		char m_addrString[64];

		bool m_readBufInUse;
		char m_readBuf[READ_BUF_SIZE];
		uint32_t m_numRead;

		std::atomic<uint32_t> m_resetCounter{ 0 };

		uv_mutex_t m_sendLock;
	};

	struct WriteBuf
	{
		Client* m_client;
		uv_write_t m_write;
		char m_data[WRITE_BUF_SIZE];
	};

	uv_mutex_t m_writeBuffersLock;
	std::vector<WriteBuf*> m_writeBuffers;

	struct SendCallbackBase
	{
		virtual ~SendCallbackBase() {}
		virtual size_t operator()(void*) = 0;
	};

	template<typename T>
	struct SendCallback : public SendCallbackBase
	{
		explicit FORCEINLINE SendCallback(T&& callback) : m_callback(std::move(callback)) {}
		size_t operator()(void* buf) override { return m_callback(buf); }

	private:
		SendCallback& operator=(SendCallback&&) = delete;

		T m_callback;
	};

	template<typename T>
	FORCEINLINE bool send(Client* client, T&& callback) { return send_internal(client, SendCallback<T>(std::move(callback))); }

private:
	static void loop(void* data);
	static void on_new_connection(uv_stream_t* server, int status);
	static void on_connection_close(uv_handle_t* handle);
	static void on_connect(uv_connect_t* req, int status);
	void on_new_client(uv_stream_t* server);
	void on_new_client_nolock(uv_stream_t* server, Client* client);

	bool connect_to_peer_nolock(Client* client, bool is_v6, const sockaddr* addr);

	bool send_internal(Client* client, SendCallbackBase&& callback);

	allocate_client_callback m_allocateNewClient;

	void close_sockets(bool listen_sockets);

	std::vector<uv_tcp_t*> m_listenSockets6;
	std::vector<uv_tcp_t*> m_listenSockets;
	uv_thread_t m_loopThread;

protected:
	void start_listening(const std::string& listen_addresses);

	std::atomic<int> m_finished;
	int m_listenPort;

	uv_loop_t m_loop;
	volatile bool m_loopStopped;

	uv_mutex_t m_clientsListLock;
	std::vector<Client*> m_preallocatedClients;
	Client* m_connectedClientsList;
	uint32_t m_numConnections;
	uint32_t m_numIncomingConnections;

	uv_mutex_t m_bansLock;
	unordered_map<raw_ip, time_t> m_bans;

	bool is_banned(const raw_ip& ip);

	uv_mutex_t m_pendingConnectionsLock;
	unordered_set<raw_ip> m_pendingConnections;

	uv_async_t m_dropConnectionsAsync;
	static void on_drop_connections(uv_async_t* async) { reinterpret_cast<TCPServer*>(async->data)->close_sockets(false); }

	uv_async_t m_shutdownAsync;
	static void on_shutdown(uv_async_t* async)
	{
		TCPServer* server = reinterpret_cast<TCPServer*>(async->data);
		server->close_sockets(true);

		uv_close(reinterpret_cast<uv_handle_t*>(&server->m_dropConnectionsAsync), nullptr);
		uv_close(reinterpret_cast<uv_handle_t*>(&server->m_shutdownAsync), nullptr);
	}
};

} // namespace p2pool
