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

#include <thread>

static thread_local bool server_event_loop_thread = false;

namespace p2pool {

template<size_t READ_BUF_SIZE, size_t WRITE_BUF_SIZE>
TCPServer<READ_BUF_SIZE, WRITE_BUF_SIZE>::TCPServer(allocate_client_callback allocate_new_client)
	: m_allocateNewClient(allocate_new_client)
	, m_listenPort(-1)
	, m_loopStopped(false)
	, m_numConnections(0)
	, m_numIncomingConnections(0)
{
	int err = uv_loop_init(&m_loop);
	if (err) {
		LOGERR(1, "failed to create event loop, error " << uv_err_name(err));
		panic();
	}

	uv_async_init(&m_loop, &m_dropConnectionsAsync, on_drop_connections);
	m_dropConnectionsAsync.data = this;

	uv_async_init(&m_loop, &m_shutdownAsync, on_shutdown);
	m_shutdownAsync.data = this;

	uv_mutex_init_checked(&m_clientsListLock);
	uv_mutex_init_checked(&m_bansLock);
	uv_mutex_init_checked(&m_pendingConnectionsLock);

	m_preallocatedClients.reserve(DEFAULT_BACKLOG);
	for (int i = 0; i < DEFAULT_BACKLOG; ++i) {
		m_preallocatedClients.emplace_back(m_allocateNewClient());
	}

	m_connectedClientsList = m_allocateNewClient();
	m_connectedClientsList->m_next = m_connectedClientsList;
	m_connectedClientsList->m_prev = m_connectedClientsList;
}

template<size_t READ_BUF_SIZE, size_t WRITE_BUF_SIZE>
TCPServer<READ_BUF_SIZE, WRITE_BUF_SIZE>::~TCPServer()
{
	if (m_finished.load() == 0) {
		LOGERR(1, "TCP wasn't shutdown properly");
		shutdown_tcp();
	}

	delete m_connectedClientsList;
}


template<size_t READ_BUF_SIZE, size_t WRITE_BUF_SIZE>
template<typename T>
void TCPServer<READ_BUF_SIZE, WRITE_BUF_SIZE>::parse_address_list(const std::string& address_list, T callback)
{
	if (address_list.empty()) {
		return;
	}

	std::string address, ip;
	address.reserve(64);
	ip.reserve(64);

	for (size_t k1 = 0;; ++k1) {
		const size_t next_k1 = address_list.find_first_of(',', k1);
		address = address_list.substr(k1, next_k1 - k1);
		k1 = next_k1;

		const size_t k2 = address.find_last_of(':');
		if (k2 != std::string::npos) {
			ip = address.substr(0, k2);

			const bool is_v6 = (ip.find(':') != std::string::npos);
			if (is_v6) {
				if (!ip.empty() && ip.front() == '[') {
					ip.erase(ip.begin());
				}
				if (!ip.empty() && ip.back() == ']') {
					ip.pop_back();
				}
			}

			const int port = atoi(address.substr(k2 + 1).c_str());
			if ((port > 0) && (port < 655356)) {
				callback(is_v6, address, ip, port);
			}
			else {
				LOGWARN(1, "invalid IP:port " << address);
			}
		}

		if (k1 == std::string::npos) {
			return;
		}
	}
}

template<size_t READ_BUF_SIZE, size_t WRITE_BUF_SIZE>
void TCPServer<READ_BUF_SIZE, WRITE_BUF_SIZE>::start_listening(const std::string& listen_addresses)
{
	if (listen_addresses.empty()) {
		LOGERR(1, "listen address not set");
		panic();
	}

	parse_address_list(listen_addresses,
		[this](bool is_v6, const std::string& address, const std::string& ip, int port)
		{
			if (m_listenPort < 0) {
				m_listenPort = port;
			}
			else if (m_listenPort != port) {
				LOGERR(1, "all sockets must be listening on the same port number, fix the command line");
				panic();
			}

			uv_tcp_t* socket = new uv_tcp_t();

			if (is_v6) {
				m_listenSockets6.push_back(socket);
			}
			else {
				m_listenSockets.push_back(socket);
			}

			int err = uv_tcp_init(&m_loop, socket);
			if (err) {
				LOGERR(1, "failed to create tcp server handle, error " << uv_err_name(err));
				panic();
			}
			socket->data = this;

			err = uv_tcp_nodelay(socket, 1);
			if (err) {
				LOGERR(1, "failed to set tcp_nodelay on tcp server handle, error " << uv_err_name(err));
				panic();
			}

			if (is_v6) {
				sockaddr_in6 addr6;
				err = uv_ip6_addr(ip.c_str(), port, &addr6);
				if (err) {
					LOGERR(1, "failed to parse IPv6 address " << ip << ", error " << uv_err_name(err));
					panic();
				}

				err = uv_tcp_bind(socket, reinterpret_cast<sockaddr*>(&addr6), UV_TCP_IPV6ONLY);
				if (err) {
					LOGERR(1, "failed to bind tcp server IPv6 socket, error " << uv_err_name(err));
					panic();
				}
			}
			else {
				sockaddr_in addr;
				err = uv_ip4_addr(ip.c_str(), port, &addr);
				if (err) {
					LOGERR(1, "failed to parse IPv4 address " << ip << ", error " << uv_err_name(err));
					panic();
				}

				err = uv_tcp_bind(socket, reinterpret_cast<sockaddr*>(&addr), 0);
				if (err) {
					LOGERR(1, "failed to bind tcp server IPv4 socket, error " << uv_err_name(err));
					panic();
				}
			}

			err = uv_listen(reinterpret_cast<uv_stream_t*>(socket), DEFAULT_BACKLOG, on_new_connection);
			if (err) {
				LOGERR(1, "failed to listen on tcp server socket, error " << uv_err_name(err));
				panic();
			}

			LOGINFO(1, "listening on " << log::Gray() << address);
		});

	const int err = uv_thread_create(&m_loopThread, loop, this);
	if (err) {
		LOGERR(1, "failed to start event loop thread, error " << uv_err_name(err));
		panic();
	}
}

template<size_t READ_BUF_SIZE, size_t WRITE_BUF_SIZE>
bool TCPServer<READ_BUF_SIZE, WRITE_BUF_SIZE>::connect_to_peer(bool is_v6, const char* ip, int port)
{
	if (!ip || (strlen(ip) > sizeof(Client::m_addrString) - 16)) {
		LOGERR(1, "failed to parse IP address, too long");
		return false;
	}

	MutexLock lock(m_clientsListLock);

	if (m_finished.load()) {
		return false;
	}

	Client* client;

	if (!m_preallocatedClients.empty()) {
		client = m_preallocatedClients.back();
		m_preallocatedClients.pop_back();
		client->reset();
	}
	else {
		client = m_allocateNewClient();
	}

	client->m_owner = this;
	client->m_port = port;

	log::Stream s(client->m_addrString);

	sockaddr_storage addr;
	if (is_v6) {
		sockaddr_in6* addr6 = reinterpret_cast<sockaddr_in6*>(&addr);
		const int err = uv_ip6_addr(ip, port, addr6);
		if (err) {
			LOGERR(1, "failed to parse IPv6 address " << ip << ", error " << uv_err_name(err));
			m_preallocatedClients.push_back(client);
			return false;
		}

		memcpy(client->m_addr.data, &addr6->sin6_addr, sizeof(in6_addr));

		s << '[' << ip << "]:" << port << '\0';
	}
	else {
		sockaddr_in* addr4 = reinterpret_cast<sockaddr_in*>(&addr);
		const int err = uv_ip4_addr(ip, port, addr4);
		if (err) {
			LOGERR(1, "failed to parse IPv4 address " << ip << ", error " << uv_err_name(err));
			m_preallocatedClients.push_back(client);
			return false;
		}

		client->m_addr = {};
		client->m_addr.data[10] = 0xFF;
		client->m_addr.data[11] = 0xFF;
		memcpy(client->m_addr.data + 12, &addr4->sin_addr, sizeof(in_addr));

		s << ip << ':' << port << '\0';
	}

	return connect_to_peer_nolock(client, is_v6, reinterpret_cast<sockaddr*>(&addr));
}

template<size_t READ_BUF_SIZE, size_t WRITE_BUF_SIZE>
bool TCPServer<READ_BUF_SIZE, WRITE_BUF_SIZE>::connect_to_peer(bool is_v6, const raw_ip& ip, int port)
{
	MutexLock lock(m_clientsListLock);

	if (m_finished.load()) {
		return false;
	}

	Client* client;

	if (!m_preallocatedClients.empty()) {
		client = m_preallocatedClients.back();
		m_preallocatedClients.pop_back();
		client->reset();
	}
	else {
		client = m_allocateNewClient();
	}

	client->m_owner = this;
	client->m_addr = ip;
	client->m_port = port;

	sockaddr_storage addr{};

	if (is_v6) {
		sockaddr_in6* addr6 = reinterpret_cast<sockaddr_in6*>(&addr);
		addr6->sin6_family = AF_INET6;
		memcpy(&addr6->sin6_addr, ip.data, sizeof(in6_addr));
		addr6->sin6_port = htons(static_cast<uint16_t>(port));
	}
	else {
		sockaddr_in* addr4 = reinterpret_cast<sockaddr_in*>(&addr);
		addr4->sin_family = AF_INET;
		memcpy(&addr4->sin_addr, ip.data + 12, sizeof(in_addr));
		addr4->sin_port = htons(static_cast<uint16_t>(port));
	}

	client->init_addr_string(is_v6, &addr);
	return connect_to_peer_nolock(client, is_v6, reinterpret_cast<sockaddr*>(&addr));
}


template<size_t READ_BUF_SIZE, size_t WRITE_BUF_SIZE>
void TCPServer<READ_BUF_SIZE, WRITE_BUF_SIZE>::on_connect_failed(bool, const raw_ip&, int)
{
}

template<size_t READ_BUF_SIZE, size_t WRITE_BUF_SIZE>
bool TCPServer<READ_BUF_SIZE, WRITE_BUF_SIZE>::is_banned(const raw_ip& ip)
{
	MutexLock lock(m_bansLock);

	auto it = m_bans.find(ip);
	if ((it != m_bans.end()) && (time(nullptr) < it->second)) {
		return true;
	}

	return false;
}

template<size_t READ_BUF_SIZE, size_t WRITE_BUF_SIZE>
bool TCPServer<READ_BUF_SIZE, WRITE_BUF_SIZE>::connect_to_peer_nolock(Client* client, bool is_v6, const sockaddr* addr)
{
	if (is_banned(client->m_addr)) {
		LOGINFO(5, "peer " << log::Gray() << static_cast<char*>(client->m_addrString) << log::NoColor() << " is banned, not connecting to it");
		m_preallocatedClients.push_back(client);
		return false;
	}

	client->m_isV6 = is_v6;

	int err = uv_tcp_init(&m_loop, &client->m_socket);
	if (err) {
		LOGERR(1, "failed to create tcp client handle, error " << uv_err_name(err));
		m_preallocatedClients.push_back(client);
		return false;
	}
	client->m_socket.data = client;

	err = uv_tcp_nodelay(&client->m_socket, 1);
	if (err) {
		LOGERR(1, "failed to set tcp_nodelay on tcp client handle, error " << uv_err_name(err));
		m_preallocatedClients.push_back(client);
		return false;
	}

	MutexLock lock(m_pendingConnectionsLock);

	if (!m_pendingConnections.insert(client->m_addr).second) {
		LOGINFO(6, "there is already a pending connection to this IP, not connecting to " << log::Gray() << static_cast<char*>(client->m_addrString));
		m_preallocatedClients.push_back(client);
		return false;
	}

	client->m_connectRequest.data = client;
	err = uv_tcp_connect(&client->m_connectRequest, &client->m_socket, addr, on_connect);
	if (err) {
		LOGERR(1, "failed to initiate tcp connection, error " << uv_err_name(err));
		m_pendingConnections.erase(client->m_addr);
		m_preallocatedClients.push_back(client);
		return false;
	}
	else {
		LOGINFO(5, "connecting to " << log::Gray() << static_cast<char*>(client->m_addrString));
	}

	return true;
}

template<size_t READ_BUF_SIZE, size_t WRITE_BUF_SIZE>
void TCPServer<READ_BUF_SIZE, WRITE_BUF_SIZE>::close_sockets(bool listen_sockets)
{
	if (!server_event_loop_thread) {
		LOGERR(1, "closing sockets from another thread, this is not thread safe");
	}

	if (listen_sockets) {
		for (uv_tcp_t* s : m_listenSockets6) {
			uv_close(reinterpret_cast<uv_handle_t*>(s), [](uv_handle_t* h) { delete reinterpret_cast<uv_tcp_t*>(h); });
		}
		for (uv_tcp_t* s : m_listenSockets) {
			uv_close(reinterpret_cast<uv_handle_t*>(s), [](uv_handle_t* h) { delete reinterpret_cast<uv_tcp_t*>(h); });
		}
	}

	MutexLock lock(m_clientsListLock);

	size_t numClosed = 0;

	for (Client* c = m_connectedClientsList->m_next; c != m_connectedClientsList; c = c->m_next) {
		uv_handle_t* h = reinterpret_cast<uv_handle_t*>(&c->m_socket);
		if (!uv_is_closing(h)) {
			uv_close(h, on_connection_close);
			++numClosed;
		}
	}

	if (numClosed > 0) {
		LOGWARN(1, "closed " << numClosed << " active client connections");
	}
}

template<size_t READ_BUF_SIZE, size_t WRITE_BUF_SIZE>
void TCPServer<READ_BUF_SIZE, WRITE_BUF_SIZE>::shutdown_tcp()
{
	if (m_finished.exchange(1)) {
		return;
	}

	uv_async_send(&m_shutdownAsync);

	using namespace std::chrono;

	const system_clock::time_point start_time = system_clock::now();
	int64_t counter = 0;
	uv_async_t asy;

	constexpr uint32_t timeout_seconds = 30;

	while (!m_loopStopped) {
		const int64_t elapsed_time = duration_cast<milliseconds>(system_clock::now() - start_time).count();

		if (elapsed_time >= (counter + 1) * 1000) {
			++counter;
			if (counter < timeout_seconds) {
				LOGINFO(1, "waiting for event loop to stop for " << (timeout_seconds - counter) << " more seconds...");
			}
			else {
				LOGWARN(1, "timed out while waiting for event loop to stop");
				uv_async_init(&m_loop, &asy, nullptr);
				uv_stop(&m_loop);
				uv_async_send(&asy);
				break;
			}
		}

		std::this_thread::sleep_for(milliseconds(1));
	}

	uv_thread_join(&m_loopThread);

	for (Client* c : m_preallocatedClients) {
		delete c;
	}

	uv_mutex_destroy(&m_clientsListLock);
	uv_mutex_destroy(&m_bansLock);
	uv_mutex_destroy(&m_pendingConnectionsLock);

	LOGINFO(1, "stopped");
}

template<size_t READ_BUF_SIZE, size_t WRITE_BUF_SIZE>
void TCPServer<READ_BUF_SIZE, WRITE_BUF_SIZE>::print_status()
{
	LOGINFO(0, "status" <<
		"\nConnections = " << m_numConnections << " (" << m_numIncomingConnections << " incoming)"
	);
}

template<size_t READ_BUF_SIZE, size_t WRITE_BUF_SIZE>
void TCPServer<READ_BUF_SIZE, WRITE_BUF_SIZE>::ban(const raw_ip& ip, uint64_t seconds)
{
	MutexLock lock(m_bansLock);
	m_bans[ip] = time(nullptr) + seconds;
}

template<size_t READ_BUF_SIZE, size_t WRITE_BUF_SIZE>
bool TCPServer<READ_BUF_SIZE, WRITE_BUF_SIZE>::send_internal(Client* client, SendCallbackBase&& callback)
{
	if (!server_event_loop_thread) {
		LOGERR(1, "sending data from another thread, this is not thread safe");
	}

	MutexLock lock0(client->m_sendLock);

	typename Client::WriteBuf* buf = nullptr;

	{
		MutexLock lock(client->m_writeBuffersLock);
		if (!client->m_writeBuffers.empty()) {
			buf = client->m_writeBuffers.back();
			client->m_writeBuffers.pop_back();
		}
	}

	if (!buf) {
		buf = new typename Client::WriteBuf();
	}

	const size_t bytes_written = callback(buf->m_data);

	if (bytes_written > sizeof(buf->m_data)) {
		LOGERR(0, "send callback wrote " << bytes_written << " bytes, expected no more than " << sizeof(buf->m_data) << " bytes");
		panic();
	}

	if (bytes_written == 0) {
		LOGWARN(1, "send callback wrote 0 bytes, nothing to do");
		{
			MutexLock lock(client->m_writeBuffersLock);
			client->m_writeBuffers.push_back(buf);
		}
		return true;
	}

	buf->m_client = client;
	buf->m_write.data = buf;

	uv_buf_t bufs[1];
	bufs[0].base = buf->m_data;
	bufs[0].len = static_cast<int>(bytes_written);

	const int err = uv_write(&buf->m_write, reinterpret_cast<uv_stream_t*>(&client->m_socket), bufs, 1, Client::on_write);
	if (err) {
		{
			MutexLock lock(client->m_writeBuffersLock);
			client->m_writeBuffers.push_back(buf);
		}
		LOGWARN(1, "failed to start writing data to client connection " << static_cast<const char*>(client->m_addrString) << ", error " << uv_err_name(err));
		return false;
	}

	return true;
}

template<size_t READ_BUF_SIZE, size_t WRITE_BUF_SIZE>
void TCPServer<READ_BUF_SIZE, WRITE_BUF_SIZE>::loop(void* data)
{
	LOGINFO(1, "event loop started");
	server_event_loop_thread = true;
	TCPServer* server = static_cast<TCPServer*>(data);
	uv_run(&server->m_loop, UV_RUN_DEFAULT);
	uv_loop_close(&server->m_loop);
	server->m_loopStopped = true;
}

template<size_t READ_BUF_SIZE, size_t WRITE_BUF_SIZE>
void TCPServer<READ_BUF_SIZE, WRITE_BUF_SIZE>::on_new_connection(uv_stream_t* server, int status)
{
	TCPServer* pThis = static_cast<TCPServer*>(server->data);

	if (pThis->m_finished.load()) {
		return;
	}

	if (status < 0) {
		LOGWARN(1, "new connection error " << uv_strerror(status));
		return;
	}

	pThis->on_new_client(server);
}

template<size_t READ_BUF_SIZE, size_t WRITE_BUF_SIZE>
void TCPServer<READ_BUF_SIZE, WRITE_BUF_SIZE>::on_connection_close(uv_handle_t* handle)
{
	Client* client = static_cast<Client*>(handle->data);
	MutexLock lock0(client->m_sendLock);

	TCPServer* owner = client->m_owner;

	LOGINFO(5, "peer " << log::Gray() << static_cast<char*>(client->m_addrString) << log::NoColor() << " disconnected");

	if (owner) {
		MutexLock lock(owner->m_clientsListLock);

		Client* prev_in_list = client->m_prev;
		Client* next_in_list = client->m_next;

		const bool is_incoming = client->m_isIncoming;

		client->reset();

		prev_in_list->m_next = next_in_list;
		next_in_list->m_prev = prev_in_list;

		owner->m_preallocatedClients.push_back(client);

		--owner->m_numConnections;
		if (is_incoming) {
			--owner->m_numIncomingConnections;
		}
	}
	else {
		LOGERR(5, "internal error: can't find TCPServer instance for peer " << log::Gray() << static_cast<char*>(client->m_addrString) << ", this will leak memory");
	}
}

template<size_t READ_BUF_SIZE, size_t WRITE_BUF_SIZE>
void TCPServer<READ_BUF_SIZE, WRITE_BUF_SIZE>::on_connect(uv_connect_t* req, int status)
{
	Client* client = reinterpret_cast<Client*>(req->data);

	TCPServer* server = client->m_owner;
	if (!server) {
		return;
	}

	{
		MutexLock lock(server->m_pendingConnectionsLock);
		server->m_pendingConnections.erase(client->m_addr);
	}

	MutexLock lock(server->m_clientsListLock);

	if (status) {
		if (status == UV_ETIMEDOUT) {
			LOGINFO(5, "connection to " << static_cast<char*>(client->m_addrString) << " timed out");
		}
		else {
			LOGWARN(5, "failed to connect to " << static_cast<char*>(client->m_addrString) << ", error " << uv_err_name(status));
		}
		server->on_connect_failed(client->m_isV6, client->m_addr, client->m_port);
		uv_close(reinterpret_cast<uv_handle_t*>(&client->m_socket), nullptr);
		server->m_preallocatedClients.push_back(client);
		return;
	}

	server->on_new_client_nolock(nullptr, client);
}

template<size_t READ_BUF_SIZE, size_t WRITE_BUF_SIZE>
void TCPServer<READ_BUF_SIZE, WRITE_BUF_SIZE>::on_new_client(uv_stream_t* server)
{
	MutexLock lock(m_clientsListLock);

	if (m_finished.load()) {
		return;
	}

	Client* client;

	if (!m_preallocatedClients.empty()) {
		client = m_preallocatedClients.back();
		m_preallocatedClients.pop_back();
		client->reset();
	}
	else {
		client = m_allocateNewClient();
	}

	int err = uv_tcp_init(&m_loop, &client->m_socket);
	if (err) {
		LOGERR(1, "failed to create tcp client handle, error " << uv_err_name(err));
		m_preallocatedClients.push_back(client);
		return;
	}
	client->m_socket.data = client;
	client->m_owner = this;

	err = uv_tcp_nodelay(&client->m_socket, 1);
	if (err) {
		LOGERR(1, "failed to set tcp_nodelay on tcp client handle, error " << uv_err_name(err));
		m_preallocatedClients.push_back(client);
		return;
	}

	err = uv_accept(server, reinterpret_cast<uv_stream_t*>(&client->m_socket));
	if (err) {
		LOGERR(1, "failed to accept client connection, error " << uv_err_name(err));
		m_preallocatedClients.push_back(client);
		return;
	}

	on_new_client_nolock(server, client);
}


template<size_t READ_BUF_SIZE, size_t WRITE_BUF_SIZE>
void TCPServer<READ_BUF_SIZE, WRITE_BUF_SIZE>::on_new_client_nolock(uv_stream_t* server, Client* client)
{
	client->m_prev = m_connectedClientsList;
	client->m_next = m_connectedClientsList->m_next;
	m_connectedClientsList->m_next->m_prev = client;
	m_connectedClientsList->m_next = client;

	++m_numConnections;
	client->m_isIncoming = false;

	sockaddr_storage peer_addr;
	int peer_addr_len = static_cast<int>(sizeof(peer_addr));
	int err = uv_tcp_getpeername(&client->m_socket, reinterpret_cast<sockaddr*>(&peer_addr), &peer_addr_len);
	if (err) {
		LOGERR(1, "failed to get IP address of the client connection, error " << uv_err_name(err));
		client->close();
		return;
	}

	bool is_v6;
	if (server) {
		is_v6 = (std::find(m_listenSockets6.begin(), m_listenSockets6.end(), reinterpret_cast<uv_tcp_t*>(server)) != m_listenSockets6.end());
		client->m_isV6 = is_v6;
	}
	else {
		is_v6 = client->m_isV6;
	}

	if (is_v6) {
		memcpy(client->m_addr.data, &reinterpret_cast<sockaddr_in6*>(&peer_addr)->sin6_addr, sizeof(in6_addr));
		client->m_port = ntohs(reinterpret_cast<sockaddr_in6*>(&peer_addr)->sin6_port);
	}
	else {
		client->m_addr = {};
		client->m_addr.data[10] = 0xFF;
		client->m_addr.data[11] = 0xFF;
		memcpy(client->m_addr.data + 12, &reinterpret_cast<sockaddr_in*>(&peer_addr)->sin_addr, sizeof(in_addr));
		client->m_port = ntohs(reinterpret_cast<sockaddr_in*>(&peer_addr)->sin_port);
	}

	client->init_addr_string(is_v6, &peer_addr);

	if (server) {
		LOGINFO(5, "new connection from " << log::Gray() << static_cast<char*>(client->m_addrString));
		client->m_isIncoming = true;
		++m_numIncomingConnections;
	}
	else {
		LOGINFO(5, "new connection to " << log::Gray() << static_cast<char*>(client->m_addrString));
		client->m_isIncoming = false;
	}

	if (is_banned(client->m_addr)) {
		LOGINFO(5, "peer " << log::Gray() << static_cast<char*>(client->m_addrString) << log::NoColor() << " is banned, disconnecting");
		client->close();
		return;
	}

	if (client->m_owner->m_finished.load() || !client->on_connect()) {
		client->close();
		return;
	}

	err = uv_read_start(reinterpret_cast<uv_stream_t*>(&client->m_socket), Client::on_alloc, Client::on_read);
	if (err) {
		LOGERR(1, "failed to start reading from client connection, error " << uv_err_name(err));
		client->close();
	}
}

template<size_t READ_BUF_SIZE, size_t WRITE_BUF_SIZE>
TCPServer<READ_BUF_SIZE, WRITE_BUF_SIZE>::Client::Client()
{
	Client::reset();

	uv_mutex_init_checked(&m_writeBuffersLock);
	uv_mutex_init_checked(&m_sendLock);

	m_readBuf[0] = '\0';

	m_writeBuffers.resize(2);
	for (size_t i = 0; i < m_writeBuffers.size(); ++i) {
		m_writeBuffers[i] = new WriteBuf();
	}
}

template<size_t READ_BUF_SIZE, size_t WRITE_BUF_SIZE>
TCPServer<READ_BUF_SIZE, WRITE_BUF_SIZE>::Client::~Client()
{
	{
		MutexLock lock(m_writeBuffersLock);
		for (WriteBuf* buf : m_writeBuffers) {
			delete buf;
		}
	}
	uv_mutex_destroy(&m_writeBuffersLock);
	uv_mutex_destroy(&m_sendLock);
}

template<size_t READ_BUF_SIZE, size_t WRITE_BUF_SIZE>
void TCPServer<READ_BUF_SIZE, WRITE_BUF_SIZE>::Client::reset()
{
	m_resetCounter.fetch_add(1);

	m_owner = nullptr;
	m_prev = nullptr;
	m_next = nullptr;
	memset(&m_socket, 0, sizeof(m_socket));
	memset(&m_write, 0, sizeof(m_write));
	memset(&m_connectRequest, 0, sizeof(m_connectRequest));
	m_isV6 = false;
	m_isIncoming = false;
	m_addr = {};
	m_port = -1;
	m_addrString[0] = '\0';
	m_readBufInUse = false;
	m_numRead = 0;
}

template<size_t READ_BUF_SIZE, size_t WRITE_BUF_SIZE>
void TCPServer<READ_BUF_SIZE, WRITE_BUF_SIZE>::Client::on_alloc(uv_handle_t* handle, size_t /*suggested_size*/, uv_buf_t* buf)
{
	Client* pThis = static_cast<Client*>(handle->data);

	if (pThis->m_readBufInUse) {
		LOGWARN(4, "client " << static_cast<const char*>(pThis->m_addrString) << " read buffer is already in use");
		buf->len = 0;
		buf->base = nullptr;
		return;
	}

	if (pThis->m_numRead >= sizeof(pThis->m_readBuf)) {
		LOGWARN(4, "client " << static_cast<const char*>(pThis->m_addrString) << " read buffer is full");
		buf->len = 0;
		buf->base = nullptr;
		return;
	}

	buf->len = sizeof(pThis->m_readBuf) - pThis->m_numRead;
	buf->base = pThis->m_readBuf + pThis->m_numRead;
	pThis->m_readBufInUse = true;
}

template<size_t READ_BUF_SIZE, size_t WRITE_BUF_SIZE>
void TCPServer<READ_BUF_SIZE, WRITE_BUF_SIZE>::Client::on_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
	Client* pThis = static_cast<Client*>(stream->data);
	pThis->m_readBufInUse = false;

	if (nread > 0) {
		if (pThis->m_owner && !pThis->m_owner->m_finished.load()) {
			if (!pThis->on_read(buf->base, static_cast<uint32_t>(nread))) {
				pThis->close();
			}
		}
	}
	else if (nread < 0) {
		if (nread != UV_EOF) {
			LOGWARN(5, "client " << static_cast<const char*>(pThis->m_addrString) << " failed to read response, err = " << uv_err_name(static_cast<int>(nread)));
		}
		pThis->close();
	}
}

template<size_t READ_BUF_SIZE, size_t WRITE_BUF_SIZE>
void TCPServer<READ_BUF_SIZE, WRITE_BUF_SIZE>::Client::on_write(uv_write_t* req, int status)
{
	Client::WriteBuf* buf = static_cast<Client::WriteBuf*>(req->data);
	Client* client = buf->m_client;

	{
		MutexLock lock(client->m_writeBuffersLock);
		client->m_writeBuffers.push_back(buf);
	}

	if (status != 0) {
		LOGWARN(5, "client " << static_cast<const char*>(client->m_addrString) << " failed to write data to client connection, error " << uv_err_name(status));
		client->close();
	}
}

template<size_t READ_BUF_SIZE, size_t WRITE_BUF_SIZE>
void TCPServer<READ_BUF_SIZE, WRITE_BUF_SIZE>::Client::close()
{
	if (!m_owner) {
		// Already closed
		return;
	}

	uv_read_stop(reinterpret_cast<uv_stream_t*>(&m_socket));

	uv_tcp_t* s = &m_socket;
	uv_handle_t* h = reinterpret_cast<uv_handle_t*>(s);
	if (!uv_is_closing(h)) {
		uv_close(h, on_connection_close);
	}
}

template<size_t READ_BUF_SIZE, size_t WRITE_BUF_SIZE>
void TCPServer<READ_BUF_SIZE, WRITE_BUF_SIZE>::Client::ban(uint64_t seconds)
{
	if (m_owner) {
		LOGWARN(3, "peer " << static_cast<char*>(m_addrString) << " banned for " << seconds << " seconds");
		m_owner->ban(m_addr, seconds);
	}
}

template<size_t READ_BUF_SIZE, size_t WRITE_BUF_SIZE>
void TCPServer<READ_BUF_SIZE, WRITE_BUF_SIZE>::Client::init_addr_string(bool is_v6, const sockaddr_storage* peer_addr)
{
	const char* addr_str;
	char addr_str_buf[64];

	if (is_v6) {
		addr_str = inet_ntop(AF_INET6, &reinterpret_cast<const sockaddr_in6*>(peer_addr)->sin6_addr, addr_str_buf, sizeof(addr_str_buf));
	}
	else {
		addr_str = inet_ntop(AF_INET, &reinterpret_cast<const sockaddr_in*>(peer_addr)->sin_addr, addr_str_buf, sizeof(addr_str_buf));
	}

	if (addr_str) {
		size_t n = strlen(addr_str);
		if (n > sizeof(m_addrString) - 16) {
			n = sizeof(m_addrString) - 16;
		}

		log::Stream s(m_addrString);
		if (is_v6) {
			s << '[' << log::const_buf(addr_str, n) << "]:" << ntohs(reinterpret_cast<const sockaddr_in6*>(peer_addr)->sin6_port) << '\0';
		}
		else {
			s << log::const_buf(addr_str, n) << ':' << ntohs(reinterpret_cast<const sockaddr_in*>(peer_addr)->sin_port) << '\0';
		}
	}
}

} // namespace p2pool
