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
#include "tcp_server.h"

static thread_local void* server_event_loop_thread = nullptr;
static thread_local const char* log_category_prefix = "TCPServer ";

namespace p2pool {

TCPServer::TCPServer(int default_backlog, allocate_client_callback allocate_new_client)
	: m_allocateNewClient(allocate_new_client)
	, m_defaultBacklog(default_backlog)
	, m_loopThread{}
	, m_loopThreadRunning(false)
#ifdef WITH_UPNP
	, m_portMapping(0)
#endif
	, m_socks5ProxyV6(false)
	, m_socks5ProxyIP{}
	, m_socks5ProxyPort(-1)
	, m_finished(0)
	, m_listenPort(-1)
	, m_loop{}
	, m_numConnections{ 0 }
	, m_numIncomingConnections{ 0 }
	, m_shutdownPrepare{}
	, m_shutdownTimer{}
	, m_shutdownCountdown(30)
	, m_numHandles(0)
{
	int err = uv_loop_init(&m_loop);
	if (err) {
		LOGERR(1, "failed to create event loop, error " << uv_err_name(err));
		PANIC_STOP();
	}

	// Init loop user data before running it
	GetLoopUserData(&m_loop);

	err = uv_async_init(&m_loop, &m_dropConnectionsAsync, on_drop_connections);
	if (err) {
		LOGERR(1, "uv_async_init failed, error " << uv_err_name(err));
		PANIC_STOP();
	}
	m_dropConnectionsAsync.data = this;

	err = uv_async_init(&m_loop, &m_shutdownAsync, on_shutdown);
	if (err) {
		LOGERR(1, "uv_async_init failed, error " << uv_err_name(err));
		PANIC_STOP();
	}
	m_shutdownAsync.data = this;

	uv_mutex_init_checked(&m_bansLock);

	m_connectedClientsList = m_allocateNewClient();
	m_connectedClientsList->m_next = m_connectedClientsList;
	m_connectedClientsList->m_prev = m_connectedClientsList;
}

TCPServer::~TCPServer()
{
	if (m_finished.load() == 0) {
		LOGERR(1, "TCP wasn't shutdown properly");
		shutdown_tcp();
	}

	delete m_connectedClientsList;
}

void TCPServer::parse_address_list_internal(const std::string& address_list, Callback<void, bool, const std::string&, const std::string&, int>::Base&& callback)
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

			const int port = strtol(address.substr(k2 + 1).c_str(), nullptr, 10);
			if ((port > 0) && (port < 65536)) {
				callback(is_v6, address, ip, port);
			}
			else {
				error_invalid_ip(address);
			}
		}

		if (k1 == std::string::npos) {
			return;
		}
	}
}

bool TCPServer::start_listening(bool is_v6, const std::string& ip, int port, std::string address)
{
	if ((m_listenPort >= 0) && (m_listenPort != port)) {
		LOGERR(1, "all sockets must be listening on the same port number, fix the command line");
		return false;
	}

	uv_tcp_t* socket = new uv_tcp_t();

	int err = uv_tcp_init(&m_loop, socket);
	if (err) {
		LOGERR(1, "failed to create tcp server handle, error " << uv_err_name(err));
		delete socket;
		return false;
	}
	socket->data = this;

	ON_SCOPE_LEAVE([is_v6, this, socket]()
	{
		const std::vector<uv_tcp_t*>& v = is_v6 ? m_listenSockets6 : m_listenSockets;
		if (std::find(v.begin(), v.end(), socket) == v.end()) {
			uv_close(reinterpret_cast<uv_handle_t*>(socket), [](uv_handle_t* h) { delete reinterpret_cast<uv_tcp_t*>(h); });
		}
	});

	err = uv_tcp_nodelay(socket, 1);
	if (err) {
		LOGERR(1, "failed to set tcp_nodelay on tcp server handle, error " << uv_err_name(err));
		return false;
	}

	if (is_v6) {
		if (address.empty()) {
			char buf[64] = {};
			log::Stream s(buf);
			s << '[' << ip << "]:" << port;
			address = buf;
		}

		sockaddr_in6 addr6;
		err = uv_ip6_addr(ip.c_str(), port, &addr6);
		if (err) {
			LOGERR(1, "failed to parse IPv6 address " << ip << ", error " << uv_err_name(err));
			return false;
		}

		err = uv_tcp_bind(socket, reinterpret_cast<sockaddr*>(&addr6), UV_TCP_IPV6ONLY);
		if (err) {
			LOGERR(1, "failed to bind tcp server IPv6 socket " << address << ", error " << uv_err_name(err));
			return false;
		}
	}
	else {
		if (address.empty()) {
			char buf[64] = {};
			log::Stream s(buf);
			s << ip << ':' << port;
			address = buf;
		}

		sockaddr_in addr;
		err = uv_ip4_addr(ip.c_str(), port, &addr);
		if (err) {
			LOGERR(1, "failed to parse IPv4 address " << ip << ", error " << uv_err_name(err));
			return false;
		}

		err = uv_tcp_bind(socket, reinterpret_cast<sockaddr*>(&addr), 0);
		if (err) {
			LOGERR(1, "failed to bind tcp server IPv4 socket " << address << ", error " << uv_err_name(err));
			return false;
		}
	}

	err = uv_listen(reinterpret_cast<uv_stream_t*>(socket), m_defaultBacklog, on_new_connection);
	if (err) {
		LOGERR(1, "failed to listen on tcp server socket " << address << ", error " << uv_err_name(err));
		return false;
	}

	if (is_v6) {
		m_listenSockets6.push_back(socket);
	}
	else {
		m_listenSockets.push_back(socket);
	}

	if (m_listenPort < 0) {
		m_listenPort = port;
	}

	LOGINFO(1, "listening on " << log::Gray() << address);
	return true;
}

void TCPServer::start_listening(const std::string& listen_addresses, bool upnp)
{
	if (listen_addresses.empty()) {
		LOGERR(1, "listen address not set");
		PANIC_STOP();
	}

	parse_address_list(listen_addresses,
		[this](bool is_v6, const std::string& /*address*/, const std::string& ip, int port)
		{
			if (!start_listening(is_v6, ip, port)) {
				PANIC_STOP();
			}
		});

#ifdef WITH_UPNP
	if (upnp) {
		m_portMapping = add_portmapping(external_listen_port(), m_listenPort);
	}
#else
	(void)upnp;
#endif

	const int err = uv_thread_create(&m_loopThread, loop, this);
	if (err) {
		LOGERR(1, "failed to start event loop thread, error " << uv_err_name(err));
		PANIC_STOP();
	}
}

bool TCPServer::connect_to_peer(bool is_v6, const char* ip, int port)
{
	if (!ip || (strlen(ip) > sizeof(Client::m_addrString) - 16)) {
		LOGERR(1, "failed to parse IP address, too long");
		return false;
	}

	if (m_finished.load()) {
		return false;
	}

	Client* client = get_client();
	client->m_owner = this;
	client->m_port = port;
	client->m_isV6 = is_v6;

	if (!str_to_ip(is_v6, ip, client->m_addr)) {
		return_client(client);
		return false;
	}

	log::Stream s(client->m_addrString);
	if (is_v6) {
		s << '[' << ip << "]:" << port << '\0';
	}
	else {
		s << ip << ':' << port << '\0';
	}

	return connect_to_peer(client);
}

bool TCPServer::connect_to_peer(bool is_v6, const raw_ip& ip, int port)
{
	if (m_finished.load()) {
		return false;
	}

	Client* client = get_client();
	client->m_owner = this;
	client->m_addr = ip;
	client->m_port = port;
	client->m_isV6 = is_v6;
	client->init_addr_string();

	return connect_to_peer(client);
}

bool TCPServer::is_banned(bool is_v6, raw_ip ip)
{
	if (ip.is_localhost()) {
		return false;
	}

	// If it's IPv6, check the whole /64 prefix
	if (is_v6 && !ip.is_ipv4_prefix()) {
		memset(ip.data + 8, 0, sizeof(ip.data) - 8);
	}

	const auto cur_time = std::chrono::steady_clock::now();

	MutexLock lock(m_bansLock);

	auto it = m_bans.find(ip);
	if (it != m_bans.end()) {
		const bool banned = (cur_time < it->second);
		if (!banned) {
			m_bans.erase(it);
		}
		return banned;
	}

	return false;
}

bool TCPServer::connect_to_peer(Client* client)
{
	if (is_banned(client->m_isV6, client->m_addr)) {
		LOGINFO(5, "peer " << log::Gray() << static_cast<char*>(client->m_addrString) << log::NoColor() << " is banned, not connecting to it");
		return_client(client);
		return false;
	}

	if (!m_pendingConnections.insert(client->m_addr).second) {
		LOGINFO(6, "there is already a pending connection to this IP, not connecting to " << log::Gray() << static_cast<char*>(client->m_addrString));
		return_client(client);
		return false;
	}

	int err = uv_tcp_init(&m_loop, &client->m_socket);
	if (err) {
		LOGERR(1, "failed to create tcp client handle, error " << uv_err_name(err));
		return_client(client);
		return false;
	}
	client->m_socket.data = client;

	err = uv_tcp_nodelay(&client->m_socket, 1);
	if (err) {
		LOGERR(1, "failed to set tcp_nodelay on tcp client handle, error " << uv_err_name(err));
		uv_close(reinterpret_cast<uv_handle_t*>(&client->m_socket), on_connection_error);
		return false;
	}

	if (client->m_readBufSize < sizeof(uv_connect_t)) {
		LOGERR(1, "client read buf size is too small (" << client->m_readBufSize << " bytes), expected at least " << sizeof(uv_connect_t) << " bytes");
		uv_close(reinterpret_cast<uv_handle_t*>(&client->m_socket), on_connection_error);
		return false;
	}

	uv_connect_t* connect_request = reinterpret_cast<uv_connect_t*>(client->m_readBuf);
	memset(connect_request, 0, sizeof(uv_connect_t));
	connect_request->data = client;

	sockaddr_storage addr{};

	if (m_socks5Proxy.empty()) {
		if (client->m_isV6) {
			sockaddr_in6* addr6 = reinterpret_cast<sockaddr_in6*>(&addr);
			addr6->sin6_family = AF_INET6;
			memcpy(&addr6->sin6_addr, client->m_addr.data, sizeof(in6_addr));
			addr6->sin6_port = htons(static_cast<uint16_t>(client->m_port));
		}
		else {
			sockaddr_in* addr4 = reinterpret_cast<sockaddr_in*>(&addr);
			addr4->sin_family = AF_INET;
			memcpy(&addr4->sin_addr, client->m_addr.data + 12, sizeof(in_addr));
			addr4->sin_port = htons(static_cast<uint16_t>(client->m_port));
		}
	}
	else {
		if (m_socks5ProxyV6) {
			sockaddr_in6* addr6 = reinterpret_cast<sockaddr_in6*>(&addr);
			addr6->sin6_family = AF_INET6;
			memcpy(&addr6->sin6_addr, m_socks5ProxyIP.data, sizeof(in6_addr));
			addr6->sin6_port = htons(static_cast<uint16_t>(m_socks5ProxyPort));
		}
		else {
			sockaddr_in* addr4 = reinterpret_cast<sockaddr_in*>(&addr);
			addr4->sin_family = AF_INET;
			memcpy(&addr4->sin_addr, m_socks5ProxyIP.data + 12, sizeof(in_addr));
			addr4->sin_port = htons(static_cast<uint16_t>(m_socks5ProxyPort));
		}
	}

	err = uv_tcp_connect(connect_request, &client->m_socket, reinterpret_cast<sockaddr*>(&addr), on_connect);
	if (err) {
		LOGWARN(5, "failed to initiate tcp connection to " << static_cast<const char*>(client->m_addrString) << ", error " << uv_err_name(err));
		m_pendingConnections.erase(client->m_addr);
		uv_close(reinterpret_cast<uv_handle_t*>(&client->m_socket), on_connection_error);
		return false;
	}
	else {
		LOGINFO(5, "connecting to " << log::Gray() << static_cast<const char*>(client->m_addrString));
	}

	return true;
}

#ifdef P2POOL_DEBUGGING
void TCPServer::check_event_loop_thread(const char* func) const
{
	if (server_event_loop_thread != this) {
		LOGERR(1, func << " called from another thread, this is not thread safe");
	}
}
#endif

void TCPServer::close_sockets(bool listen_sockets)
{
	check_event_loop_thread(__func__);

	if (listen_sockets) {
		for (uv_tcp_t* s : m_listenSockets6) {
			uv_handle_t* h = reinterpret_cast<uv_handle_t*>(s);
			if (!uv_is_closing(h)) {
				uv_close(h, [](uv_handle_t* h) { delete reinterpret_cast<uv_tcp_t*>(h); });
			}
		}
		for (uv_tcp_t* s : m_listenSockets) {
			uv_handle_t* h = reinterpret_cast<uv_handle_t*>(s);
			if (!uv_is_closing(h)) {
				uv_close(h, [](uv_handle_t* h) { delete reinterpret_cast<uv_tcp_t*>(h); });
			}
		}
	}

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

void TCPServer::error_invalid_ip(const std::string& address)
{
	LOGERR(1, "invalid IP:port " << address);
}

void TCPServer::shutdown_tcp()
{
	if (m_finished.exchange(1)) {
		return;
	}

	uv_async_send(&m_shutdownAsync);

#ifdef WITH_UPNP
	if (m_portMapping) {
		remove_portmapping(m_portMapping);
	}
#endif

	if (m_loopThreadRunning.load()) {
		uv_thread_join(&m_loopThread);
	}

	uv_mutex_destroy(&m_bansLock);

	LOGINFO(1, "stopped");
}

void TCPServer::print_status()
{
	LOGINFO(0, "status" <<
		"\nConnections = " << m_numConnections.load() << " (" << m_numIncomingConnections.load() << " incoming)"
	);
}

void TCPServer::ban(bool is_v6, raw_ip ip, uint64_t seconds)
{
	if (ip.is_localhost()) {
		return;
	}

	// If it's IPv6, ban the whole /64 prefix
	if (is_v6 && !ip.is_ipv4_prefix()) {
		memset(ip.data + 8, 0, sizeof(ip.data) - 8);
	}

	const auto ban_time = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);

	MutexLock lock(m_bansLock);
	m_bans[ip] = ban_time;
}

void TCPServer::print_bans()
{
	using namespace std::chrono;
	const auto cur_time = steady_clock::now();

	MutexLock lock(m_bansLock);

	for (const auto& b : m_bans) {
		if (cur_time < b.second) {
			const uint64_t t = duration_cast<seconds>(b.second - cur_time).count();
			LOGINFO(0, b.first << " is banned (" << t << " seconds left)");
		}
	}
}

bool TCPServer::send_internal(Client* client, Callback<size_t, uint8_t*, size_t>::Base&& callback)
{
	check_event_loop_thread(__func__);

	if (client->m_isClosing) {
		LOGWARN(5, "client " << static_cast<const char*>(client->m_addrString) << " is being disconnected, can't send any more data");
		return true;
	}

	const size_t bytes_written = callback(m_callbackBuf.data(), m_callbackBuf.size());

	if (bytes_written > m_callbackBuf.size()) {
		LOGERR(0, "send callback wrote " << bytes_written << " bytes, expected no more than " << m_callbackBuf.size() << " bytes");
		PANIC_STOP();
	}

	if (bytes_written == 0) {
		LOGWARN(1, "send callback wrote 0 bytes, nothing to do");
		return true;
	}

	WriteBuf* buf = get_write_buffer(bytes_written);

	buf->m_write.data = buf;
	buf->m_client = client;

	if (buf->m_dataCapacity < bytes_written) {
		buf->m_dataCapacity = round_up(bytes_written, 64);
		buf->m_data = realloc_hook(buf->m_data, buf->m_dataCapacity);
		if (!buf->m_data) {
			LOGERR(0, "failed to allocate " << buf->m_dataCapacity << " bytes to send data");
			PANIC_STOP();
		}
	}

	memcpy(buf->m_data, m_callbackBuf.data(), bytes_written);

	uv_buf_t bufs[1];
	bufs[0].base = reinterpret_cast<char*>(buf->m_data);
	bufs[0].len = static_cast<int>(bytes_written);

	const int err = uv_write(&buf->m_write, reinterpret_cast<uv_stream_t*>(&client->m_socket), bufs, 1, Client::on_write);
	if (err) {
		LOGWARN(1, "failed to start writing data to client connection " << static_cast<const char*>(client->m_addrString) << ", error " << uv_err_name(err));
		return_write_buffer(buf);
		return false;
	}

	return true;
}

const char* TCPServer::get_log_category() const
{
	return log_category_prefix;
}

void TCPServer::loop(void* data)
{
	TCPServer* server = static_cast<TCPServer*>(data);
	server->m_loopThreadRunning.exchange(true);
	ON_SCOPE_LEAVE([server]() { server->m_loopThreadRunning.exchange(false); });

	log_category_prefix = server->get_log_category();

	LOGINFO(1, "event loop started");
	server_event_loop_thread = data;

	server->m_preallocatedClients.reserve(server->m_defaultBacklog);
	for (int i = 0; i < server->m_defaultBacklog; ++i) {
		WriteBuf* wb = new WriteBuf();
		const size_t capacity = wb->m_dataCapacity;

		Client* c = server->m_allocateNewClient();

		ASAN_POISON_MEMORY_REGION(wb, sizeof(WriteBuf));
		ASAN_POISON_MEMORY_REGION(c, c->size());
		ASAN_UNPOISON_MEMORY_REGION(&c->m_resetCounter, sizeof(c->m_resetCounter));

		server->m_writeBuffers.emplace(capacity, wb);
		server->m_preallocatedClients.emplace_back(c);
	}

	int err = uv_run(&server->m_loop, UV_RUN_DEFAULT);
	if (err) {
		LOGWARN(1, "uv_run returned " << err);
	}

	err = uv_loop_close(&server->m_loop);
	if (err) {
		LOGWARN(1, "uv_loop_close returned error " << uv_err_name(err));
	}

	for (const auto& it : server->m_writeBuffers) {
		WriteBuf* buf = it.second;

		ASAN_UNPOISON_MEMORY_REGION(buf, sizeof(WriteBuf));
		if (buf->m_data) {
			ASAN_UNPOISON_MEMORY_REGION(buf->m_data, buf->m_dataCapacity);
			free_hook(buf->m_data);
		}
		delete buf;
	}
	server->m_writeBuffers.clear();

	for (Client* c : server->m_preallocatedClients) {
		ASAN_UNPOISON_MEMORY_REGION(c, sizeof(Client));
		ASAN_UNPOISON_MEMORY_REGION(c, c->size());
		delete c;
	}
	server->m_preallocatedClients.clear();

	LOGINFO(1, "event loop stopped");
}

void TCPServer::on_new_connection(uv_stream_t* server, int status)
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

void TCPServer::on_connection_close(uv_handle_t* handle)
{
	Client* client = static_cast<Client*>(handle->data);
	TCPServer* owner = client->m_owner;

	LOGINFO(5, "peer " << log::Gray() << static_cast<char*>(client->m_addrString) << log::NoColor() << " disconnected");

	if (owner) {
		owner->check_event_loop_thread(__func__);

		Client* prev_in_list = client->m_prev;
		Client* next_in_list = client->m_next;

		const bool is_incoming = client->m_isIncoming;

		client->reset();

		prev_in_list->m_next = next_in_list;
		next_in_list->m_prev = prev_in_list;

		owner->return_client(client);

		--owner->m_numConnections;
		if (is_incoming) {
			--owner->m_numIncomingConnections;
		}
	}
	else {
		LOGERR(5, "internal error: can't find TCPServer instance for peer " << log::Gray() << static_cast<char*>(client->m_addrString) << ", this will leak memory");
	}
}

void TCPServer::on_connection_error(uv_handle_t* handle)
{
	Client* client = reinterpret_cast<Client*>(handle->data);
	client->m_owner->return_client(client);
}

void TCPServer::on_connect(uv_connect_t* req, int status)
{
	Client* client = reinterpret_cast<Client*>(req->data);

	TCPServer* server = client->m_owner;
	if (!server) {
		return;
	}

	server->m_pendingConnections.erase(client->m_addr);

	if (status) {
		if (status == UV_ETIMEDOUT) {
			LOGINFO(5, "connection to " << static_cast<char*>(client->m_addrString) << " timed out");
		}
		else {
			LOGWARN(5, "failed to connect to " << static_cast<char*>(client->m_addrString) << ", error " << uv_err_name(status));
		}
		server->on_connect_failed(client->m_isV6, client->m_addr, client->m_port);
		uv_close(reinterpret_cast<uv_handle_t*>(&client->m_socket), on_connection_error);
		return;
	}

	server->on_new_client(nullptr, client);
}

void TCPServer::on_new_client(uv_stream_t* server)
{
	if (m_finished.load()) {
		return;
	}

	Client* client = get_client();

	int err = uv_tcp_init(&m_loop, &client->m_socket);
	if (err) {
		LOGERR(1, "failed to create tcp client handle, error " << uv_err_name(err));
		return_client(client);
		return;
	}
	client->m_socket.data = client;
	client->m_owner = this;

	err = uv_tcp_nodelay(&client->m_socket, 1);
	if (err) {
		LOGERR(1, "failed to set tcp_nodelay on tcp client handle, error " << uv_err_name(err));
		uv_close(reinterpret_cast<uv_handle_t*>(&client->m_socket), on_connection_error);
		return;
	}

	err = uv_accept(server, reinterpret_cast<uv_stream_t*>(&client->m_socket));
	if (err) {
		LOGERR(1, "failed to accept client connection, error " << uv_err_name(err));
		uv_close(reinterpret_cast<uv_handle_t*>(&client->m_socket), on_connection_error);
		return;
	}

	on_new_client(server, client);
}

void TCPServer::on_new_client(uv_stream_t* server, Client* client)
{
	check_event_loop_thread(__func__);

	client->m_prev = m_connectedClientsList;
	client->m_next = m_connectedClientsList->m_next;
	m_connectedClientsList->m_next->m_prev = client;
	m_connectedClientsList->m_next = client;

	++m_numConnections;

	client->m_isIncoming = (server != nullptr);

	if (client->m_isIncoming) {
		++m_numIncomingConnections;

		client->m_isV6 = (std::find(m_listenSockets6.begin(), m_listenSockets6.end(), reinterpret_cast<uv_tcp_t*>(server)) != m_listenSockets6.end());

		sockaddr_storage peer_addr;
		int peer_addr_len = static_cast<int>(sizeof(peer_addr));
		int err = uv_tcp_getpeername(&client->m_socket, reinterpret_cast<sockaddr*>(&peer_addr), &peer_addr_len);
		if (err) {
			LOGERR(1, "failed to get IP address of the client connection, error " << uv_err_name(err));
			client->close();
			return;
		}

		if (client->m_isV6) {
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

		client->init_addr_string();
	}

	LOGINFO(5, "new connection " << (client->m_isIncoming ? "from " : "to ") << log::Gray() << static_cast<char*>(client->m_addrString));

	if (is_banned(client->m_isV6, client->m_addr)) {
		LOGINFO(5, "peer " << log::Gray() << static_cast<char*>(client->m_addrString) << log::NoColor() << " is banned, disconnecting");
		client->close();
		return;
	}

	TCPServer* owner = client->m_owner;

	if (owner->m_finished.load()) {
		client->close();
		return;
	}

	if (client->m_isIncoming || owner->m_socks5Proxy.empty()) {
		if (!client->on_connect()) {
			client->close();
			return;
		}
	}
	else {
		const bool result = owner->send(client,
			[](uint8_t* buf, size_t buf_size) -> size_t
			{
				if (buf_size < 3) {
					return 0;
				}

				buf[0] = 5; // Protocol version (SOCKS5)
				buf[1] = 1; // NMETHODS
				buf[2] = 0; // Method 0 (no authentication)

				return 3;
			});

		if (result) {
			client->m_socks5ProxyState = Client::Socks5ProxyState::MethodSelectionSent;
		}
		else {
			client->close();
		}
	}

	const int err = uv_read_start(reinterpret_cast<uv_stream_t*>(&client->m_socket), Client::on_alloc, Client::on_read);
	if (err) {
		LOGERR(1, "failed to start reading from client connection, error " << uv_err_name(err));
		client->close();
	}
}

void TCPServer::on_shutdown(uv_async_t* async)
{
	TCPServer* s = reinterpret_cast<TCPServer*>(async->data);
	s->on_shutdown();
	s->close_sockets(true);

	uv_close(reinterpret_cast<uv_handle_t*>(&s->m_dropConnectionsAsync), nullptr);
	uv_close(reinterpret_cast<uv_handle_t*>(&s->m_shutdownAsync), nullptr);

	delete GetLoopUserData(&s->m_loop, false);

	s->m_numHandles = 0;
	uv_walk(&s->m_loop, [](uv_handle_t*, void* n) { (*reinterpret_cast<uint32_t*>(n))++; }, &s->m_numHandles);

	uv_prepare_init(&s->m_loop, &s->m_shutdownPrepare);
	s->m_shutdownPrepare.data = s;

	uv_timer_init(&s->m_loop, &s->m_shutdownTimer);
	s->m_shutdownTimer.data = s;
	s->m_shutdownCountdown = 30;

	uv_timer_start(&s->m_shutdownTimer,
		[](uv_timer_t* h)
		{
			TCPServer* s = reinterpret_cast<TCPServer*>(h->data);
			const uint32_t k = --s->m_shutdownCountdown;
			if (k > 0) {
				LOGINFO(1, "waiting for event loop to stop for " << k << " more seconds (" << s->m_numHandles << " handles left)...");
			}
			else {
				LOGINFO(1, "force stopping the event loop...");
				uv_timer_stop(&s->m_shutdownTimer);
				uv_prepare_stop(&s->m_shutdownPrepare);
				uv_close(reinterpret_cast<uv_handle_t*>(&s->m_shutdownTimer), nullptr);
				uv_close(reinterpret_cast<uv_handle_t*>(&s->m_shutdownPrepare), nullptr);
				uv_stop(&s->m_loop);
			}
		}, 1000, 1000);

	uv_prepare_start(&s->m_shutdownPrepare,
		[](uv_prepare_t* h)
		{
			TCPServer* s = reinterpret_cast<TCPServer*>(h->data);

			s->m_numHandles = 0;
			uv_walk(&s->m_loop, [](uv_handle_t*, void* n) { (*reinterpret_cast<uint32_t*>(n))++; }, &s->m_numHandles);

			if (s->m_numHandles > 2) {
				// Don't count m_shutdownTimer and m_shutdownPrepare
				s->m_numHandles -= 2;
			}
			else {
				uv_timer_stop(&s->m_shutdownTimer);
				uv_prepare_stop(&s->m_shutdownPrepare);
				uv_close(reinterpret_cast<uv_handle_t*>(&s->m_shutdownTimer), nullptr);
				uv_close(reinterpret_cast<uv_handle_t*>(&s->m_shutdownPrepare), nullptr);
			}
		});
}

TCPServer::WriteBuf* TCPServer::get_write_buffer(size_t size_hint)
{
	WriteBuf* buf;

	if (!m_writeBuffers.empty()) {
		// Try to find the smallest buffer that still has enough capacity
		// If there is no buffer with enough capacity, just take the largest available buffer
		auto it = m_writeBuffers.lower_bound(size_hint);
		if (it == m_writeBuffers.end()) {
			it = std::prev(it);
		}

		buf = it->second;
		m_writeBuffers.erase(it);

		ASAN_UNPOISON_MEMORY_REGION(buf, sizeof(WriteBuf));
		if (buf->m_data) {
			ASAN_UNPOISON_MEMORY_REGION(buf->m_data, buf->m_dataCapacity);
		}
	}
	else {
		buf = new WriteBuf();
	}

	return buf;
}

void TCPServer::return_write_buffer(WriteBuf* buf)
{
	const size_t capacity = buf->m_dataCapacity;

	if (buf->m_data) {
		ASAN_POISON_MEMORY_REGION(buf->m_data, capacity);
	}
	ASAN_POISON_MEMORY_REGION(buf, sizeof(WriteBuf));

	m_writeBuffers.emplace(capacity, buf);
}

TCPServer::Client* TCPServer::get_client()
{
	Client* c;

	if (!m_preallocatedClients.empty()) {
		c = m_preallocatedClients.back();
		m_preallocatedClients.pop_back();
		ASAN_UNPOISON_MEMORY_REGION(c, sizeof(Client));
		ASAN_UNPOISON_MEMORY_REGION(c, c->size());
		c->reset();
	}
	else {
		c = m_allocateNewClient();
	}

	return c;
}

void TCPServer::return_client(Client* c)
{
	ASAN_POISON_MEMORY_REGION(c, c->size());
	ASAN_UNPOISON_MEMORY_REGION(&c->m_resetCounter, sizeof(c->m_resetCounter));
	m_preallocatedClients.push_back(c);
}

TCPServer::Client::Client(char* read_buf, size_t size)
	: m_readBuf(read_buf)
	, m_readBufSize(static_cast<uint32_t>(size))
	, m_owner(nullptr)
	, m_prev(nullptr)
	, m_next(nullptr)
	, m_socket{}
	, m_isV6(false)
	, m_isIncoming(false)
	, m_readBufInUse(false)
	, m_isClosing(false)
	, m_numRead(0)
	, m_addr{}
	, m_port(0)
	, m_addrString{}
	, m_socks5ProxyState(Socks5ProxyState::Default)
	, m_resetCounter{ 0 }
{
	m_readBuf[0] = '\0';
	m_readBuf[m_readBufSize - 1] = '\0';
}

void TCPServer::Client::reset()
{
	m_resetCounter.fetch_add(1);

	m_owner = nullptr;
	m_prev = nullptr;
	m_next = nullptr;
	memset(&m_socket, 0, sizeof(m_socket));
	m_isV6 = false;
	m_isIncoming = false;
	m_readBufInUse = false;
	m_isClosing = false;
	m_numRead = 0;
	m_addr = {};
	m_port = -1;
	m_addrString[0] = '\0';
	m_socks5ProxyState = Socks5ProxyState::Default;
	m_readBuf[0] = '\0';
	m_readBuf[m_readBufSize - 1] = '\0';
}

void TCPServer::Client::on_alloc(uv_handle_t* handle, size_t /*suggested_size*/, uv_buf_t* buf)
{
	Client* pThis = static_cast<Client*>(handle->data);

	if (pThis->m_readBufInUse) {
		LOGWARN(4, "client " << static_cast<const char*>(pThis->m_addrString) << " read buffer is already in use");
		buf->len = 0;
		buf->base = nullptr;
		return;
	}

	if (pThis->m_numRead >= pThis->m_readBufSize) {
		LOGWARN(4, "client " << static_cast<const char*>(pThis->m_addrString) << " read buffer is full");
		buf->len = 0;
		buf->base = nullptr;
		return;
	}

	buf->len = pThis->m_readBufSize - pThis->m_numRead;
	buf->base = pThis->m_readBuf + pThis->m_numRead;
	pThis->m_readBufInUse = true;
}

void TCPServer::Client::on_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
	Client* client = static_cast<Client*>(stream->data);
	client->m_readBufInUse = false;

	if (client->m_isClosing) {
		LOGWARN(5, "client " << static_cast<const char*>(client->m_addrString) << " is being disconnected but data received from it, nread = " << nread << ". Ignoring it.");
		return;
	}

	if (nread > 0) {
		if (client->m_owner && !client->m_owner->m_finished.load()) {
			if (client->m_socks5ProxyState == Socks5ProxyState::Default) {
				if (!client->on_read(buf->base, static_cast<uint32_t>(nread))) {
					client->close();
				}
			}
			else if (!client->on_proxy_handshake(buf->base, static_cast<uint32_t>(nread))) {
				client->close();
			}
		}
	}
	else if (nread < 0) {
		if (nread != UV_EOF) {
			const int err = static_cast<int>(nread);
			LOGWARN(5, "client " << static_cast<const char*>(client->m_addrString) << " failed to read response, err = " << uv_err_name(err));
			client->on_read_failed(err);
		}
		else {
			client->on_disconnected();
		}
		client->close();
	}
}

bool TCPServer::Client::on_proxy_handshake(char* data, uint32_t size)
{
	if ((data != m_readBuf + m_numRead) || (data + size > m_readBuf + m_readBufSize)) {
		LOGERR(1, "peer " << static_cast<char*>(m_addrString) << " invalid data pointer or size in on_read()");
		return false;
	}
	m_numRead += size;

	uint32_t n = 0;

	switch (m_socks5ProxyState) {
	case Socks5ProxyState::MethodSelectionSent:
		if (m_numRead >= 2) {
			if ((m_readBuf[0] != 5) && (m_readBuf[1] != 0)) {
				LOGWARN(5, "SOCKS5 proxy returned an invalid METHOD selection message");
				return false;
			}
			n = 2;

			const bool result = m_owner->send(this,
				[this](uint8_t* buf, size_t buf_size) -> size_t
				{
					if (buf_size < 22) {
						return 0;
					}

					buf[0] = 5; // Protocol version (SOCKS5)
					buf[1] = 1; // CONNECT
					buf[2] = 0; // RESERVED
					if (m_isV6) {
						buf[3] = 4; // ATYP
						memcpy(buf + 4, m_addr.data, 16);
						buf[20] = static_cast<uint8_t>(m_port >> 8);
						buf[21] = static_cast<uint8_t>(m_port & 0xFF);
					}
					else {
						buf[3] = 1; // ATYP
						memcpy(buf + 4, m_addr.data + 12, 4);
						buf[8] = static_cast<uint8_t>(m_port >> 8);
						buf[9] = static_cast<uint8_t>(m_port & 0xFF);
					}

					return m_isV6 ? 22 : 10;
				});

			if (result) {
				m_socks5ProxyState = Socks5ProxyState::ConnectRequestSent;
			}
			else {
				close();
			}
		}
		break;

	case Socks5ProxyState::ConnectRequestSent:
		if (m_numRead >= 4) {
			const uint8_t* p = reinterpret_cast<uint8_t*>(m_readBuf);
			if ((p[0] != 5) && (p[1] != 0) && p[2] != 0) {
				LOGWARN(5, "SOCKS5 proxy returned an invalid reply to CONNECT");
				return false;
			}

			switch (p[3]) {
			case 1:
				if (m_numRead >= 10) {
					m_socks5ProxyState = Socks5ProxyState::Default;
					n = 10;
				}
				break;
			case 3:
				if (m_numRead >= 5) {
					const uint32_t len = p[4];
					if (m_numRead >= 7 + len) {
						m_socks5ProxyState = Socks5ProxyState::Default;
						n = 7 + len;
					}
				}
				break;
			case 4:
				if (m_numRead >= 22) {
					m_socks5ProxyState = Socks5ProxyState::Default;
					n = 22;
				}
				break;
			default:
				LOGWARN(5, "SOCKS5 proxy returned an invalid reply to CONNECT (invalid address type " << p[3] << ')');
				return false;
			}
		}
		break;

	default:
		return false;
	}

	// Move the possible unfinished message to the beginning of m_readBuf to free up more space for reading
	if (n > 0) {
		m_numRead -= n;
		if (m_numRead > 0) {
			memmove(m_readBuf, m_readBuf + n, m_numRead);
		}
	}

	if (m_socks5ProxyState == Socks5ProxyState::Default) {
		if (!on_connect()) {
			return false;
		}

		if (m_numRead > 0) {
			const uint32_t nread = m_numRead;
			m_numRead = 0;
			if (!on_read(m_readBuf, nread)) {
				return false;
			}
		}
	}

	return true;
}

void TCPServer::Client::on_write(uv_write_t* req, int status)
{
	WriteBuf* buf = static_cast<WriteBuf*>(req->data);
	Client* client = buf->m_client;
	TCPServer* server = client->m_owner;

	if (server) {
		server->return_write_buffer(buf);
	}

	if (status != 0) {
		LOGWARN(5, "client " << static_cast<const char*>(client->m_addrString) << " failed to write data to client connection, error " << uv_err_name(status));
		client->close();
	}
}

void TCPServer::Client::close()
{
	if (m_isClosing || !m_owner) {
		// Already closed
		return;
	}

	m_isClosing = true;

	uv_read_stop(reinterpret_cast<uv_stream_t*>(&m_socket));

	uv_tcp_t* s = &m_socket;
	uv_handle_t* h = reinterpret_cast<uv_handle_t*>(s);
	if (!uv_is_closing(h)) {
		uv_close(h, on_connection_close);
	}
}

void TCPServer::Client::ban(uint64_t seconds)
{
	if (m_addr.is_localhost()) {
		return;
	}

	if (m_owner) {
		LOGWARN(3, "peer " << static_cast<char*>(m_addrString) << " banned for " << seconds << " seconds");
		m_owner->ban(m_isV6, m_addr, seconds);
	}
}

void TCPServer::Client::init_addr_string()
{
	const char* addr_str;
	char addr_str_buf[64];

	if (m_isV6) {
		addr_str = inet_ntop(AF_INET6, m_addr.data, addr_str_buf, sizeof(addr_str_buf));
	}
	else {
		addr_str = inet_ntop(AF_INET, m_addr.data + 12, addr_str_buf, sizeof(addr_str_buf));
	}

	if (addr_str) {
		size_t n = strlen(addr_str);
		if (n > sizeof(m_addrString) - 16) {
			n = sizeof(m_addrString) - 16;
		}

		log::Stream s(m_addrString);
		if (m_isV6) {
			s << '[' << log::const_buf(addr_str, n) << "]:" << m_port << '\0';
		}
		else {
			s << log::const_buf(addr_str, n) << ':' << m_port << '\0';
		}
	}
}

} // namespace p2pool
