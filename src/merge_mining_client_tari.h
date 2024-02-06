/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2024 SChernykh <https://github.com/SChernykh>
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

#include "tcp_server.h"

namespace p2pool {

class p2pool;

class MergeMiningClientTari : public IMergeMiningClient, public nocopy_nomove
{
public:
	MergeMiningClientTari(p2pool* pool, const std::string& host, const std::string& wallet);
	~MergeMiningClientTari();

	bool get_params(ChainParameters& out_params) const override;
	void submit_solution(const std::vector<uint8_t>& blob, const std::vector<hash>& merkle_proof) override;

	static constexpr char TARI_PREFIX[] = "tari://";

private:
	struct gRPC_Server : public TCPServer
	{
		explicit gRPC_Server(const std::string& socks5Proxy);
		~gRPC_Server();

		[[nodiscard]] bool start(bool use_dns, const std::string& host, int port);

		void on_shutdown() override;

		[[nodiscard]] const char* get_log_category() const override;

		std::string m_host;
		int m_port;
	} *m_server;

	struct gRPC_Client : public TCPServer::Client
	{
		gRPC_Client();
		~gRPC_Client() {}

		static Client* allocate() { return new gRPC_Client(); }
		virtual size_t size() const override { return sizeof(gRPC_Client); }

		void reset() override;
		[[nodiscard]] bool on_connect() override;
		[[nodiscard]] bool on_read(char* data, uint32_t size) override;
		void on_read_failed(int err) override;
		void on_disconnected() override;

		char m_buf[1024];
		std::vector<char> m_data;
	};

	std::string m_host;
	uint32_t m_port;

	mutable uv_rwlock_t m_lock;
	ChainParameters m_chainParams;

	std::string m_auxWallet;

	p2pool* m_pool;
};

} // namespace p2pool
