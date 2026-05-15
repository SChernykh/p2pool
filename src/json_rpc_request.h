/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2026 SChernykh <https://github.com/SChernykh>
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
namespace JSONRPCRequest {

struct CallbackData
{
	std::vector<char> m_response{};
	std::string m_error{};

	double m_ping = 0.0;

#ifdef WITH_TLS
	std::string m_spkiFingerprint{};
#endif
};

typedef Callback<void, const CallbackData& /*data*/>::Base CallbackBase;

FORCEINLINE static constexpr void dummy_callback(const CallbackData& /*data*/) {}

void Call(const std::string& address, int port, const std::string& req, const std::string& auth, const std::string& proxy, bool ssl, const std::string& ssl_fingerprint, CallbackBase* cb, CallbackBase* close_cb, uv_loop_t* loop);

template<typename T, typename U>
FORCEINLINE void call(const std::string& address, int port, const std::string& req, const std::string& auth, const std::string& proxy, bool ssl, const std::string& ssl_fingerprint, T&& cb, U&& close_cb, uv_loop_t* loop = nullptr)
{
	typedef Callback<void, const CallbackData&>::Derived<T> CallbackT;
	typedef Callback<void, const CallbackData&>::Derived<U> CallbackU;

	Call(address, port, req, auth, proxy, ssl, ssl_fingerprint, new CallbackT(std::forward<T>(cb)), new CallbackU(std::forward<U>(close_cb)), loop);
}

} // namespace JSONRPCRequest
} // namespace p2pool
