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

namespace p2pool {
namespace JSONRPCRequest {

typedef Callback<void, const char*, size_t, double>::Base CallbackBase;

void Call(const std::string& address, int port, const std::string& req, const std::string& auth, const std::string& proxy, CallbackBase* cb, CallbackBase* close_cb, uv_loop_t* loop);

template<typename T, typename U>
FORCEINLINE void call(const std::string& address, int port, const std::string& req, const std::string& auth, const std::string& proxy, T&& cb, U&& close_cb, uv_loop_t* loop = nullptr)
{
	typedef Callback<void, const char*, size_t, double>::Derived<T> CallbackT;
	typedef Callback<void, const char*, size_t, double>::Derived<U> CallbackU;

	Call(address, port, req, auth, proxy, new CallbackT(std::move(cb)), new CallbackU(std::move(close_cb)), loop);
}

} // namespace JSONRPCRequest
} // namespace p2pool
