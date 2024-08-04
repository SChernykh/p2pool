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

#include <openssl/base.h>

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
#endif

#include <openssl/ssl.h>

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

namespace p2pool {

class ServerTls
{
public:
	FORCEINLINE ServerTls() { reset(); }

	void reset();
	[[nodiscard]] bool init();

	template<typename T, typename U>
	[[nodiscard]] FORCEINLINE bool on_read(char* data, uint32_t size, T&& read_callback, U&& write_callback)
	{
		return on_read_internal(data, size, ReadCallback::Derived<T>(std::move(read_callback)), WriteCallback::Derived<U>(std::move(write_callback)));
	}

	template<typename T>
	[[nodiscard]] FORCEINLINE bool on_write(const uint8_t* data, size_t size, T&& write_callback)
	{
		return on_write_internal(data, size, WriteCallback::Derived<T>(std::move(write_callback)));
	}

	[[nodiscard]] FORCEINLINE bool is_empty() const { return m_ssl.get() == nullptr; }

private:
	typedef Callback<bool, char*, uint32_t> ReadCallback;
	typedef Callback<bool, const uint8_t*, size_t> WriteCallback;

	[[nodiscard]] bool on_read_internal(char* data, uint32_t size, ReadCallback::Base&& read_callback, WriteCallback::Base&& write_callback);
	[[nodiscard]] bool on_write_internal(const uint8_t* data, size_t size, WriteCallback::Base&& write_callback);

private:
	bssl::UniquePtr<SSL> m_ssl;
};

} // namespace p2pool
