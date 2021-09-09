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

template<typename T> struct not_implemented { enum { value = 0 }; };

struct nocopy_nomove
{
	nocopy_nomove() = default;
	nocopy_nomove(const nocopy_nomove&) = delete;
	nocopy_nomove(nocopy_nomove&&) = delete;
	nocopy_nomove& operator=(const nocopy_nomove&) = delete;
	nocopy_nomove& operator=(nocopy_nomove&&) = delete;
};

template<typename T>
struct ScopeGuard
{
	explicit FORCEINLINE ScopeGuard(T&& handler) : m_handler(std::move(handler)) {}
	FORCEINLINE ~ScopeGuard() { m_handler(); }

	T m_handler;

	// Disable copying/moving of ScopeGuard objects

	// We can't declare copy constructor as explicitly deleted because of copy elision semantics
	// Just leave it without definition and it'll fail when linking if someone tries to copy a ScopeGuard object
	ScopeGuard(const ScopeGuard&);

private:
	ScopeGuard& operator=(const ScopeGuard&) = delete;
	ScopeGuard& operator=(ScopeGuard&&) = delete;
};

template<typename T> FORCEINLINE ScopeGuard<T> on_scope_leave(T&& handler) { return ScopeGuard<T>(std::move(handler)); }

#define ON_SCOPE_LEAVE(x) auto CONCAT(scope_guard_, __LINE__) = on_scope_leave(x);

struct MinerCallbackHandler
{
	virtual ~MinerCallbackHandler() = 0;

	virtual void handle_tx(TxMempoolData& tx) = 0;
	virtual void handle_miner_data(MinerData& data) = 0;
	virtual void handle_chain_main(ChainMain& data, const char* extra) = 0;
};

template<typename T>
static FORCEINLINE bool from_hex(char c, T& out_value) {
	if ('0' <= c && c <= '9') { out_value = static_cast<T>(c - '0'); return true; }
	if ('a' <= c && c <= 'f') { out_value = static_cast<T>((c - 'a') + 10); return true; }
	if ('A' <= c && c <= 'F') { out_value = static_cast<T>((c - 'A') + 10); return true; }
	return false;
}

template<typename T, bool is_signed> struct abs_helper {};
template<typename T> struct abs_helper<T, false> { static FORCEINLINE T value(T x) { return x; } };
template<typename T> struct abs_helper<T, true>  { static FORCEINLINE T value(T x) { return (x >= 0) ? x : -x; } };

template<typename T> FORCEINLINE T abs(T x) { return abs_helper<T, std::is_signed<T>::value>::value(x); }

template<typename T, typename U>
FORCEINLINE void writeVarint(T value, U&& callback)
{
	while (value >= 0x80) {
		callback(static_cast<uint8_t>((value & 0x7F) | 0x80));
		value >>= 7;
	}
	callback(static_cast<uint8_t>(value));
}

template<typename T>
FORCEINLINE void writeVarint(T value, std::vector<uint8_t>& out)
{
	writeVarint(value, [&out](uint8_t b) { out.emplace_back(b); });
}

template<typename T, size_t N> FORCEINLINE constexpr size_t array_size(T(&)[N]) { return N; }

[[noreturn]] void panic();

void make_thread_background();

class BackgroundJobTracker : public nocopy_nomove
{
public:
	BackgroundJobTracker();
	~BackgroundJobTracker();

	void start(const char* name);
	void stop(const char* name);
	void wait();
	void print_status();

private:
	struct Impl;
	Impl* m_impl;
};

extern BackgroundJobTracker bkg_jobs_tracker;
extern thread_local bool is_main_thread;

bool resolve_host(std::string& host, bool& is_v6);

} // namespace p2pool

namespace std {

template<>
struct hash<p2pool::hash>
{
	FORCEINLINE size_t operator()(const p2pool::hash& value) const
	{
		uint64_t result = 0xcbf29ce484222325ull;
		for (size_t i = 0; i < p2pool::HASH_SIZE; ++i) {
			result = (result ^ value.h[i]) * 0x100000001b3ull;
		}
		return static_cast<size_t>(result);
	}
};

} // namespace std
