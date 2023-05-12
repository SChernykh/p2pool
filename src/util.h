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

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4623 5026 5027)
#endif

#define ROBIN_HOOD_MALLOC(size) p2pool::malloc_hook(size)
#define ROBIN_HOOD_CALLOC(count, size) p2pool::calloc_hook((count), (size))
#define ROBIN_HOOD_FREE(ptr) p2pool::free_hook(ptr)

#include "robin_hood.h"

#ifdef _MSC_VER
#pragma warning(pop)
#endif

namespace p2pool {

#define P2POOL_VERSION_MAJOR 3
#define P2POOL_VERSION_MINOR 3

extern const char* VERSION;

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

#define ON_SCOPE_LEAVE(...) auto CONCAT(scope_guard_, __LINE__) = on_scope_leave(__VA_ARGS__);

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

template<typename T>
const uint8_t* readVarint(const uint8_t* data, const uint8_t* data_end, T& b)
{
	uint64_t result = 0;
	int k = 0;

	while (data < data_end) {
		if (k >= static_cast<int>(sizeof(T)) * 8) {
			return nullptr;
		}

		const uint64_t cur_byte = *(data++);
		result |= (cur_byte & 0x7F) << k;
		k += 7;

		if ((cur_byte & 0x80) == 0) {
			b = result;
			return data;
		}
	}

	return nullptr;
}

template<typename T>
FORCEINLINE T read_unaligned(const T* p)
{
	static_assert(std::is_trivially_copyable<T>::value, "T must be a trivially copyable type");

	T result;
	memcpy(&result, p, sizeof(T));
	return result;
}

template<typename T, size_t N> FORCEINLINE constexpr size_t array_size(T(&)[N]) { return N; }
template<typename T, typename U, size_t N> FORCEINLINE constexpr size_t array_size(T(U::*)[N]) { return N; }

[[noreturn]] void panic_stop(const char* message);

#define STR(X) #X
#define STR2(X) STR(X)

#define PANIC_STOP(...) panic_stop(__FILE__ ":" STR2(__LINE__))

void make_thread_background();

class BackgroundJobTracker : public nocopy_nomove
{
public:
	BackgroundJobTracker();
	~BackgroundJobTracker();

	template<size_t N> FORCEINLINE void start(const char (&name)[N]) { start_internal(name); }
	template<size_t N> FORCEINLINE void stop (const char (&name)[N]) { stop_internal (name); }

	void wait();
	void print_status();

private:
	void start_internal(const char* name);
	void stop_internal(const char* name);

	struct Impl;
	Impl* m_impl;
};

extern BackgroundJobTracker bkg_jobs_tracker;

#define BACKGROUND_JOB_START(x) do { bkg_jobs_tracker.start(#x); } while (0)
#define BACKGROUND_JOB_STOP(x)  do { bkg_jobs_tracker.stop(#x);  } while (0)

void set_main_thread();
bool is_main_thread();

extern bool disable_resolve_host;
bool resolve_host(std::string& host, bool& is_v6);

template <typename Key, typename T>
using unordered_map = robin_hood::detail::Table<false, 80, Key, T, robin_hood::hash<Key>, std::equal_to<Key>>;

template <typename Key>
using unordered_set = robin_hood::detail::Table<false, 80, Key, void, robin_hood::hash<Key>, std::equal_to<Key>>;

// Fills the whole initial MT19937-64 state with non-deterministic random numbers
struct RandomDeviceSeed
{
	using result_type = std::random_device::result_type;
	static_assert(sizeof(result_type) >= 4, "result_type must have at least 32 bits");

	template<typename T>
	static void generate(T begin, T end)
	{
		std::random_device rd;
		for (T i = begin; i != end; ++i) {
			*i = rd();
		}
	}

	static RandomDeviceSeed instance;
};

FORCEINLINE uint64_t xorshift64star(uint64_t x)
{
	x ^= x >> 12;
	x ^= x << 25;
	x ^= x >> 27;
	return x * 0x2545F4914F6CDD1DULL;
}

FORCEINLINE uint64_t seconds_since_epoch()
{
	using namespace std::chrono;
	return duration_cast<seconds>(steady_clock::now().time_since_epoch()).count();
}

FORCEINLINE uint64_t microseconds_since_epoch()
{
	using namespace std::chrono;
	return duration_cast<microseconds>(steady_clock::now().time_since_epoch()).count();
}

uint64_t bsr_reference(uint64_t x);

#ifdef HAVE_BUILTIN_CLZLL
#define bsr(x) (63 - __builtin_clzll(x))
#elif defined HAVE_BITSCANREVERSE64
#pragma intrinsic(_BitScanReverse64)
FORCEINLINE uint64_t bsr(uint64_t x)
{
	unsigned long index;
	_BitScanReverse64(&index, x);
	return index;
}
#else
#define bsr bsr_reference
#endif

bool str_to_ip(bool is_v6, const char* ip, raw_ip& result);
bool is_localhost(const std::string& host);

#ifdef WITH_UPNP
void init_upnp();
void destroy_upnp();
int add_portmapping(int external_port, int internal_port);
void remove_portmapping(int external_port);
#endif

struct PerfTimer
{
	FORCEINLINE PerfTimer(int level, const char* name) : m_level(level), m_name(name), m_start(std::chrono::high_resolution_clock::now()) {}
	~PerfTimer();

	int m_level;
	const char* m_name;
	std::chrono::time_point<std::chrono::high_resolution_clock> m_start;
};

#ifdef P2POOL_LOG_DISABLE
#define PERFLOG(level, name)
#else
#define PERFLOG(level, name) PerfTimer CONCAT(perf_timer_, __LINE__)(level, name)
#endif

template<typename R, typename ...Args>
struct Callback
{
	struct Base
	{
		virtual ~Base() {}
		virtual R operator()(Args...) = 0;
	};

	template<typename T>
	struct Derived : public Base
	{
		explicit FORCEINLINE Derived(T&& cb) : m_cb(std::move(cb)) {}
		R operator()(Args... args) override { return m_cb(args...); }

	private:
		Derived& operator=(Derived&&) = delete;
		T m_cb;
	};
};

bool get_dns_txt_records_base(const std::string& host, Callback<void, const char*, size_t>::Base&& callback);

template<typename T>
FORCEINLINE bool get_dns_txt_records(const std::string& host, T&& callback) { return get_dns_txt_records_base(host, Callback<void, const char*, size_t>::Derived<T>(std::move(callback))); }

} // namespace p2pool

void memory_tracking_start();
void memory_tracking_stop();
void p2pool_usage();
void p2pool_version();

namespace robin_hood {

template<>
struct hash<p2pool::hash>
{
	FORCEINLINE size_t operator()(const p2pool::hash& value) const noexcept
	{
		return hash_bytes(value.h, p2pool::HASH_SIZE);
	}
};

template<size_t N>
struct hash<std::array<uint8_t, N>>
{
	FORCEINLINE size_t operator()(const std::array<uint8_t, N>& value) const noexcept
	{
		return hash_bytes(value.data(), N);
	}
};

template<>
struct hash<p2pool::raw_ip>
{
	FORCEINLINE size_t operator()(const p2pool::raw_ip& value) const noexcept
	{
		return hash_bytes(value.data, sizeof(value.data));
	}
};

template<>
struct hash<std::pair<uint64_t, uint64_t>>
{
	FORCEINLINE size_t operator()(const std::pair<uint64_t, uint64_t>& value) const noexcept
	{
		static_assert(sizeof(value) == sizeof(uint64_t) * 2, "Invalid std::pair<uint64_t, uint64_t> size");
		return hash_bytes(&value, sizeof(value));
	}
};

} // namespace robin_hood
