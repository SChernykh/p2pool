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
#include "util.h"
#include "uv_util.h"
#include <map>
#include <istream>
#include <ostream>

#if !defined(_WIN32) && defined(HAVE_SCHED)
#include <sched.h>
#endif

#ifdef WITH_UPNP
#include "miniupnpc.h"
#include "upnpcommands.h"
#endif

#ifdef _WIN32
#include <WinDNS.h>
#elif defined(HAVE_RES_QUERY)
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#endif

static constexpr char log_category_prefix[] = "Util ";

namespace p2pool {

const char* VERSION = "v" STR2(P2POOL_VERSION_MAJOR) "." STR2(P2POOL_VERSION_MINOR) " (built"
#if defined(__clang__)
	" with clang/" __clang_version__
#elif defined(__GNUC__)
	" with GCC/" STR2(__GNUC__) "." STR2(__GNUC_MINOR__) "." STR2(__GNUC_PATCHLEVEL__)
#elif defined(_MSC_VER)
	" with MSVC/" STR2(_MSC_VER)
#endif
" on " __DATE__ ")";

MinerCallbackHandler::~MinerCallbackHandler() {}

void panic_stop(const char* message)
{
	fprintf(stderr, "P2Pool can't continue execution: panic at %s\n", message);

	p2pool::log::stop();
	do {
#ifdef _WIN32
		if (IsDebuggerPresent()) {
			__debugbreak();
		}
#endif
		abort();
	} while (true);
}

void make_thread_background()
{
#ifdef _WIN32
	SetThreadPriorityBoost(GetCurrentThread(), true);
	SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN);
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_IDLE);
#elif defined(HAVE_SCHED)
	sched_param param;
	param.sched_priority = 0;
	if (sched_setscheduler(0, SCHED_IDLE, &param) != 0) {
		sched_setscheduler(0, SCHED_BATCH, &param);
	}
#endif
}

NOINLINE difficulty_type& difficulty_type::operator/=(difficulty_type b)
{
	if (*this < b) {
		lo = 0;
		hi = 0;
		return *this;
	}

	if (*this - b < b) {
		lo = 1;
		hi = 0;
		return *this;
	}

	if (b.hi == 0) {
		return operator/=(b.lo);
	}

	const uint64_t shift = bsr(b.hi) + 1;
	const uint64_t divisor = shiftleft128(b.lo, b.hi, 64 - shift);

	uint64_t t;
	if (hi < divisor) {
		uint64_t r;
		t = udiv128(hi, lo, divisor, &r) >> shift;
	}
	else {
		uint64_t r;
		t = shiftright128(udiv128(hi - divisor, lo, divisor, &r), 1, shift);
	}

	difficulty_type product;
	product.lo = umul128(b.lo, t, &product.hi);

	uint64_t t1, t2;
	t1 = umul128(b.hi, t, &t2);
	product.hi += t1;

	if (t2 || (product.hi < t1) || (*this < product)) {
		--t;
	}

	lo = t;
	hi = 0;

	return *this;
}

NOINLINE bool difficulty_type::check_pow(const hash& pow_hash) const
{
	const uint64_t* a = reinterpret_cast<const uint64_t*>(pow_hash.h);

	uint64_t result[6] = {};
	uint64_t product[6] = {};

	if (LIKELY(hi == 0)) {
		for (int i = 3; i >= 0; --i) {
			product[0] = umul128(a[i], lo, &product[1]);

			uint64_t carry = 0;
			for (int k = i, l = 0; k < 5; ++k, ++l) {
				uint64_t t = result[k] + product[l];
				const uint64_t next_carry = static_cast<uint64_t>(t < result[k]);
				t += carry;
				carry = next_carry | static_cast<uint64_t>(t < result[k]);
				result[k] = t;
			}

			if (result[4]) {
				return false;
			}
		}
	}
	else {
		const uint64_t* b = reinterpret_cast<const uint64_t*>(this);

		for (int i = 3; i >= 0; --i) {
			for (int j = 1; j >= 0; --j) {
				product[0] = umul128(a[i], b[j], &product[1]);

				uint64_t carry = 0;
				for (int k = i + j, l = 0; k < 6; ++k, ++l) {
					uint64_t t = result[k] + product[l];
					const uint64_t next_carry = static_cast<uint64_t>(t < result[k]);
					t += carry;
					carry = next_carry | static_cast<uint64_t>(t < result[k]);
					result[k] = t;
				}

				if (result[4] || result[5]) {
					return false;
				}
			}
		}
	}

	return true;
}

std::ostream& operator<<(std::ostream& s, const difficulty_type& d)
{
	char buf[log::Stream::BUF_SIZE + 1];
	log::Stream s1(buf);
	s1 << d << '\0';
	s << buf;
	return s;
}

std::istream& operator>>(std::istream& s, difficulty_type& diff)
{
	diff.lo = 0;
	diff.hi = 0;

	bool found_number = false;
	char c;
	while (s.good() && !s.eof()) {
		s.read(&c, 1);
		if (!s.good() || s.eof()) {
			break;
		}
		if ('0' <= c && c <= '9') {
			found_number = true;
			const uint32_t digit = static_cast<uint32_t>(c - '0');
			uint64_t hi;
			diff.lo = umul128(diff.lo, 10, &hi) + digit;
			if (diff.lo < digit) {
				++hi;
			}
			diff.hi = diff.hi * 10 + hi;
		}
		else if (found_number) {
			return s;
		}
	}
	return s;
}

std::ostream& operator<<(std::ostream& s, const hash& h)
{
	char buf[log::Stream::BUF_SIZE + 1];
	log::Stream s1(buf);
	s1 << h << '\0';
	s << buf;
	return s;
}

std::istream& operator>>(std::istream& s, hash& h)
{
	memset(h.h, 0, HASH_SIZE);

	bool found_number = false;
	uint32_t index = 0;
	char c;
	while (s.good() && !s.eof()) {
		s.read(&c, 1);
		if (!s.good() || s.eof()) {
			break;
		}
		uint8_t digit;
		if (from_hex(c, digit)) {
			found_number = true;
			h.h[index >> 1] = (h.h[index >> 1] << 4) | digit;
			++index;
			if (index >= HASH_SIZE * 2) {
				return s;
			}
		}
		else if (found_number) {
			return s;
		}
	}
	return s;
}

void uv_cond_init_checked(uv_cond_t* cond)
{
	const int result = uv_cond_init(cond);
	if (result) {
		LOGERR(1, "failed to create conditional variable, error " << uv_err_name(result));
		PANIC_STOP();
	}
}

void uv_mutex_init_checked(uv_mutex_t* mutex)
{
	const int result = uv_mutex_init(mutex);
	if (result) {
		LOGERR(1, "failed to create mutex, error " << uv_err_name(result));
		PANIC_STOP();
	}
}

void uv_rwlock_init_checked(uv_rwlock_t* lock)
{
	const int result = uv_rwlock_init(lock);
	if (result) {
		LOGERR(1, "failed to create rwlock, error " << uv_err_name(result));
		PANIC_STOP();
	}
}

void uv_async_init_checked(uv_loop_t* loop, uv_async_t* async, uv_async_cb async_cb)
{
	const int err = uv_async_init(loop, async, async_cb);
	if (err) {
		LOGERR(1, "uv_async_init failed, error " << uv_err_name(err));
		PANIC_STOP();
	}
}

uv_loop_t* uv_default_loop_checked()
{
	if (!is_main_thread()) {
		LOGERR(1, "uv_default_loop() can only be used by the main thread. Fix the code!");
#ifdef _WIN32
		if (IsDebuggerPresent()) {
			__debugbreak();
		}
#endif
	}
	return uv_default_loop();
}

struct BackgroundJobTracker::Impl
{
	Impl() { uv_mutex_init_checked(&m_lock); }
	~Impl() { uv_mutex_destroy(&m_lock); }

	void start(const char* name)
	{
		MutexLock lock(m_lock);

		auto it = m_jobs.insert({ name, 1 });
		if (!it.second) {
			++it.first->second;
		}
	}

	void stop(const char* name)
	{
		MutexLock lock(m_lock);

		auto it = m_jobs.find(name);
		if (it == m_jobs.end()) {
			LOGWARN(1, "background job " << name << " is not running, but stop() was called");
			return;
		}

		--it->second;
		if (it->second <= 0) {
			m_jobs.erase(it);
		}
	}

	void wait()
	{
		uint64_t last_msg_time = 0;
		do {
			{
				MutexLock lock(m_lock);
				// cppcheck-suppress knownConditionTrueFalse
				if (m_jobs.empty()) {
					return;
				}
				const uint64_t t = seconds_since_epoch();
				if (t != last_msg_time) {
					last_msg_time = t;
					for (const auto& job : m_jobs) {
						LOGINFO(1, "waiting for " << job.second << " \"" << job.first << "\" jobs to finish");
					}
				}
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
		} while (1);
	}

	void print_status()
	{
		MutexLock lock(m_lock);

		if (m_jobs.empty()) {
			LOGINFO(0, "no background jobs running");
			return;
		}

		char buf[log::Stream::BUF_SIZE + 1];
		log::Stream s(buf);
		for (const auto& job : m_jobs) {
			s << '\n' << job.first << " (" << job.second << ')';
		}

		LOGINFO(0, "background jobs running:" << log::const_buf(buf, s.m_pos));
	}

	struct Compare { FORCEINLINE bool operator()(const char* a, const char* b) const { return strcmp(a, b) < 0; } };

	uv_mutex_t m_lock;
	std::map<const char*, int32_t, Compare> m_jobs;
};

BackgroundJobTracker::BackgroundJobTracker() : m_impl(new Impl())
{
}

BackgroundJobTracker::~BackgroundJobTracker()
{
	delete m_impl;
}

void BackgroundJobTracker::start_internal(const char* name)
{
	m_impl->start(name);
}

void BackgroundJobTracker::stop_internal(const char* name)
{
	m_impl->stop(name);
}

void BackgroundJobTracker::wait()
{
	m_impl->wait();
}

void BackgroundJobTracker::print_status()
{
	m_impl->print_status();
}

BackgroundJobTracker bkg_jobs_tracker;

static thread_local bool main_thread = false;
void set_main_thread() { main_thread = true; }
bool is_main_thread() { return main_thread; }

bool disable_resolve_host = false;

bool resolve_host(std::string& host, bool& is_v6)
{
	if (disable_resolve_host) {
		LOGERR(1, "resolve_host was called with DNS disabled for host " << host);
		return false;
	}

	addrinfo hints{};
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_ADDRCONFIG;

	addrinfo* r = nullptr;
	int err = getaddrinfo(host.c_str(), nullptr, &hints, &r);
	if (err) {
		LOGWARN(4, "getaddrinfo failed for " << host << ": " << gai_strerror(err) << ", retrying with IPv4 only");
		hints.ai_family = AF_INET;
		err = getaddrinfo(host.c_str(), nullptr, &hints, &r);
	}
	if ((err == 0) && r) {
		const char* addr_str = nullptr;
		char addr_str_buf[64];

		void* addr;
		if (r->ai_family == AF_INET6) {
			addr = &reinterpret_cast<sockaddr_in6*>(r->ai_addr)->sin6_addr;
			is_v6 = true;
		}
		else {
			addr = &reinterpret_cast<sockaddr_in*>(r->ai_addr)->sin_addr;
			is_v6 = false;
		}

		addr_str = inet_ntop(r->ai_family, addr, addr_str_buf, sizeof(addr_str_buf));
		if (addr_str) {
			LOGINFO(5, log::LightCyan() << host << log::NoColor() << " resolved to " << log::Gray() << addr_str);
			host = addr_str;
		}
		freeaddrinfo(r);
	}
	else {
		LOGWARN(3, "getaddrinfo failed for " << host << ": " << gai_strerror(err));
		return false;
	}

	return true;
}

bool get_dns_txt_records_base(const std::string& host, Callback<void, const char*, size_t>::Base&& callback)
{
	if (disable_resolve_host) {
		LOGERR(1, "get_dns_txt_records was called with DNS disabled for host " << host);
		return false;
	}

#ifdef _WIN32
	PDNS_RECORD pQueryResults;
	if (DnsQuery(host.c_str(), DNS_TYPE_TEXT, DNS_QUERY_STANDARD, NULL, &pQueryResults, NULL) != 0) {
		return false;
	}

	for (PDNS_RECORD p = pQueryResults; p; p = p->pNext) {
		for (size_t j = 0; j < p->Data.TXT.dwStringCount; ++j) {
			const char* s = p->Data.TXT.pStringArray[j];
			const size_t n = strlen(s);
			if (n > 0) {
				callback(s, n);
			}
		}
	}

	DnsRecordListFree(pQueryResults, DnsFreeRecordList);

	return true;
#elif defined(HAVE_RES_QUERY)
	static const int res_init_result = res_init();
	if (res_init_result != 0) {
		return false;
	}

	uint8_t answer[4096] = {};
	const int anslen = res_query(host.c_str(), ns_c_in, ns_t_txt, answer, sizeof(answer));
	if ((anslen <= 0) || (anslen > static_cast<int>(sizeof(answer)))) {
		return false;
	}

	ns_msg handle{};
	if (ns_initparse(answer, anslen, &handle) != 0) {
		return false;
	}

	for (int rrnum = 0, n = ns_msg_count(handle, ns_s_an); rrnum < n; ++rrnum) {
		ns_rr rr{};
		if ((ns_parserr(&handle, ns_s_an, rrnum, &rr) == 0) && (ns_rr_type(rr) == ns_t_txt)) {
			for (const uint8_t* data = ns_rr_rdata(rr), *e = data + ns_rr_rdlen(rr); data < e;) {
				const size_t k = *(data++);
				if (k && (data + k <= e)) {
					callback(reinterpret_cast<const char*>(data), k);
				}
				data += k;
			}
		}
	}

	return true;
#else
	(void)host;
	(void)callback;

	return false;
#endif
}

RandomDeviceSeed RandomDeviceSeed::instance;

struct BSR8
{
	uint8_t data[256];

	static constexpr BSR8 init() {
		BSR8 result = { 55 };

		for (int i = 1; i < 256; ++i) {
			int x = i;
			result.data[i] = 63;
			while (x < 0x80) {
				--result.data[i];
				x <<= 1;
			}
		}

		return result;
	}
};

static constexpr BSR8 bsr8_table = BSR8::init();

NOINLINE uint64_t bsr_reference(uint64_t x)
{
	uint32_t y = static_cast<uint32_t>(x);

	uint64_t n0 = (x == y) ? 0 : 32;
	y = static_cast<uint32_t>(x >> n0);
	n0 ^= 32;

	const uint64_t n1 = (y & 0xFFFF0000UL) ? 0 : 16;
	y <<= n1;

	const uint64_t n2 = (y & 0xFF000000UL) ? 0 : 8;
	y <<= n2;

	return bsr8_table.data[y >> 24] - n0 - n1 - n2;
}

bool str_to_ip(bool is_v6, const char* ip, raw_ip& result)
{
	sockaddr_storage addr;

	if (is_v6) {
		sockaddr_in6* addr6 = reinterpret_cast<sockaddr_in6*>(&addr);
		const int err = uv_ip6_addr(ip, 0, addr6);
		if (err) {
			LOGERR(1, "failed to parse IPv6 address " << ip << ", error " << uv_err_name(err));
			return false;
		}
		memcpy(result.data, &addr6->sin6_addr, sizeof(in6_addr));
	}
	else {
		sockaddr_in* addr4 = reinterpret_cast<sockaddr_in*>(&addr);
		const int err = uv_ip4_addr(ip, 0, addr4);
		if (err) {
			LOGERR(1, "failed to parse IPv4 address " << ip << ", error " << uv_err_name(err));
			return false;
		}
		result = {};
		result.data[10] = 0xFF;
		result.data[11] = 0xFF;
		memcpy(result.data + 12, &addr4->sin_addr, sizeof(in_addr));
	}

	return true;
}

bool is_localhost(const std::string& host)
{
	if (host.empty()) {
		return false;
	}

	if (host.compare("localhost") == 0) {
		return true;
	}

	if (host.find_first_not_of("0123456789.:") != std::string::npos) {
		return false;
	}

	raw_ip addr;
	if (!str_to_ip(host.find(':') != std::string::npos, host.c_str(), addr)) {
		return false;
	}

	return addr.is_localhost();
}

UV_LoopUserData* GetLoopUserData(uv_loop_t* loop, bool create)
{
	UV_LoopUserData* data = reinterpret_cast<UV_LoopUserData*>(loop->data);

	if (!data && create) {
		data = new UV_LoopUserData(loop);
		loop->data = data;
	}

	return data;
}

#ifdef WITH_UPNP
static struct UPnP_Discover
{
	uv_mutex_t lock;
	int error;
	UPNPDev* devlist;
} upnp_discover;

void init_upnp()
{
	uv_mutex_init_checked(&upnp_discover.lock);

	uv_work_t* req = new uv_work_t{};

	const int err = uv_queue_work(uv_default_loop_checked(), req,
		[](uv_work_t* /*req*/)
		{
			BACKGROUND_JOB_START(init_upnp);
			LOGINFO(1, "UPnP: Started scanning for UPnP IGD devices");
			{
				MutexLock lock(upnp_discover.lock);
				upnp_discover.devlist = upnpDiscover(1000, nullptr, nullptr, UPNP_LOCAL_PORT_ANY, 0, 2, &upnp_discover.error);
			}
			LOGINFO(1, "UPnP: Finished scanning for UPnP IGD devices");
		},
		[](uv_work_t* req, int /*status*/)
		{
			delete req;
			BACKGROUND_JOB_STOP(init_upnp);
		}
	);

	if (err) {
		LOGERR(0, "init_upnp: uv_queue_work failed, error " << uv_err_name(err));
		delete req;
	}
}

void destroy_upnp()
{
	{
		MutexLock lock(upnp_discover.lock);

		freeUPNPDevlist(upnp_discover.devlist);
		upnp_discover.devlist = nullptr;
	}
	uv_mutex_destroy(&upnp_discover.lock);
}

int add_portmapping(int external_port, int internal_port)
{
	LOGINFO(1, "UPnP: trying to map WAN:" << external_port << " to LAN:" << internal_port);

	MutexLock lock(upnp_discover.lock);

	if (!upnp_discover.devlist) {
		LOGWARN(1, "upnpDiscover: no UPnP IGD devices found, error " << upnp_discover.error);
		return 0;
	}

	UPNPUrls urls;
	IGDdatas data;
	char local_addr[64] = {};

	int result = UPNP_GetValidIGD(upnp_discover.devlist, &urls, &data, local_addr, sizeof(local_addr));
	if (result != 1) {
		LOGWARN(1, "UPNP_GetValidIGD returned " << result << ", no valid UPnP IGD devices found");
		return 0;
	}

	LOGINFO(1, "UPnP: LAN IP address " << log::Gray() << static_cast<const char*>(local_addr));

	char ext_addr[64] = {};
	result = UPNP_GetExternalIPAddress(urls.controlURL, data.first.servicetype, ext_addr);
	if ((result != UPNPCOMMAND_SUCCESS) || !ext_addr[0]) {
		LOGWARN(1, "UPNP_GetExternalIPAddress: failed to query external IP address, error " << result);
	}
	else {
		LOGINFO(1, "UPnP: WAN IP address " << log::Gray() << static_cast<const char*>(ext_addr));
	}

	const std::string eport = std::to_string(external_port);
	const std::string iport = std::to_string(internal_port);

	result = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype, eport.c_str(), iport.c_str(), local_addr, "P2Pool", "TCP", nullptr, nullptr);

	// ConflictInMappingEntry: try to delete the old record and then add the new one again
	if (result == 718) {
		LOGWARN(1, "UPNP_AddPortMapping failed: ConflictInMappingEntry");

		result = UPNP_DeletePortMapping(urls.controlURL, data.first.servicetype, eport.c_str(), "TCP", nullptr);
		if (result) {
			LOGWARN(1, "UPNP_DeletePortMapping returned error " << result);
			return 0;
		}
		else {
			LOGINFO(1, "UPnP: Deleted mapping for external port " << external_port);
			result = UPNP_AddPortMapping(urls.controlURL, data.first.servicetype, eport.c_str(), iport.c_str(), local_addr, "P2Pool", "TCP", nullptr, nullptr);
		}
	}

	if (result) {
		LOGWARN(1, "UPNP_AddPortMapping returned error " << result);
		return 0;
	}

	LOGINFO(1, "UPnP: Mapped " << log::Gray() << static_cast<const char*>(ext_addr) << ':' << external_port << log::NoColor() << " to " << log::Gray() << static_cast<const char*>(local_addr) << ':' << internal_port);
	return external_port;
}

void remove_portmapping(int external_port)
{
	LOGINFO(1, "UPnP: trying to delete mapping for external port " << external_port);

	MutexLock lock(upnp_discover.lock);

	if (!upnp_discover.devlist) {
		LOGWARN(1, "upnpDiscover: no UPnP IGD devices found, error " << upnp_discover.error);
		return;
	}

	UPNPUrls urls;
	IGDdatas data;
	char local_addr[64] = {};

	int result = UPNP_GetValidIGD(upnp_discover.devlist, &urls, &data, local_addr, sizeof(local_addr));
	if (result != 1) {
		LOGWARN(1, "UPNP_GetValidIGD returned " << result << ", no valid UPnP IGD devices found");
		return;
	}

	const std::string eport = std::to_string(external_port);
	result = UPNP_DeletePortMapping(urls.controlURL, data.first.servicetype, eport.c_str(), "TCP", nullptr);
	if (result) {
		LOGWARN(1, "UPNP_DeletePortMapping returned error " << result);
	}
	else {
		LOGINFO(1, "UPnP: Deleted mapping for external port " << external_port);
	}
}
#endif

NOINLINE PerfTimer::~PerfTimer()
{
	using namespace std::chrono;
	const duration<double, std::milli> dt = high_resolution_clock::now() - m_start;
	LOGINFO(m_level, m_name << " took " << dt.count() << " ms");
}

} // namespace p2pool
