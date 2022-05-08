/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2022 SChernykh <https://github.com/SChernykh>
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

namespace log {

extern int GLOBAL_LOG_LEVEL;
extern bool CONSOLE_COLORS;
constexpr int MAX_GLOBAL_LOG_LEVEL = 6;

enum class Severity {
	Info,
	Warning,
	Error,
};

struct Stream
{
	enum params : int { BUF_SIZE = 1024 - 1 };

	template<size_t N>
	explicit FORCEINLINE Stream(char (&buf)[N]) : m_pos(0), m_numberWidth(1), m_buf(buf), m_bufSize(N - 1) {}

	FORCEINLINE Stream(void* buf, size_t size) : m_pos(0), m_numberWidth(1), m_buf(reinterpret_cast<char*>(buf)), m_bufSize(static_cast<int>(size) - 1) {}

	template<typename T>
	struct Entry
	{
		static constexpr void no() { static_assert(not_implemented<T>::value, "Logging for this type is not implemented"); }

		static constexpr void put(const T&, Stream*) { no(); }
		static constexpr void put(T&&, Stream*) { no(); }
	};

	template<typename T>
	FORCEINLINE Stream& operator<<(T& data)
	{
		Entry<typename std::remove_cv<T>::type>::put(data, this);
		return *this;
	}

	template<typename T>
	FORCEINLINE Stream& operator<<(T&& data)
	{
		Entry<T>::put(std::move(data), this);
		return *this;
	}

	template<typename T, int base = 10>
	NOINLINE void writeInt(T data)
	{
		static_assert(1 < base && base <= 64, "Invalid base");

		const T data_with_sign = data;
		data = abs(data);
		const bool negative = (data != data_with_sign);

		char buf[32];
		size_t k = sizeof(buf);
		int w = m_numberWidth;

		do {
			buf[--k] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/"[data % base];
			data /= base;
			--w;
		} while ((data > 0) || (w > 0));

		if (negative) {
			buf[--k] = '-';
		}

		writeBuf(buf + k, sizeof(buf) - k);
	}

	FORCEINLINE void writeBuf(const char* buf, size_t n0)
	{
		const int n = static_cast<int>(n0);
		const int pos = m_pos;
		if (pos + n > m_bufSize) {
			return;
		}
		memcpy(m_buf + pos, buf, n);
		m_pos = pos + n;
	}

	FORCEINLINE int getNumberWidth() const { return m_numberWidth; }
	FORCEINLINE void setNumberWidth(int width) { m_numberWidth = width; }

	NOINLINE void writeCurrentTime();

	int m_pos;
	int m_numberWidth;
	char* m_buf;
	int m_bufSize;
};

struct Writer : public Stream
{
	explicit NOINLINE Writer(Severity severity);
	NOINLINE ~Writer();

	char m_stackBuf[BUF_SIZE + 1];
};

#define COLOR_ENTRY(x, s) \
struct x{}; \
template<> struct Stream::Entry<x> { static FORCEINLINE void put(x&&, Stream* wrapper) { wrapper->writeBuf(s, sizeof(s) - 1); } };

COLOR_ENTRY(NoColor,      "\x1b[0m")
COLOR_ENTRY(Black,        "\x1b[0;30m")
COLOR_ENTRY(Red,          "\x1b[0;31m")
COLOR_ENTRY(Green,        "\x1b[0;32m")
COLOR_ENTRY(Yellow,       "\x1b[0;33m")
COLOR_ENTRY(Blue,         "\x1b[0;34m")
COLOR_ENTRY(Magenta,      "\x1b[0;35m")
COLOR_ENTRY(Cyan,         "\x1b[0;36m")
COLOR_ENTRY(White,        "\x1b[0;37m")
COLOR_ENTRY(Gray,         "\x1b[0;90m")
COLOR_ENTRY(LightRed,     "\x1b[0;91m")
COLOR_ENTRY(LightGreen,   "\x1b[0;92m")
COLOR_ENTRY(LightYellow,  "\x1b[0;93m")
COLOR_ENTRY(LightBlue,    "\x1b[0;94m")
COLOR_ENTRY(LightMagenta, "\x1b[0;95m")
COLOR_ENTRY(LightCyan,    "\x1b[0;96m")

#undef COLOR_ENTRY

template<size_t N> struct Stream::Entry<char[N]>
{
	static FORCEINLINE void put(const char (&data)[N], Stream* wrapper) { wrapper->writeBuf(data, N - 1); }
};

template<> struct Stream::Entry<const char*>
{
	static FORCEINLINE void put(const char* data, Stream* wrapper) { wrapper->writeBuf(data, strlen(data)); }
};

template<> struct Stream::Entry<char*>
{
	static FORCEINLINE void put(char* data, Stream* wrapper) { wrapper->writeBuf(data, strlen(data)); }
};

template<> struct Stream::Entry<char>
{
	static FORCEINLINE void put(char c, Stream* wrapper) { wrapper->writeBuf(&c, 1); }
};

#define INT_ENTRY(x) \
template<> struct Stream::Entry<x> { static FORCEINLINE void put(x data, Stream* wrapper) { wrapper->writeInt(data); } };

INT_ENTRY(int8_t)
INT_ENTRY(int16_t)
INT_ENTRY(int32_t)
INT_ENTRY(int64_t)
INT_ENTRY(uint8_t)
INT_ENTRY(uint16_t)
INT_ENTRY(uint32_t)
INT_ENTRY(uint64_t)

#ifdef __APPLE__
INT_ENTRY(long)
INT_ENTRY(unsigned long)
#endif

#undef INT_ENTRY

template<typename T, int base>
struct BasedValue
{
	explicit FORCEINLINE BasedValue(T value) : m_value(value)
	{
		static_assert(std::is_integral<T>::value, "Must be an integer type here");
	}

	T m_value;
};

template<typename T, int base>
struct Stream::Entry<BasedValue<T, base>>
{
	static FORCEINLINE void put(BasedValue<T, base> data, Stream* wrapper)
	{
		wrapper->writeInt<T, base>(data.m_value);
	}
};

template<typename T> FORCEINLINE BasedValue<T, 16> Hex(T value) { return BasedValue<T, 16>(value); }

template<> struct Stream::Entry<double>
{
	static NOINLINE void put(double x, Stream* wrapper)
	{
		char buf[16];
		int n = snprintf(buf, sizeof(buf), "%.3f", x);
		if (n > 0) {
			if (n > static_cast<int>(sizeof(buf)) - 1) {
				n = static_cast<int>(sizeof(buf)) - 1;
			}
			wrapper->writeBuf(buf, n);
		}
	}
};

template<> struct Stream::Entry<float>
{
	static FORCEINLINE void put(float x, Stream* wrapper) { Stream::Entry<double>::put(x, wrapper); }
};

template<> struct Stream::Entry<hash>
{
	static NOINLINE void put(const hash& data, Stream* wrapper)
	{
		char buf[sizeof(data) * 2];
		for (size_t i = 0; i < sizeof(data.h); ++i) {
			buf[i * 2 + 0] = "0123456789abcdef"[data.h[i] >> 4];
			buf[i * 2 + 1] = "0123456789abcdef"[data.h[i] & 15];
		}
		wrapper->writeBuf(buf, sizeof(buf));
	}
};

template<> struct Stream::Entry<difficulty_type>
{
	static NOINLINE void put(const difficulty_type& data, Stream* wrapper)
	{
		char buf[40];
		size_t k = sizeof(buf);
		int w = wrapper->m_numberWidth;

		uint64_t a = data.lo;
		uint64_t b = data.hi;

		do {
			// 2^64 % 10 = 6, so (b % 10) is multiplied by 6
			static constexpr uint64_t mul6[10] = { 0, 6, 2, 8, 4, 0, 6, 2, 8, 4 };

			buf[--k] = "01234567890123456789"[a % 10 + mul6[b % 10]];

			uint64_t r;
			a = udiv128(b % 10, a, 10, &r);
			b /= 10;

			--w;
		} while ((a > 0) || (b > 0) || (w > 0));

		wrapper->writeBuf(buf + k, sizeof(buf) - k);
	}
};

struct const_buf
{
	FORCEINLINE const_buf(const char* data, size_t size) : m_data(data), m_size(size) {}

	const char* m_data;
	size_t m_size;
};

template<> struct log::Stream::Entry<const_buf>
{
	static FORCEINLINE void put(const_buf&& buf, Stream* wrapper) { wrapper->writeBuf(buf.m_data, buf.m_size); }
};

struct hex_buf
{
	FORCEINLINE hex_buf(const uint8_t* data, size_t size) : m_data(data), m_size(size) {}

	const uint8_t* m_data;
	size_t m_size;
};

template<> struct log::Stream::Entry<hex_buf>
{
	static FORCEINLINE void put(const hex_buf& value, Stream* wrapper)
	{
		for (size_t i = 0; i < value.m_size; ++i) {
			char buf[2];
			buf[0] = "0123456789abcdef"[value.m_data[i] >> 4];
			buf[1] = "0123456789abcdef"[value.m_data[i] & 15];
			wrapper->writeBuf(buf, sizeof(buf));
		}
	}
};

template<> struct log::Stream::Entry<std::string>
{
	static FORCEINLINE void put(const std::string& value, Stream* wrapper) { wrapper->writeBuf(value.c_str(), value.length()); }
};

struct Hashrate
{
	FORCEINLINE Hashrate() : m_data(0), m_valid(false) {}
	explicit FORCEINLINE Hashrate(uint64_t data) : m_data(data), m_valid(true) {}
	FORCEINLINE Hashrate(uint64_t data, bool valid) : m_data(data), m_valid(valid) {}

	uint64_t m_data;
	bool m_valid;
};

template<> struct log::Stream::Entry<Hashrate>
{
	static NOINLINE void put(const Hashrate& value, Stream* wrapper)
	{
		if (!value.m_valid) {
			return;
		}

		const double x = static_cast<double>(value.m_data);

		static constexpr const char* units[] = { "H/s", "KH/s", "MH/s", "GH/s", "TH/s", "PH/s", "EH/s" };

		int n;
		char buf[32];
		if (value.m_data < 1000) {
			n = snprintf(buf, sizeof(buf), "%u %s", static_cast<uint32_t>(value.m_data), units[0]);
		}
		else {
			size_t k = 0;
			double magnitude = 1.0;

			while ((x >= magnitude * 1e3) && (k < array_size(units) - 1)) {
				magnitude *= 1e3;
				++k;
			}

			n = snprintf(buf, sizeof(buf), "%.3f %s", x / magnitude, units[k]);
		}

		if (n > 0) {
			if (n > static_cast<int>(sizeof(buf)) - 1) {
				n = static_cast<int>(sizeof(buf)) - 1;
			}
			wrapper->writeBuf(buf, n);
		}
	}
};

struct XMRAmount
{
	explicit FORCEINLINE XMRAmount(uint64_t data) : m_data(data) {}

	uint64_t m_data;
};

template<> struct log::Stream::Entry<XMRAmount>
{
	static NOINLINE void put(XMRAmount value, Stream* wrapper)
	{
		constexpr uint64_t denomination = 1000000000000ULL;

		const int w = wrapper->getNumberWidth();

		wrapper->setNumberWidth(1);
		*wrapper << value.m_data / denomination << '.';

		wrapper->setNumberWidth(12);
		*wrapper << value.m_data % denomination << " XMR";

		wrapper->setNumberWidth(w);
	}
};

template<> struct log::Stream::Entry<NetworkType>
{
	// cppcheck-suppress constParameter
	static NOINLINE void put(NetworkType value, Stream* wrapper)
	{
		switch (value) {
		case NetworkType::Invalid:  *wrapper << "invalid";  break;
		case NetworkType::Mainnet:  *wrapper << "mainnet";  break;
		case NetworkType::Testnet:  *wrapper << "testnet";  break;
		case NetworkType::Stagenet: *wrapper << "stagenet"; break;
		}
	}
};

struct Duration
{
	explicit FORCEINLINE Duration(uint64_t data) : m_data(data) {}

	uint64_t m_data;
};

template<> struct log::Stream::Entry<Duration>
{
	static NOINLINE void put(Duration value, Stream* wrapper)
	{
		const uint64_t uptime = value.m_data;

		const int64_t s = uptime % 60;
		const int64_t m = (uptime / 60) % 60;
		const int64_t h = (uptime / 3600) % 24;
		const int64_t d = uptime / 86400;

		if (d > 0) {
			*wrapper << d << "d ";
		}
		*wrapper << h << "h " << m << "m " << s << 's';
	}
};

template<typename T>
struct PadRight
{
	FORCEINLINE PadRight(const T& value, int len) : m_value(value), m_len(len) {}

	const T& m_value;
	int m_len;

	// Declare it to make compiler happy
	PadRight(const PadRight&);

private:
	PadRight& operator=(const PadRight&) = delete;
	PadRight& operator=(PadRight&&) = delete;
};

template<typename T> FORCEINLINE PadRight<T> pad_right(const T& value, int len) { return PadRight<T>(value, len); }

template<typename T>
struct log::Stream::Entry<PadRight<T>>
{
	static NOINLINE void put(PadRight<T>&& data, Stream* wrapper)
	{
		char buf[log::Stream::BUF_SIZE + 1];
		log::Stream s(buf);
		s << data.m_value;

		const int len = std::min<int>(data.m_len, log::Stream::BUF_SIZE);
		if (s.m_pos < len) {
			memset(buf + s.m_pos, ' ', static_cast<size_t>(len) - s.m_pos);
			s.m_pos = len;
		}

		wrapper->writeBuf(buf, s.m_pos);
	}
};

void put_rawip(const raw_ip& value, Stream* wrapper);

template<> struct log::Stream::Entry<raw_ip>
{
	static FORCEINLINE void put(const raw_ip& value, Stream* wrapper) { put_rawip(value, wrapper); }
};

namespace {
	template<log::Severity severity> void apply_severity(log::Stream&);

	template<> FORCEINLINE void apply_severity<log::Severity::Info>(log::Stream& s) { s << log::NoColor(); }
	template<> FORCEINLINE void apply_severity<log::Severity::Warning>(log::Stream& s) { s << log::Yellow(); }
	template<> FORCEINLINE void apply_severity<log::Severity::Error>(log::Stream& s) { s << log::Red(); }
}

#define CONCAT(a, b) CONCAT2(a, b)
#define CONCAT2(a, b) a##b

#ifdef P2POOL_LOG_DISABLE

#define LOGINFO(level, ...)
#define LOGWARN(level, ...)
#define LOGERR(level, ...)

#else

#define LOG(level, severity, ...) \
	do { \
		if (level <= log::GLOBAL_LOG_LEVEL) { \
			log::Writer CONCAT(log_wrapper_, __LINE__)(severity); \
			CONCAT(log_wrapper_, __LINE__) << log::Gray() << log_category_prefix; \
			log::apply_severity<severity>(CONCAT(log_wrapper_, __LINE__)); \
			CONCAT(log_wrapper_, __LINE__) << __VA_ARGS__ << log::NoColor(); \
		} \
	} while (0)

#define LOGINFO(level, ...) LOG(level, log::Severity::Info, __VA_ARGS__)
#define LOGWARN(level, ...) LOG(level, log::Severity::Warning, __VA_ARGS__)
#define LOGERR(level, ...)  LOG(level, log::Severity::Error, __VA_ARGS__)

#endif

void reopen();
void stop();

} // namespace log

} // namespace p2pool
