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

#include "common.h"
#include "uv_util.h"
#include <ctime>
#include <fstream>
#include <thread>

static constexpr char log_category_prefix[] = "Log ";
static constexpr char log_file_name[] = "p2pool.log";

namespace p2pool {

namespace log {

int GLOBAL_LOG_LEVEL = 3;
bool CONSOLE_COLORS = true;

#ifndef P2POOL_LOG_DISABLE

static std::atomic<bool> stopped{ false };
static volatile bool worker_started = false;

#ifdef _WIN32
static const HANDLE hStdIn  = GetStdHandle(STD_INPUT_HANDLE);
static const HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
static const HANDLE hStdErr = GetStdHandle(STD_ERROR_HANDLE);
#endif

class Worker
{
public:
	enum params : int
	{
		SLOT_SIZE = 1024,
		BUF_SIZE = SLOT_SIZE * 8192,
	};

	FORCEINLINE Worker()
		: m_writePos(0)
		, m_readPos(0)
	{
		set_main_thread();

		m_logFile.open(log_file_name, std::ios::app | std::ios::binary);

		m_buf.resize(BUF_SIZE);

		// Create default loop here
		uv_default_loop();

		uv_cond_init(&m_cond);
		uv_mutex_init(&m_mutex);

		const int err = uv_thread_create(&m_worker, run_wrapper, this);
		if (err) {
			fprintf(stderr, "failed to start logger thread (%s), aborting\n", uv_err_name(err));
			abort();
		}

		while (!worker_started) {
			std::this_thread::yield();
		}

#ifdef _WIN32
		DWORD dwConsoleMode;
		if (GetConsoleMode(hStdIn, &dwConsoleMode)) {
			SetConsoleMode(hStdIn, dwConsoleMode & ~ENABLE_QUICK_EDIT_MODE);
		}
		if (GetConsoleMode(hStdOut, &dwConsoleMode)) {
			SetConsoleMode(hStdOut, dwConsoleMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
		}
#endif

		LOGINFO(0, "started");

		if (!m_logFile.is_open()) {
			LOGERR(0, "failed to open " << log_file_name);
		}
	}

	~Worker()
	{
		try {
			stop();
		}
		catch (...) {
		}
	}

	FORCEINLINE void stop()
	{
		if (stopped.exchange(true)) {
			return;
		}

		LOGINFO(0, "stopped");
		uv_thread_join(&m_worker);
		uv_cond_destroy(&m_cond);
		uv_mutex_destroy(&m_mutex);
		uv_loop_close(uv_default_loop());

		m_logFile.close();
	}

	FORCEINLINE void write(const char* buf, uint32_t size)
	{
		if (m_writePos.load() - m_readPos > BUF_SIZE - SLOT_SIZE * 16) {
			// Buffer is full, can't log normally
			if (size > 3) {
				fwrite(buf + 3, 1, size - 3, stderr);
			}
			return;
		}

		const uint32_t writePos = m_writePos.fetch_add(SLOT_SIZE);
		char* p = m_buf.data() + (writePos % BUF_SIZE);

		memcpy(p + 1, buf + 1, size - 1);

		// Ensure memory order in the writer thread
		std::atomic_thread_fence(std::memory_order_seq_cst);

		// Mark that everything is written into this log slot
		p[0] = buf[0] + 1;

		// Signal the worker thread
		uv_cond_signal(&m_cond);
	}

private:
	static void run_wrapper(void* arg) { reinterpret_cast<Worker*>(arg)->run(); }

	NOINLINE void run()
	{
		worker_started = true;

		do {
			uv_mutex_lock(&m_mutex);
			if (m_readPos == m_writePos.load()) {
				// Nothing to do, wait for the signal
				uv_cond_wait(&m_cond, &m_mutex);
			}
			uv_mutex_unlock(&m_mutex);

			for (uint32_t writePos = m_writePos.load(); m_readPos != writePos; writePos = m_writePos.load()) {
				// We have at least one log slot pending, possibly more than one
				// Process everything in a loop before reading m_writePos again
				do {
					char* p = m_buf.data() + (m_readPos % BUF_SIZE);

					// Wait until everything is written into this log slot
					volatile char& severity = p[0];
					while (!severity) {
						std::this_thread::yield();
					}

					// Ensure memory order in the reader thread
					std::atomic_thread_fence(std::memory_order_seq_cst);

					uint32_t size = static_cast<uint8_t>(p[2]);
					size = (size << 8) + static_cast<uint8_t>(p[1]);

					if (size > 3) {
						p += 3;
						size -= 3;

						// Read CONSOLE_COLORS only once because its value can be changed in another thread
						const bool c = CONSOLE_COLORS;

						if (!c) {
							strip_colors(p, size);
						}

#ifdef _WIN32
						DWORD k;
						WriteConsole((severity == 1) ? hStdOut : hStdErr, p, size, &k, nullptr);
#else
						fwrite(p, 1, size, (severity == 1) ? stdout : stderr);
#endif

						// Reopen the log file if it's been moved (logrotate support)
						if (m_logFile.is_open()) {
							struct stat buf;
							if (stat(log_file_name, &buf) != 0) {
								m_logFile.close();
								m_logFile.open(log_file_name, std::ios::app | std::ios::binary);
							}
						}

						if (m_logFile.is_open()) {
							if (c) {
								strip_colors(p, size);
							}

							if (severity == 1) {
								m_logFile.write("NOTICE  ", 8);
							}
							else if (severity == 2) {
								m_logFile.write("WARNING ", 8);
							}
							else if (severity == 3) {
								m_logFile.write("ERROR   ", 8);
							}

							m_logFile.write(p, size);
						}
					}

					// Mark this log slot empty
					severity = '\0';

					m_readPos += SLOT_SIZE;
				} while (m_readPos < writePos);
			}

			// Flush the log file only after all pending log lines have been written
			if (m_logFile.is_open()) {
				m_logFile.flush();
			}
		} while (!stopped);
	}

	static FORCEINLINE void strip_colors(char* buf, uint32_t& size)
	{
		char* p_read = buf;
		char* p_write = buf;
		char* buf_end = buf + size;

		bool is_color = false;

		while (p_read < buf_end) {
			if (!is_color && (*p_read == '\x1b')) {
				is_color = true;
			}

			if (!is_color) {
				*(p_write++) = *p_read;
			}

			if (is_color && (*p_read == 'm')) {
				is_color = false;
			}

			++p_read;
		}

		size = static_cast<uint32_t>(p_write - buf);
	}

	std::vector<char> m_buf;
	std::atomic<uint32_t> m_writePos;
	uint32_t m_readPos;

	uv_cond_t m_cond;
	uv_mutex_t m_mutex;
	uv_thread_t m_worker;

	std::ofstream m_logFile;
};

static Worker worker;

#endif // P2POOL_LOG_DISABLE

// cppcheck-suppress uninitMemberVar
NOINLINE Writer::Writer(Severity severity) : Stream(m_stackBuf)
{
	m_buf[0] = static_cast<char>(severity);
	m_pos = 3;

	*this << Cyan();
	writeCurrentTime();
	*this << NoColor() << ' ';
}

NOINLINE Writer::~Writer()
{
	const uint32_t size = static_cast<uint32_t>(m_pos + 1);
	m_buf[1] = static_cast<uint8_t>(size & 255);
	m_buf[2] = static_cast<uint8_t>(size >> 8);
	m_buf[m_pos] = '\n';
#ifndef P2POOL_LOG_DISABLE
	worker.write(m_buf, size);
#endif
}

void reopen()
{
	// This will trigger the worker thread which will then reopen log file if it's been moved
	LOGINFO(0, "reopening " << log_file_name);
}

void stop()
{
#ifndef P2POOL_LOG_DISABLE
	worker.stop();
#endif
}

NOINLINE void Stream::writeCurrentTime()
{
	using namespace std::chrono;

	const system_clock::time_point now = system_clock::now();
	const time_t t0 = system_clock::to_time_t(now);

	tm t;

#ifdef _WIN32
	gmtime_s(&t, &t0);
#else
	gmtime_r(&t0, &t);
#endif

	m_numberWidth = 2;
	*this << (t.tm_year + 1900) << '-' << (t.tm_mon + 1) << '-' << t.tm_mday << ' ' << t.tm_hour << ':' << t.tm_min << ':' << t.tm_sec << '.';

	const int32_t mcs = time_point_cast<microseconds>(now).time_since_epoch().count() % 1000000;

	m_numberWidth = 4;
	*this << (mcs / 100);
	// cppcheck-suppress redundantAssignment
	m_numberWidth = 1;
}

NOINLINE void put_rawip(const raw_ip& value, Stream* wrapper)
{
	const char* addr_str;
	char addr_str_buf[64];

	static constexpr uint8_t ipv4_prefix[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255 };
	const bool is_v6 = (memcmp(value.data, ipv4_prefix, 12) != 0);

	if (is_v6) {
		addr_str = inet_ntop(AF_INET6, value.data, addr_str_buf, sizeof(addr_str_buf));
	}
	else {
		addr_str = inet_ntop(AF_INET, value.data + 12, addr_str_buf, sizeof(addr_str_buf));
	}

	if (addr_str) {
		*wrapper << addr_str;
	}
	else {
		*wrapper << "N/A";
	}
}

} // namespace log

} // namespace p2pool
