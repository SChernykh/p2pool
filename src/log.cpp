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

#include "common.h"
#include "uv_util.h"
#include "wallet.h"
#include <ctime>
#include <fstream>
#include <thread>
#include <stdlib.h>
#include <clocale>

#ifdef _MSC_VER
#pragma warning(disable : 4996)
#endif

LOG_CATEGORY(Log)

static constexpr char log_file_name[] = "p2pool.log";

namespace p2pool {

namespace log {

int GLOBAL_LOG_LEVEL = 3;
bool CONSOLE_COLORS = true;

#ifndef P2POOL_LOG_DISABLE

#ifdef _WIN32
static const HANDLE hStdIn  = GetStdHandle(STD_INPUT_HANDLE);
static const HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);

#if defined(_MSC_VER) && !defined(NDEBUG)

#include <DbgHelp.h>

#pragma comment(lib, "Dbghelp.lib")

LONG WINAPI UnhandledExceptionFilter(_In_ _EXCEPTION_POINTERS* exception_pointers)
{
	constexpr size_t MAX_FRAMES = 32;

	void* stack_trace[MAX_FRAMES] = {};
	DWORD hash;
	CaptureStackBackTrace(1, MAX_FRAMES, stack_trace, &hash);

	char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)] = {};
	PSYMBOL_INFO pSymbol = reinterpret_cast<PSYMBOL_INFO>(buffer);

	pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
	pSymbol->MaxNameLen = MAX_SYM_NAME;

	IMAGEHLP_LINE64 line{};
	line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);

	const HANDLE h = GetCurrentProcess();

	const uint32_t code = (exception_pointers && exception_pointers->ExceptionRecord) ? exception_pointers->ExceptionRecord->ExceptionCode : 0;

	fprintf(stderr, "\n\nUnhandled exception %X at:\n", code);
	fflush(stderr);

	for (size_t j = 0; j < MAX_FRAMES; ++j) {
		const DWORD64 address = reinterpret_cast<DWORD64>(stack_trace[j]);
		DWORD t = 0;
		if (SymFromAddr(h, address, nullptr, pSymbol) && SymGetLineFromAddr64(h, address, &t, &line)) {
			fprintf(stderr, "%s (%s, line %lu)\n", line.FileName, pSymbol->Name, line.LineNumber);
			fflush(stderr);
		}
	}

	fprintf(stderr, "\n\n");
	fflush(stderr);

	// Normal logging might be broken at this point, but try to log it anyway
	LOGERR(0, "Unhandled exception " << log::Hex(code) << " at:");

	for (size_t j = 0; j < MAX_FRAMES; ++j) {
		const DWORD64 address = reinterpret_cast<DWORD64>(stack_trace[j]);
		DWORD t = 0;
		if (SymFromAddr(h, address, nullptr, pSymbol) && SymGetLineFromAddr64(h, address, &t, &line)) {
			LOGERR(0, line.FileName << " (" << static_cast<const char*>(pSymbol->Name) << ", line " << static_cast<size_t>(line.LineNumber) << ')');
		}
	}

	Sleep(1000);

	return EXCEPTION_CONTINUE_SEARCH;
}
#endif // _MSC_VER && !NDEBUG
#endif // _WIN32

class Worker
{
public:
	enum params : int
	{
		SLOT_SIZE = log::Stream::BUF_SIZE + 1,
		BUF_SIZE = SLOT_SIZE * 8192,
	};

	FORCEINLINE Worker()
		: m_writePos(0)
		, m_readPos(0)
		, m_stopped(false)
	{
#if defined(_WIN32) && defined(_MSC_VER) && !defined(NDEBUG)
		SetUnhandledExceptionFilter(UnhandledExceptionFilter);
#endif

		set_main_thread();

		std::setlocale(LC_ALL, "en_001");

		m_logFile.open(log_file_name, std::ios::app | std::ios::binary);

		m_buf.resize(BUF_SIZE);

		uv_cond_init(&m_cond);
		uv_mutex_init(&m_mutex);

#ifdef _WIN32
		SetConsoleMode(hStdIn, ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT | ENABLE_EXTENDED_FLAGS);

		DWORD dwConsoleMode;
		if (GetConsoleMode(hStdOut, &dwConsoleMode)) {
			SetConsoleMode(hStdOut, dwConsoleMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
		}
#endif

		const char* no_color = getenv("NO_COLOR");
		if (no_color && *no_color) {
			CONSOLE_COLORS = false;
		}

		if (!m_logFile.is_open()) {
			fprintf(stderr, "failed to open %s\n", log_file_name);
		}

		init_uv_threadpool();

		const int err = uv_thread_create(&m_worker, run_wrapper, this);
		if (err) {
			fprintf(stderr, "failed to start logger thread (%s), aborting\n", uv_err_name(err));
			abort();
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
		{
			MutexLock lock(m_mutex);
			if (m_stopped) {
				return;
			}

			m_stopped = true;
			LOGINFO(0, "stopped");
		}

		uv_thread_join(&m_worker);
		uv_cond_destroy(&m_cond);
		uv_mutex_destroy(&m_mutex);

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
#ifndef DEV_WITH_TSAN
		std::atomic_thread_fence(std::memory_order_seq_cst);
#endif

		// Mark that everything is written into this log slot
		p[0] = buf[0] + 1;

		// Signal the worker thread
		uv_cond_signal(&m_cond);
	}

private:
	static void init_uv_threadpool()
	{
#ifdef _MSC_VER
#define putenv _putenv
#endif

		const uint32_t N = std::min(std::max(std::thread::hardware_concurrency(), 4U), 8U);

		static char buf[40] = {};
		log::Stream s(buf);
		s << "UV_THREADPOOL_SIZE=" << N << '\0';

		int err = putenv(buf);
		if (err != 0) {
			err = errno;
			fprintf(stderr, "Couldn't set UV thread pool size to %u threads, putenv returned error %d\n", N, err);
		}

		static uv_work_t dummy;
		err = uv_queue_work(uv_default_loop_checked(), &dummy, [](uv_work_t*) {}, nullptr);
		if (err) {
			fprintf(stderr, "init_uv_threadpool: uv_queue_work failed, error %s\n", uv_err_name(err));
		}
	}

private:
	static void run_wrapper(void* arg) { reinterpret_cast<Worker*>(arg)->run(); }

	NOINLINE void run()
	{
		do {
			uv_mutex_lock(&m_mutex);
			if (m_readPos == m_writePos.load()) {
				// Nothing to do, wait for the signal or exit if stopped
				if (m_stopped) {
					uv_mutex_unlock(&m_mutex);
					return;
				}
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
#ifndef DEV_WITH_TSAN
					std::atomic_thread_fence(std::memory_order_seq_cst);
#endif

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

						fwrite(p, 1, size, (severity == 1) ? stdout : stderr);

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
				} while (m_readPos != writePos);
			}

			// Flush the log file only after all pending log lines have been written
			if (m_logFile.is_open()) {
				m_logFile.flush();

				// Reopen the log file if it's been moved (logrotate support)
				struct stat buf;
				if (stat(log_file_name, &buf) != 0) {
					m_logFile.close();
					m_logFile.open(log_file_name, std::ios::app | std::ios::binary);
				}
			}

			fflush(stdout);
			fflush(stderr);
		} while (1);
	}

	static FORCEINLINE void strip_colors(char* buf, uint32_t& size)
	{
		const char* p_read = buf;
		char* p_write = buf;
		const char* buf_end = buf + size;

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

	bool m_stopped;

	std::ofstream m_logFile;
};

static Worker* worker = nullptr;

#endif // P2POOL_LOG_DISABLE

static FORCEINLINE void writeCurrentTime(Stream& s)
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

	s.setNumberWidth(2);
	s << (t.tm_year + 1900) << '-' << (t.tm_mon + 1) << '-' << t.tm_mday << ' ' << t.tm_hour << ':' << t.tm_min << ':' << t.tm_sec << '.';

	const int32_t mcs = time_point_cast<microseconds>(now).time_since_epoch().count() % 1000000;

	s.setNumberWidth(4);
	s << (mcs / 100);
	s.setNumberWidth(1);
}

NOINLINE Writer::Writer(Severity severity) : Stream(m_stackBuf)
{
	m_stackBuf[BUF_SIZE] = '\0';
	m_buf[0] = static_cast<char>(severity);
	m_pos = 3;

	*this << Cyan();
	writeCurrentTime(*this);
	*this << NoColor() << ' ';
}

NOINLINE Writer::~Writer()
{
	const uint32_t size = static_cast<uint32_t>(m_pos + 1);
	m_buf[1] = static_cast<uint8_t>(size & 255);
	m_buf[2] = static_cast<uint8_t>(size >> 8);
	m_buf[m_pos] = '\n';
#ifndef P2POOL_LOG_DISABLE
	worker->write(m_buf, size);
#endif
}

void start()
{
#ifndef P2POOL_LOG_DISABLE
	worker = new Worker();

	LOGINFO(0, "started");
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
	delete worker;
	worker = nullptr;
#endif
}

NOINLINE void Stream::Entry<raw_ip>::put(const raw_ip& value, Stream* wrapper)
{
	const bool is_ipv4 = value.is_ipv4_prefix();

	char addr_str_buf[64];
	const char* addr_str = inet_ntop(is_ipv4 ? AF_INET : AF_INET6, value.data + (is_ipv4 ? 12 : 0), addr_str_buf, sizeof(addr_str_buf));

	*wrapper << (addr_str ? addr_str : "N/A");
}

NOINLINE void Stream::Entry<Wallet>::put(const Wallet& w, Stream* wrapper)
{
	char buf[Wallet::ADDRESS_LENGTH];
	w.encode(buf);
	wrapper->writeBuf(buf, Wallet::ADDRESS_LENGTH);
}

} // namespace log

} // namespace p2pool
