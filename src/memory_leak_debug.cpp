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

// Simple memory leak detector for Windows users, works best in RelWithDebInfo configuration.
#if defined(_WIN32) && defined(DEV_TRACK_MEMORY) && defined(_MSC_VER) && !defined(NDEBUG)

#include "uv_util.h"
#include <atomic>
#include <type_traits>
#include <iostream>
#include <fstream>
#include <mutex>

#include <DbgHelp.h>

#pragma comment(lib, "Dbghelp.lib")

namespace p2pool {

static bool track_memory = false;

constexpr size_t N = 1 << 22;
constexpr size_t MAX_FRAMES = 29;

struct TrackedAllocation
{
	void* p;
	void* stack_trace[MAX_FRAMES];
	uint64_t allocated_size;
	uint32_t thread_id;

	FORCEINLINE bool operator<(const TrackedAllocation& rhs) { return memcmp(stack_trace, rhs.stack_trace, sizeof(stack_trace)) < 0; }
	FORCEINLINE bool operator==(const TrackedAllocation& rhs) { return memcmp(stack_trace, rhs.stack_trace, sizeof(stack_trace)) == 0; }

	void print(HANDLE h) const
	{
		char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)] = {};
		PSYMBOL_INFO pSymbol = reinterpret_cast<PSYMBOL_INFO>(buffer);

		pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
		pSymbol->MaxNameLen = MAX_SYM_NAME;

		IMAGEHLP_LINE64 line{};
		line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);

		for (size_t j = 0; j < MAX_FRAMES; ++j) {
			const DWORD64 address = reinterpret_cast<DWORD64>(stack_trace[j]);
			DWORD64 t1 = 0;
			DWORD t2 = 0;
			if (SymFromAddr(h, address, &t1, pSymbol) && SymGetLineFromAddr64(h, address, &t2, &line)) {
				const char* s = line.FileName;
				const char* file_name = nullptr;
				while (*s) {
					if ((*s == '\\') || (*s == '/')) {
						file_name = s + 1;
					}
					++s;
				}
				printf("%-25s %s (line %lu)\n", file_name ? file_name : line.FileName, pSymbol->Name, line.LineNumber);
			}
		}
		printf("\n");
	}
};

static_assert(sizeof(TrackedAllocation) == 256, "");

std::mutex allocation_lock;
std::hash<void*> hasher;
uint32_t first[N];
uint32_t next[N];
TrackedAllocation allocations[N];
uint32_t num_allocations = 0;
uint64_t total_allocated = 0;
uint32_t cur_allocation_index = 1;

void show_top_10_allocations()
{
	TrackedAllocation* buf = reinterpret_cast<TrackedAllocation*>(VirtualAlloc(nullptr, sizeof(TrackedAllocation) * N, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
	if (!buf) {
		return;
	}

	const HANDLE h = GetCurrentProcess();

	{
		std::lock_guard<std::mutex> lock(allocation_lock);

		TrackedAllocation* end = buf;
		for (size_t i = 0; i < N; ++i) {
			if (allocations[i].allocated_size) {
				*(end++) = allocations[i];
			}
		}

		std::sort(buf, end);

		TrackedAllocation* prev = buf;
		for (TrackedAllocation* p = buf + 1; p < end; ++p) {
			if (*p == *prev) {
				prev->allocated_size += p->allocated_size;
			}
			else {
				++prev;
				*prev = *p;
			}
		}
		end = prev + 1;

		std::sort(buf, end, [](const auto& a, const auto& b) { return a.allocated_size > b.allocated_size; });

		printf("%I64u total bytes allocated\n\n", total_allocated);
		printf("Top 10 allocations:\n\n");

		for (TrackedAllocation* p = buf; (p < buf + 10) && (p < end); ++p) {
			printf("%I64u bytes allocated at:\n", p->allocated_size);
			p->print(h);
		}
	}

	printf("\n");

	VirtualFree(buf, 0, MEM_RELEASE);
}

static DWORD WINAPI minidump_and_crash_thread(LPVOID param)
{
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

	const size_t delay = reinterpret_cast<size_t>(param);
	Sleep(static_cast<DWORD>(delay));

	HANDLE h = CreateFile(TEXT("p2pool.dmp"), GENERIC_ALL, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), h, MiniDumpWithHandleData, nullptr, nullptr, nullptr);
	CloseHandle(h);

	TerminateProcess(GetCurrentProcess(), 123);

	return 0;
}

void minidump_and_crash(size_t delay)
{
	HANDLE h = CreateThread(nullptr, 0, minidump_and_crash_thread, reinterpret_cast<LPVOID>(delay), 0, nullptr);
	CloseHandle(h);
}

FORCEINLINE static void add_alocation(void* p, size_t size)
{
	if (!track_memory) {
		return;
	}

	void* stack_trace[MAX_FRAMES] = {};
	DWORD hash;
	CaptureStackBackTrace(1, MAX_FRAMES, stack_trace, &hash);

	const DWORD thread_id = GetCurrentThreadId();

	const size_t index = hasher(p) & (N - 1);

	std::lock_guard<std::mutex> lock(allocation_lock);

	++num_allocations;
	if (num_allocations >= N / 2) {
		// Make N two times bigger if this triggers
		__debugbreak();
	}
	total_allocated += size;

	for (uint64_t i = cur_allocation_index;; i = (i + 1) & (N - 1)) {
		if (i && !allocations[i].allocated_size) {
			cur_allocation_index = static_cast<uint32_t>(i);
			allocations[i].allocated_size = static_cast<uint32_t>(size);
			break;
		}
	}

	TrackedAllocation& t = allocations[cur_allocation_index];
	t.p = p;
	memcpy(t.stack_trace, stack_trace, sizeof(stack_trace));
	next[cur_allocation_index] = first[index];
	t.thread_id = thread_id;
	first[index] = cur_allocation_index;
}

FORCEINLINE static void remove_allocation(void* p)
{
	if (!track_memory || !p) {
		return;
	}

	std::lock_guard<std::mutex> lock(allocation_lock);

	--num_allocations;

	const size_t index = hasher(p) & (N - 1);

	for (uint32_t prev = 0, k = first[index]; k != 0; prev = k, k = next[k]) {
		if (allocations[k].p == p) {
			total_allocated -= allocations[k].allocated_size;
			allocations[k].allocated_size = 0;
			if (prev) {
				next[prev] = next[k];
			}
			else {
				first[index] = next[k];
			}
			return;
		}
	}

	// Someone tried to deallocate a pointer that wasn't allocated before
	__debugbreak();
}

void* malloc_hook(size_t n) noexcept
{
	void* p = malloc(n);
	if (p) {
		add_alocation(p, n);
	}
	return p;
}

FORCEINLINE static void* allocate(size_t n)
{
	void* p = malloc_hook(n);
	if (!p) {
		throw std::bad_alloc();
	}
	return p;
}

void free_hook(void* p) noexcept
{
	remove_allocation(p);
	free(p);
}

char* strdup_hook(const char* s) noexcept
{
#ifdef _MSC_VER
	char* s1 = _strdup(s);
#else
	char* s1 = strdup(s);
#endif
	if (s1) {
		add_alocation(s1, strlen(s) + 1);
	}
	return s1;
}

void* realloc_hook(void* ptr, size_t size) noexcept
{
	remove_allocation(ptr);

	void* p = realloc(ptr, size);
	if (p) {
		add_alocation(p, size);
	}
	return p;
}

void* calloc_hook(size_t count, size_t size) noexcept
{
	void* p = calloc(count, size);
	if (p) {
		add_alocation(p, size);
	}
	return p;
}

} // p2pool

void memory_tracking_start()
{
	// Trigger std::ostream initialization to avoid reporting it as leaks
	std::cout << "Memory leak detection = " << 1 << std::endl;

	// Trigger std::ofstream initialization to avoid reporting it as leaks
	{
		std::ofstream tmp("memory_tracking.tmp");
	}

	using namespace p2pool;

	uv_replace_allocator(malloc_hook, realloc_hook, calloc_hook, free_hook);
	track_memory = true;
}

bool memory_tracking_stop()
{
	using namespace p2pool;

	track_memory = false;

	const HANDLE h = GetCurrentProcess();

	uint64_t total_leaks = 0;

	for (uint32_t i = 0; i < N; ++i) {
		const TrackedAllocation& t = allocations[i];
		if (t.allocated_size) {
			total_leaks += t.allocated_size;

			printf("Memory leak detected, %I64u bytes allocated at %p by thread %u:\n", t.allocated_size, t.p, t.thread_id);
			t.print(h);
		}
	}

	if (total_leaks > 0) {
		printf("%I64u bytes leaked\n\n", total_leaks);
	}
	else {
		printf("No memory leaks detected\n\n");
	}

	return (total_leaks == 0);
}

NOINLINE void* operator new(size_t n) { return p2pool::allocate(n); }
NOINLINE void* operator new[](size_t n) { return p2pool::allocate(n); }
NOINLINE void* operator new(size_t n, const std::nothrow_t&) noexcept { return p2pool::malloc_hook(n); }
NOINLINE void* operator new[](size_t n, const std::nothrow_t&) noexcept { return p2pool::malloc_hook(n); }
NOINLINE void operator delete(void* p) noexcept { p2pool::free_hook(p); }
NOINLINE void operator delete[](void* p) noexcept { p2pool::free_hook(p); }
NOINLINE void operator delete(void* p, size_t) noexcept { p2pool::free_hook(p); }
NOINLINE void operator delete[](void* p, size_t) noexcept { p2pool::free_hook(p); }

#else
// cppcheck-suppress functionStatic
void memory_tracking_start() {}
// cppcheck-suppress functionStatic
bool memory_tracking_stop() { return true; }

namespace p2pool {

void* malloc_hook(size_t n) noexcept { return malloc(n); }
void* realloc_hook(void* ptr, size_t size) noexcept { return realloc(ptr, size); }
void* calloc_hook(size_t count, size_t size) noexcept { return calloc(count, size); }
void free_hook(void* p) noexcept { free(p); }

char* strdup_hook(const char* s) noexcept
{
#ifdef _MSC_VER
	return _strdup(s);
#else
	return strdup(s);
#endif
}

}
#endif
