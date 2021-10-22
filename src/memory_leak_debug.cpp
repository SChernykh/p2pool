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

#include "common.h"

// Simple memory leak detector for Windows users, works best in RelWithDebInfo configuration.
#if defined(_WIN32) && 0

#include "uv_util.h"
#include <atomic>
#include <type_traits>

#include <DbgHelp.h>

#pragma comment(lib, "Dbghelp.lib")

namespace p2pool {

static bool track_memory = false;

constexpr size_t N = 1048576;
constexpr size_t MAX_FRAMES = 30;

struct TrackedAllocation
{
	void* p;
	void* stack_trace[MAX_FRAMES];
	uint32_t thread_id;
	uint32_t allocated_size;
};

static_assert(sizeof(TrackedAllocation) == 256, "");

uv_mutex_t allocation_lock;
std::hash<void*> hasher;
uint32_t first[N];
uint32_t next[N];
TrackedAllocation allocations[N];
uint32_t num_allocations = 0;
uint32_t cur_allocation_index = 1;

FORCEINLINE static void add_alocation(void* p, size_t size)
{
	if (!track_memory) {
		return;
	}

	void* stack_trace[MAX_FRAMES];
	DWORD hash;
	CaptureStackBackTrace(1, MAX_FRAMES, stack_trace, &hash);

	const DWORD thread_id = GetCurrentThreadId();

	const size_t index = hasher(p) & (N - 1);

	p2pool::MutexLock lock(allocation_lock);

	++num_allocations;
	if (num_allocations >= N / 2) {
		// Make N two times bigger if this triggers
		__debugbreak();
	}

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

	p2pool::MutexLock lock(allocation_lock);

	--num_allocations;

	const size_t index = hasher(p) & (N - 1);

	for (uint32_t prev = 0, k = first[index]; k != 0; prev = k, k = next[k]) {
		if (allocations[k].p == p) {
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
	using namespace p2pool;

	uv_replace_allocator(malloc_hook, realloc_hook, calloc_hook, free_hook);
	uv_mutex_init_checked(&allocation_lock);
	track_memory = true;
}

void memory_tracking_stop()
{
	using namespace p2pool;

	track_memory = false;
	uv_mutex_destroy(&allocation_lock);

	const HANDLE h = GetCurrentProcess();
	SymInitialize(h, NULL, TRUE);

	uint64_t total_leaks = 0;

	for (uint32_t i = 0; i < N; ++i) {
		if (allocations[i].allocated_size) {
			total_leaks += allocations[i].allocated_size;

			char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)] = {};
			PSYMBOL_INFO pSymbol = reinterpret_cast<PSYMBOL_INFO>(buffer);

			pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
			pSymbol->MaxNameLen = MAX_SYM_NAME;

			IMAGEHLP_LINE64 line{};
			line.SizeOfStruct = sizeof(IMAGEHLP_LINE64);

			printf("Memory leak detected, %u bytes allocated by thread %u at:\n", allocations[i].allocated_size, allocations[i].thread_id);
			for (size_t j = 0; j < MAX_FRAMES; ++j) {
				const DWORD64 address = reinterpret_cast<DWORD64>(allocations[i].stack_trace[j]);
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
	}

	if (total_leaks > 0) {
		printf("%I64u bytes leaked\n\n", total_leaks);
	}
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
void memory_tracking_start() {}
void memory_tracking_stop() {}

namespace p2pool {

void* malloc_hook(size_t n) noexcept { return malloc(n); }
void* realloc_hook(void* ptr, size_t size) noexcept { return realloc(ptr, size); }
void* calloc_hook(size_t count, size_t size) noexcept { return calloc(count, size); }
void free_hook(void* p) noexcept { free(p); }

}
#endif
