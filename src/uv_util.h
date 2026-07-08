/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2026 SChernykh <https://github.com/SChernykh>
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

#include <uv.h>
#include <thread>
#include <utility>
#include "thread_pool.h"

constexpr uint32_t MIN_UV_THREADPOOL_SIZE = 4;
constexpr uint32_t MAX_UV_THREADPOOL_SIZE = 8;

static_assert(sizeof(in6_addr) == 16, "struct in6_addr has invalid size");
static_assert(sizeof(in_addr) == 4, "struct in_addr has invalid size");

namespace p2pool {

struct ReadWriteLock : public nocopy_nomove {
	FORCEINLINE  ReadWriteLock() { uv_rwlock_init(&m_lock);    }
	FORCEINLINE ~ReadWriteLock() { uv_rwlock_destroy(&m_lock); }

	FORCEINLINE operator uv_rwlock_t&() { return m_lock; }

private:
	uv_rwlock_t m_lock;
};

struct MutexLock : public nocopy_nomove
{
	explicit FORCEINLINE MutexLock(uv_mutex_t& handle) : m_handle(&handle) { uv_mutex_lock(&handle); }
	FORCEINLINE ~MutexLock() { uv_mutex_unlock(m_handle); }

private:
	uv_mutex_t* m_handle;
};

template<bool write> struct RWLock;

template<> struct RWLock<false> : public nocopy_nomove
{
	explicit FORCEINLINE RWLock(uv_rwlock_t& handle) : m_handle(&handle) { uv_rwlock_rdlock(&handle); }
	FORCEINLINE ~RWLock() { uv_rwlock_rdunlock(m_handle); }

private:
	uv_rwlock_t* m_handle;
};

typedef RWLock<false> ReadLock;

template<> struct RWLock<true> : public nocopy_nomove
{
	explicit FORCEINLINE RWLock(uv_rwlock_t& handle) : m_handle(&handle) { uv_rwlock_wrlock(&handle); }
	FORCEINLINE ~RWLock() { uv_rwlock_wrunlock(m_handle); }

private:
	uv_rwlock_t* m_handle;
};

typedef RWLock<true> WriteLock;

void uv_cond_init_checked(uv_cond_t* cond);
void uv_mutex_init_checked(uv_mutex_t* mutex);
void uv_rwlock_init_checked(uv_rwlock_t* lock);
void uv_async_init_checked(uv_loop_t* loop, uv_async_t* async, uv_async_cb async_cb);
uv_loop_t* uv_default_loop_checked();

typedef Callback<void>::Base UV_LoopCallbackBase;

struct UV_LoopUserData
{
	uv_loop_t* m_loop;
	uv_async_t* m_async;

	uv_mutex_t m_callbacksLock;
	std::vector<UV_LoopCallbackBase*> m_callbacks;

	std::vector<UV_LoopCallbackBase*> m_callbacksToRun;

	explicit UV_LoopUserData(uv_loop_t* loop)
		: m_loop(loop)
		, m_async(new uv_async_t{})
		, m_callbacksLock{}
		, m_callbacks{}
		, m_callbacksToRun{}
	{
		uv_async_init_checked(m_loop, m_async, async_cb);
		m_async->data = this;

		uv_mutex_init_checked(&m_callbacksLock);

		m_callbacks.reserve(2);
		m_callbacksToRun.reserve(2);
	}

	~UV_LoopUserData()
	{
		uv_mutex_destroy(&m_callbacksLock);
		uv_close(reinterpret_cast<uv_handle_t*>(m_async), [](uv_handle_t* h) { delete reinterpret_cast<uv_async_t*>(h); });
		for (const UV_LoopCallbackBase* cb : m_callbacks) {
			delete cb;
		}
	}

	static void async_cb(uv_async_t* h)
	{
		UV_LoopUserData* data = reinterpret_cast<UV_LoopUserData*>(h->data);

		data->m_callbacksToRun.clear();
		{
			MutexLock lock(data->m_callbacksLock);
			std::swap(data->m_callbacks, data->m_callbacksToRun);
		}

		for (UV_LoopCallbackBase* cb : data->m_callbacksToRun) {
			(*cb)();
			delete cb;
		}
	}

	UV_LoopUserData(const UV_LoopUserData&) = delete;
	UV_LoopUserData& operator=(const UV_LoopUserData&) = delete;
};

UV_LoopUserData* GetLoopUserData(uv_loop_t* loop, bool create = true);
void DeleteLoopUserData(uv_loop_t* loop);

template<typename T>
bool CallOnLoop(uv_loop_t* loop, T&& callback)
{
	UV_LoopUserData* data = GetLoopUserData(loop, false);
	if (!data) {
		return false;
	}

	UV_LoopCallbackBase* cb = new Callback<void>::Derived<T>(std::forward<T>(callback));
	{
		MutexLock lock(data->m_callbacksLock);
		data->m_callbacks.push_back(cb);
	}

	if (uv_async_send(data->m_async) == 0) {
		return true;
	}

	// Clean up after uv_async_send error
	bool found = false;
	{
		MutexLock lock(data->m_callbacksLock);

		auto it = std::find(data->m_callbacks.begin(), data->m_callbacks.end(), cb);
		if (it != data->m_callbacks.end()) {
			found = true;
			data->m_callbacks.erase(it);
		}
	}

	if (found) {
		delete cb;
	}

	return false;
}

template<typename T, typename U = void>
struct accepts_parallel_run_params : std::false_type{};

template<typename T>
struct accepts_parallel_run_params<T, std::void_t<decltype(std::declval<T&>()(
	// parameters that parallel_run wants to pass to the callback
	std::declval<uint32_t>(), // zero-based thread index
	std::declval<uint32_t>()  // thread count
))>> : std::true_type{};

// Runs the callback in parallel on up to 16 threads
template<typename T>
void parallel_run(T&& callback, bool wait = false)
{
	static_assert(!std::is_lvalue_reference_v<T>, "parallel_run() requires an rvalue callback; use std::move or pass a temporary lambda");
	using CallbackT = std::decay_t<T>;

	const uint32_t THREAD_CAPACITY = std::min<uint32_t>(std::thread::hardware_concurrency(), 16u);

	// Run synchronously on single-CPU systems
	if (THREAD_CAPACITY <= 1) {
		if constexpr (accepts_parallel_run_params<CallbackT>::value) {
			callback(0u, 1u);
		}
		else {
			callback();
		}
		return;
	}

	struct Work
	{
		FORCEINLINE Work(CallbackT&& f, uint32_t total_thread_count)
			: m_func(std::forward<CallbackT>(f))
			, m_threadIndex(0)
			, m_finishedThreads(0)
			, m_totalThreadCount(total_thread_count)
		{}

		Work& operator=(Work&&) = delete;

		CallbackT m_func;
		std::atomic<uint32_t> m_threadIndex;
		std::atomic<uint32_t> m_finishedThreads;

		uint32_t m_totalThreadCount;
	};

	// "THREAD_CAPACITY - 1" because current thread is already running
	const uint32_t threads_to_start = THREAD_CAPACITY - 1;

	std::shared_ptr<Work> work = std::make_shared<Work>(std::forward<T>(callback), threads_to_start + (wait ? 1 : 0));

	queue_work([work, wait]() {
		Work* w = work.get();

		if constexpr (accepts_parallel_run_params<CallbackT>::value) {
			w->m_func(w->m_threadIndex.fetch_add(1, std::memory_order_relaxed), w->m_totalThreadCount);
		}
		else {
			w->m_func();
		}

		if (wait) {
			// Ensure the data written by the callback can be read after this point
			w->m_finishedThreads.fetch_add(1, std::memory_order_acq_rel);
		}
	}, threads_to_start);

	if (wait) {
		Work* w = work.get();

		if constexpr (accepts_parallel_run_params<CallbackT>::value) {
			w->m_func(w->m_threadIndex.fetch_add(1, std::memory_order_relaxed), w->m_totalThreadCount);
		}
		else {
			w->m_func();
		}

		while (w->m_finishedThreads.load(std::memory_order_acquire) < threads_to_start) {
			std::this_thread::yield();
		}
	}
}

// Thread sync point to use inside parallel_run's callback
template<typename T>
FORCEINLINE bool sync_point(std::atomic<T>& value, T k) {
	if (value.fetch_add(1, std::memory_order_acq_rel) + 1 >= k) {
		return true;
	}

	// some threads are not here yet, wait for them
	size_t fast_spin_count = 0;

	do {
		if (fast_spin_count < 10000) {
			++fast_spin_count;
			cpu_yield();
		}
		else {
			std::this_thread::yield();
		}
	} while (value.load(std::memory_order_acquire) < k);

	return false;
}

void set_thread_name(const char* name);
void init_uv();

} // namespace p2pool
