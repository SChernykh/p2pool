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

#include "common.h"
#include "uv_util.h"
#include "thread_pool.h"
#include <thread>
#include <vector>

LOG_CATEGORY(ThreadPool)

namespace p2pool {

using work_t = std::shared_ptr<Callback<void>::Base>;

struct ThreadPool
{
	ThreadPool() = default;

	ThreadPool(const ThreadPool&) = delete;
	ThreadPool(ThreadPool&&) = delete;

	ThreadPool& operator=(const ThreadPool&) = delete;
	ThreadPool& operator=(ThreadPool&&) = delete;

	struct Thread
	{
		explicit Thread(const work_t& work)
			: m_stop(false)
			, m_thread{}
			, m_cond{}
			, m_work(work)
		{
			uv_mutex_init_checked(&m_mutex);
			uv_cond_init_checked(&m_cond);

			const int result = uv_thread_create(&m_thread, run, this);
			if (result) {
				LOGERR(1, "failed to create a thread, error " << uv_err_name(result));
				PANIC_STOP();
			}
		}

		~Thread()
		{
			m_stop.store(true, std::memory_order_release);
			{
				MutexLock lock(m_mutex);
				uv_cond_signal(&m_cond);
			}
			uv_thread_join(&m_thread);

			uv_cond_destroy(&m_cond);
			uv_mutex_destroy(&m_mutex);
		}

		static void run(void* arg) { reinterpret_cast<Thread*>(arg)->run(); }

		FORCEINLINE void do_work()
		{
			work_t w = std::move(m_work);

			auto* p = w.get();
			if (p) {
				(*p)();
			}
		}

		FORCEINLINE void run()
		{
			uv_mutex_lock(&m_mutex);

			char buf[16] = {};

			log::Stream s(buf);
			s << log_category_prefix << thread_index.fetch_add(1);

			set_thread_name(buf);

			for (;;) {
				do_work();
				if (m_stop.load(std::memory_order_acquire)) {
					uv_mutex_unlock(&m_mutex);
					return;
				}
				uv_cond_wait(&m_cond, &m_mutex);
			}
		}

		static std::atomic<uint32_t> thread_index;

		std::atomic<bool> m_stop;

		uv_thread_t m_thread;

		uv_mutex_t m_mutex;
		uv_cond_t m_cond;

		work_t m_work;
	};

	FORCEINLINE void queue_work(work_t&& callback, uint32_t N)
	{
		if (N == 0) {
			return;
		}

		work_t w = std::move(callback);
		{
			ReadLock lock(m_threadsLock);

			for (auto& t : m_threads) {
				if (uv_mutex_trylock(&t->m_mutex) == 0) {
					// Another concurrent queue_work might have assigned work to this thread already
					// Or it might be the initial work that the thread has right after its creation and before the first mutex lock
					if (t->m_work) {
						uv_mutex_unlock(&t->m_mutex);
						continue;
					}

					// This thread wasn't holding its mutex, and doesn't have any work,
					// so we can safely pass the work to it.
					t->m_work = w;
					uv_cond_signal(&t->m_cond);
					uv_mutex_unlock(&t->m_mutex);

					--N;
					if (N == 0) {
						return;
					}
				}
			}
		}

		// If there wasn't enough free threads, spawn some more
		if (N > 0) {
			WriteLock lock(m_threadsLock);

			m_threads.reserve(m_threads.size() + N);

			for (uint32_t i = 0; i < N; ++i) {
				m_threads.emplace_back(std::make_unique<Thread>(w));
			}
		}
	}

	ReadWriteLock m_threadsLock;
	std::vector<std::unique_ptr<Thread>> m_threads;
};

static ThreadPool* tp = nullptr;
std::atomic<uint32_t> ThreadPool::Thread::thread_index = 0;

void thread_pool_init()
{
	if (!tp) {
		tp = new ThreadPool();
	}
}

void thread_pool_destroy()
{
	delete tp;
	tp = nullptr;
}

void queue_work_base(work_t&& callback, uint32_t N)
{
	tp->queue_work(std::move(callback), N);
}

} // namespace p2pool
