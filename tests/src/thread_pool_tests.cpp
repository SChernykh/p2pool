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
#include "gtest/gtest.h"
#include <thread>
#include <atomic>
#include <vector>
#include <chrono>

namespace p2pool {

TEST(thread_pool, parallel_run)
{
	using namespace std;
	using namespace chrono;

	thread_pool_init();

	constexpr uint32_t NUM_CALLER_THREADS = 4;
	constexpr uint32_t ITERATIONS_PER_THREAD = 25000;

	atomic<uint64_t> completed_runs = 0;
	atomic<bool> finished = false;
	atomic<bool> wrong_thread_count = false;

	thread watchdog([&completed_runs, &finished]() {
		uint64_t last = 0;
		auto last_changed = steady_clock::now();

		while (!finished.load(memory_order_acquire)) {
			this_thread::sleep_for(milliseconds(1));

			const uint64_t now = completed_runs.load(memory_order_relaxed);

			if (now != last) {
				last = now;
				last_changed = steady_clock::now();
			}
			else {
				const double dt = static_cast<double>(duration_cast<nanoseconds>(steady_clock::now() - last_changed).count()) / 1e9;

				if (dt >= 10.0) {
					fprintf(stderr, "no progress for %.3fs after %lu runs - parallel_run() lost a thread (work-assignment race -> deadlock)\n", dt, now);
					fflush(stderr);
					abort();
				}
			}
		}
	});

	const uint32_t cap = min<uint32_t>(thread::hardware_concurrency(), 16u);
	const uint32_t effective_total = (cap <= 1) ? 1u : cap;

	vector<thread> callers;
	callers.reserve(NUM_CALLER_THREADS);

	for (uint32_t t = 0; t < NUM_CALLER_THREADS; ++t) {
		callers.emplace_back([t, effective_total, &completed_runs, &wrong_thread_count, ITERATIONS_PER_THREAD]() {
			for (uint32_t it = 0; it < ITERATIONS_PER_THREAD; ++it) {
				const uint32_t N = 2u + ((it + t) % 3u);

				atomic<uint32_t> counter = 0;
				atomic<uint32_t> participated = 0;

				parallel_run([N, &counter, &participated](uint32_t thread_index, uint32_t total_thread_count) {
					const uint32_t thread_count = min<uint32_t>(total_thread_count, N);

					if (thread_index >= thread_count) {
						return;
					}

					participated.fetch_add(1, memory_order_relaxed);

					sync_point(counter, thread_count);
					sync_point(counter, thread_count * 2u);
				}, true);

				const uint32_t expected = min<uint32_t>(effective_total, N);

				if (participated.load(memory_order_relaxed) != expected) {
					wrong_thread_count.store(true, memory_order_relaxed);
				}

				completed_runs.fetch_add(1, memory_order_relaxed);
			}
		});
	}

	for (thread& c : callers) {
		c.join();
	}

	finished.store(true, memory_order_release);
	watchdog.join();

	EXPECT_FALSE(wrong_thread_count.load(memory_order_relaxed));
	EXPECT_EQ(completed_runs.load(memory_order_relaxed), static_cast<uint64_t>(NUM_CALLER_THREADS) * ITERATIONS_PER_THREAD);

	thread_pool_destroy();
}

} // namespace p2pool
