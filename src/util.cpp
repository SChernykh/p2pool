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
#include "util.h"
#include "uv_util.h"
#include <map>
#include <thread>
#include <chrono>

#ifndef _WIN32
#include <sched.h>
#endif

static constexpr char log_category_prefix[] = "Util ";

namespace p2pool {

MinerCallbackHandler::~MinerCallbackHandler() {}

void panic()
{
	p2pool::log::stop();
	do {
#ifdef _WIN32
		if (IsDebuggerPresent()) {
			__debugbreak();
		}
#endif
		exit(1);
	} while (true);
}

void make_thread_background()
{
#ifdef _WIN32
	SetThreadPriorityBoost(GetCurrentThread(), true);
	SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN);
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_IDLE);
#elif !defined(__APPLE__)
	sched_param param;
	param.sched_priority = 0;
	if (sched_setscheduler(0, SCHED_IDLE, &param) != 0) {
		sched_setscheduler(0, SCHED_BATCH, &param);
	}
#endif
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
				const uint64_t t = result[k] + product[l] + carry;
				carry = static_cast<uint64_t>(t < result[k]);
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
					const uint64_t t = result[k] + product[l] + carry;
					carry = static_cast<uint64_t>(t < result[k]);
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

difficulty_type operator+(const difficulty_type& a, const difficulty_type& b)
{
	difficulty_type result = a;
	result += b;
	return result;
}

void uv_mutex_init_checked(uv_mutex_t* mutex)
{
	const int result = uv_mutex_init(mutex);
	if (result) {
		LOGERR(1, "failed to create mutex, error " << uv_err_name(result));
		panic();
	}
}

void uv_rwlock_init_checked(uv_rwlock_t* lock)
{
	const int result = uv_rwlock_init(lock);
	if (result) {
		LOGERR(1, "failed to create rwlock, error " << uv_err_name(result));
		panic();
	}
}

uv_loop_t* uv_default_loop_checked()
{
	if (!is_main_thread) {
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
		do {
			bool is_empty = true;
			{
				MutexLock lock(m_lock);
				is_empty = m_jobs.empty();
				for (const auto& job : m_jobs) {
					LOGINFO(1, "waiting for " << job.second << " \"" << job.first << "\" jobs to finish");
				}
			}

			if (is_empty) {
				return;
			}

			std::this_thread::sleep_for(std::chrono::milliseconds(1000));
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

	uv_mutex_t m_lock;
	std::map<std::string, int32_t> m_jobs;
};

BackgroundJobTracker::BackgroundJobTracker() : m_impl(new Impl())
{
}

BackgroundJobTracker::~BackgroundJobTracker()
{
	delete m_impl;
}

void BackgroundJobTracker::start(const char* name)
{
	m_impl->start(name);
}

void BackgroundJobTracker::stop(const char* name)
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
thread_local bool is_main_thread = false;

} // namespace p2pool
