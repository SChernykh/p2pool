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

#ifndef _WIN32
#include <sched.h>
#endif

static constexpr char log_category_prefix[] = "Util ";

namespace p2pool {

std::atomic<int32_t> num_running_jobs{ 0 };

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
#else
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

} // namespace p2pool
