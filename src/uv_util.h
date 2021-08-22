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

#pragma once

#include <uv.h>

namespace p2pool {

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

void uv_mutex_init_checked(uv_mutex_t* mutex);
void uv_rwlock_init_checked(uv_rwlock_t* lock);

} // namespace p2pool
