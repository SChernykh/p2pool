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

#pragma once

#include <uv.h>

static_assert(sizeof(in6_addr) == 16, "struct in6_addr has invalid size");
static_assert(sizeof(in_addr) == 4, "struct in_addr has invalid size");

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
uv_loop_t* uv_default_loop_checked();

struct UV_LoopCallbackBase
{
	virtual ~UV_LoopCallbackBase() {}
	virtual void operator()() = 0;
};

template<typename T>
struct UV_LoopCallback : public UV_LoopCallbackBase
{
	explicit FORCEINLINE UV_LoopCallback(T&& cb) : m_cb(std::move(cb)) {}
	void operator()() override { m_cb(); }

private:
	UV_LoopCallback& operator=(UV_LoopCallback&&) = delete;
	T m_cb;
};

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
		uv_async_init(m_loop, m_async, async_cb);
		m_async->data = this;

		uv_mutex_init_checked(&m_callbacksLock);

		m_callbacks.reserve(2);
		m_callbacksToRun.reserve(2);
	}

	~UV_LoopUserData()
	{
		m_loop->data = nullptr;
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

template<typename T>
void CallOnLoop(uv_loop_t* loop, T&& callback)
{
	UV_LoopUserData* data = GetLoopUserData(loop);

	UV_LoopCallbackBase* cb = new UV_LoopCallback<T>(std::move(callback));
	{
		MutexLock lock(data->m_callbacksLock);
		data->m_callbacks.push_back(cb);
	}

	uv_async_send(data->m_async);
}

} // namespace p2pool
