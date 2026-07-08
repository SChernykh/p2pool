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

namespace p2pool {

void thread_pool_init();
void thread_pool_destroy();

void queue_work_base(std::shared_ptr<Callback<void>::Base>&& callback, uint32_t N);

// Calls the callback N times on N threads in parallel
// Doesn't wait, returns immediately
template<typename T>
FORCEINLINE void queue_work(T&& callback, uint32_t N)
{
	static_assert(!std::is_lvalue_reference_v<T>, "queue_work() requires an rvalue callback; use std::move or pass a temporary lambda");
	queue_work_base(std::make_shared<Callback<void>::Derived<std::decay_t<T>>>(std::forward<T>(callback)), N);
}

} // namespace p2pool
