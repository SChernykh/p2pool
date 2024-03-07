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

#pragma once

#include "uv_util.h"

namespace p2pool {

constexpr uint64_t HIGH_FEE_VALUE = 6000000000ULL;

class p2pool;

class Mempool : public nocopy_nomove
{
public:
	Mempool();
	~Mempool();

	void add(const TxMempoolData& tx);
	void swap(std::vector<TxMempoolData>& transactions);

	size_t size() const
	{
		ReadLock lock(m_lock);
		return m_transactions.size();
	}

	template<typename T>
	void iterate(T&& callback) const
	{
		ReadLock lock(m_lock);

		for (const auto& it : m_transactions) {
			callback(it.first, it.second);
		}
	}

private:
	mutable uv_rwlock_t m_lock;
	unordered_map<hash, TxMempoolData> m_transactions;
};

} // namespace p2pool
