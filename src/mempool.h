/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2023 SChernykh <https://github.com/SChernykh>
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

public:
	mutable uv_rwlock_t m_lock;
	unordered_map<hash, TxMempoolData> m_transactions;
};

} // namespace p2pool
