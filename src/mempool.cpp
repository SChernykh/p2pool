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
#include "mempool.h"
#include "util.h"

static constexpr char log_category_prefix[] = "Mempool ";

namespace p2pool {

Mempool::Mempool(p2pool* pool)
	: m_pool(pool)
{
	uv_rwlock_init_checked(&m_lock);
}

Mempool::~Mempool()
{
	uv_rwlock_destroy(&m_lock);
}

void Mempool::add(const TxMempoolData& tx)
{
	WriteLock lock(m_lock);

	for (const TxMempoolData& old_tx : m_transactions) {
		if (old_tx.id == tx.id) {
			LOGWARN(1, "duplicate transaction with id = " << tx.id << ", skipped");
			return;
		}
	}

	m_transactions.push_back(tx);
}

void Mempool::swap(std::vector<TxMempoolData>& transactions)
{
	WriteLock lock(m_lock);
	m_transactions.swap(transactions);
}

} // namespace p2pool
