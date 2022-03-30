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

#include "common.h"
#include "mempool.h"
#include "util.h"

static constexpr char log_category_prefix[] = "Mempool ";

namespace p2pool {

Mempool::Mempool()
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

	if (!m_transactions.emplace(tx.id, tx).second) {
		LOGWARN(1, "duplicate transaction with id = " << tx.id << ", skipped");
	}
}

void Mempool::swap(std::vector<TxMempoolData>& transactions)
{
	const uint64_t cur_time = seconds_since_epoch();

	WriteLock lock(m_lock);

	// Initialize time_received for all transactions
	for (TxMempoolData& data : transactions) {
		auto it = m_transactions.find(data.id);
		if (it != m_transactions.end()) {
			data.time_received = it->second.time_received;
		}
		else {
			data.time_received = cur_time;
		}
	}

	m_transactions.clear();

	for (TxMempoolData& data : transactions) {
		m_transactions.emplace(data.id, data);
	}
}

} // namespace p2pool
