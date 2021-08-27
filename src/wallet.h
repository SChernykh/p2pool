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

#include "uv_util.h"

namespace p2pool {

class Wallet
{
public:
	explicit Wallet(const char* address);
	~Wallet();

	Wallet(const Wallet& w);
	Wallet& operator=(const Wallet& w);

	FORCEINLINE bool valid() const { return m_type != NetworkType::Invalid; }
	FORCEINLINE NetworkType type() const { return m_type; }

	bool decode(const char* address);
	void assign(const hash& spend_pub_key, const hash& view_pub_key);

	FORCEINLINE const hash& spend_public_key() const { return m_spendPublicKey; }
	FORCEINLINE const hash& view_public_key() const { return m_viewPublicKey; }

	void get_eph_public_key(const hash& txkey_sec, size_t output_index, hash& eph_public_key);

	FORCEINLINE bool operator<(const Wallet& w) const { return m_spendPublicKey < w.m_spendPublicKey; }
	FORCEINLINE bool operator==(const Wallet& w) const { return m_spendPublicKey == w.m_spendPublicKey; }

private:
	uint64_t m_prefix;
	hash m_spendPublicKey;
	hash m_viewPublicKey;
	uint32_t m_checksum;
	NetworkType m_type;

	mutable uv_mutex_t m_lock;
	hash m_txkeySec;
	size_t m_outputIndex;
	hash m_derivation;
	hash m_ephPublicKey;
};

} // namespace p2pool
