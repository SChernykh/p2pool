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

class Wallet
{
public:
	// public keys: 64 bytes -> 88 characters in base58
	// prefix (1 byte) + checksum (4 bytes) -> 7 characters in base58
	// 95 characters in total
	static constexpr int ADDRESS_LENGTH = 95;

	explicit Wallet(const char* address);

	Wallet(const Wallet& w);
	Wallet& operator=(const Wallet& w);

	FORCEINLINE bool valid() const { return m_type != NetworkType::Invalid; }

	bool decode(const char* address);
	bool assign(const hash& spend_pub_key, const hash& view_pub_key, NetworkType type);

	void encode(char (&buf)[ADDRESS_LENGTH]) const;

	FORCEINLINE std::string encode() const
	{
		char buf[ADDRESS_LENGTH];
		encode(buf);
		return std::string(buf, buf + ADDRESS_LENGTH);
	}

	bool get_eph_public_key(const hash& txkey_sec, size_t output_index, hash& eph_public_key, uint8_t& view_tag, const uint8_t* expected_view_tag = nullptr) const;

	FORCEINLINE bool operator<(const Wallet& w) const { return (m_spendPublicKey < w.m_spendPublicKey) || ((m_spendPublicKey == w.m_spendPublicKey) && (m_viewPublicKey < w.m_viewPublicKey)); }
	FORCEINLINE bool operator==(const Wallet& w) const { return (m_spendPublicKey == w.m_spendPublicKey) && (m_viewPublicKey == w.m_viewPublicKey); }

	FORCEINLINE uint64_t prefix() const { return m_prefix; }
	FORCEINLINE const hash& spend_public_key() const { return m_spendPublicKey; }
	FORCEINLINE const hash& view_public_key() const { return m_viewPublicKey; }
	FORCEINLINE uint32_t checksum() const { return m_checksum; }
	FORCEINLINE NetworkType type() const { return m_type; }

private:
	uint64_t m_prefix;
	hash m_spendPublicKey;
	hash m_viewPublicKey;
	uint32_t m_checksum;
	NetworkType m_type;
};

} // namespace p2pool
