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

#include "uv_util.h"

namespace p2pool {

class Wallet
{
public:
	// Kryptokrona addresses use a multi-byte VARINT base58 prefix, unlike
	// Monero's single byte. The default SEKR prefix (2239254) is a 4-byte
	// varint => 4 + 64 keys + 4 checksum = 72 bytes => 99 base58 chars (exactly
	// 9 full CryptoNote blocks). The Xkr prefix (45239) is a 3-byte varint =>
	// 98 chars. encode() emits the wallet's own prefix (so both forms round-trip)
	// and returns the actual length; ADDRESS_LENGTH is the buffer size (the
	// longest, SEKR, form). decode() accepts both lengths.
	static constexpr int ADDRESS_LENGTH = 99;

	explicit Wallet(const char* address);

	Wallet(const Wallet& w);
	Wallet& operator=(const Wallet& w);

	[[nodiscard]] FORCEINLINE bool valid() const { return m_type != NetworkType::Invalid; }

	[[nodiscard]] bool decode(const char* address);
	[[nodiscard]] bool assign(const hash& spend_pub_key, const hash& view_pub_key, NetworkType type, bool subaddress);

	// Writes the address into buf and returns the number of characters written
	// (99 for a SEKR-prefix wallet, 98 for an Xkr-prefix one). buf is sized for
	// the longest (SEKR) form; callers must use the returned length, not
	// ADDRESS_LENGTH.
	int encode(char (&buf)[ADDRESS_LENGTH]) const;

	[[nodiscard]] FORCEINLINE std::string encode() const
	{
		char buf[ADDRESS_LENGTH];
		const int len = encode(buf);
		return std::string(buf, buf + len);
	}

	[[nodiscard]] bool get_eph_public_key(const hash& txkey_sec, size_t output_index, hash& eph_public_key, uint8_t& view_tag, const uint8_t* expected_view_tag = nullptr) const;

	FORCEINLINE bool operator<(const Wallet& w) const { return (m_keys[0] < w.m_keys[0]) || ((m_keys[0] == w.m_keys[0]) && (m_keys[1] < w.m_keys[1])); }
	FORCEINLINE bool operator==(const Wallet& w) const { return (m_keys[0] == w.m_keys[0]) && (m_keys[1] == w.m_keys[1]); }

	[[nodiscard]] FORCEINLINE uint64_t prefix() const { return m_prefix; }
	[[nodiscard]] FORCEINLINE const hash* keys() const { return m_keys; }
	[[nodiscard]] FORCEINLINE const hash& spend_public_key() const { return m_keys[0]; }
	[[nodiscard]] FORCEINLINE const hash& view_public_key() const { return m_keys[1]; }
	[[nodiscard]] FORCEINLINE uint32_t checksum() const { return m_checksum; }
	[[nodiscard]] FORCEINLINE NetworkType get_type() const { return m_type; }
	[[nodiscard]] FORCEINLINE bool is_subaddress() const { return m_subaddress; }
	[[nodiscard]] bool torsion_check() const;

private:
	uint64_t m_prefix;

	hash m_keys[2];

	// Make sure it's safe to memcpy/pass to plain C dode
	static_assert(std::is_standard_layout_v<decltype(m_keys)> && (sizeof(m_keys) == HASH_SIZE * 2));

	uint32_t m_checksum;
	NetworkType m_type;
	bool m_subaddress;
};

} // namespace p2pool
