/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2025 SChernykh <https://github.com/SChernykh>
 * Portions Copyright (c) 2012-2013 The Cryptonote developers
 * Portions Copyright (c) 2014-2021 The Monero Project
 * Portions Copyright (c) 2021 XMRig <https://github.com/xmrig>
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
#include "wallet.h"
#include "keccak.h"
#include "crypto.h"

extern "C" {
#include "crypto-ops.h"
}

namespace {

// Allow only regular addresses (no integrated addresses, no subaddresses)
// Values taken from cryptonote_config.h (CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX)
constexpr uint64_t valid_prefixes[] = { 18, 53, 24 };

constexpr std::array<int, 9> block_sizes{ 0, 2, 3, 5, 6, 7, 9, 10, 11 };
constexpr int num_full_blocks = p2pool::Wallet::ADDRESS_LENGTH / block_sizes.back();
constexpr int last_block_size = p2pool::Wallet::ADDRESS_LENGTH % block_sizes.back();

constexpr int block_sizes_lookup[11] = { 0, -1, 1, 2, -1, 3, 4, 5, -1, 6, 7 };

constexpr char alphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
constexpr size_t alphabet_size = sizeof(alphabet) - 1;

static_assert(alphabet_size == 58, "Check alphabet");

struct ReverseAlphabet
{
	int8_t data[256];
	int num_symbols;

	static constexpr ReverseAlphabet init()
	{
		ReverseAlphabet result = {};

		for (int i = 0; i < 256; ++i) {
			result.data[i] = -1;
		}

		result.num_symbols = 0;
		for (size_t i = 0; i < alphabet_size; ++i) {
			if (result.data[static_cast<int>(alphabet[i])] < 0) {
				result.data[static_cast<int>(alphabet[i])] = static_cast<int8_t>(i);
				++result.num_symbols;
			}
		}

		return result;
	}
};

constexpr ReverseAlphabet rev_alphabet = ReverseAlphabet::init();

static_assert(rev_alphabet.num_symbols == 58, "Check alphabet");

}

namespace p2pool {

Wallet::Wallet(const char* address) : m_prefix(0), m_checksum(0), m_type(NetworkType::Invalid)
{
	decode(address);
}

Wallet::Wallet(const Wallet& w)
{
	operator=(w);
}

Wallet& Wallet::operator=(const Wallet& w)
{
	if (this == &w) {
		return *this;
	}

	m_prefix = w.m_prefix;
	m_spendPublicKey = w.m_spendPublicKey;
	m_viewPublicKey = w.m_viewPublicKey;
	m_checksum = w.m_checksum;
	m_type = w.m_type;

	return *this;
}

bool Wallet::decode(const char* address)
{
	m_type = NetworkType::Invalid;

	if (!address || (strlen(address) != ADDRESS_LENGTH)) {
		return false;
	}

	constexpr int last_block_size_index = block_sizes_lookup[last_block_size];

	static_assert(last_block_size_index >= 0, "Check ADDRESS_LENGTH");

	uint8_t data[static_cast<size_t>(num_full_blocks) * sizeof(uint64_t) + last_block_size_index] = {};
	int data_index = 0;

	for (int i = 0; i <= num_full_blocks; ++i) {
		uint64_t num = 0;
		uint64_t order = 1;

		for (int j = ((i < num_full_blocks) ? block_sizes.back() : last_block_size) - 1; j >= 0; --j) {
			const int digit = rev_alphabet.data[static_cast<int>(address[j])];
			if (digit < 0) {
				return false;
			}

			uint64_t hi;
			const uint64_t tmp = num + umul128(order, static_cast<uint64_t>(digit), &hi);
			if ((tmp < num) || hi) {
				return false;
			}

			num = tmp;
			order *= alphabet_size;
		}

		address += block_sizes.back();

		for (int j = ((i < num_full_blocks) ? sizeof(num) : last_block_size_index) - 1; j >= 0; --j) {
			data[data_index++] = static_cast<uint8_t>(num >> (j * 8));
		}
	}

	m_prefix = data[0];

	switch (m_prefix)
	{
	case valid_prefixes[0]: m_type = NetworkType::Mainnet;  break;
	case valid_prefixes[1]: m_type = NetworkType::Testnet;  break;
	case valid_prefixes[2]: m_type = NetworkType::Stagenet; break;

	default:
		return false;
	}

	memcpy(m_spendPublicKey.h, data + 1, HASH_SIZE);
	memcpy(m_viewPublicKey.h, data + 1 + HASH_SIZE, HASH_SIZE);
	memcpy(&m_checksum, data + 1 + HASH_SIZE * 2, sizeof(m_checksum));

	uint8_t md[200];
	keccak(data, sizeof(data) - sizeof(m_checksum), md);

	if (memcmp(&m_checksum, md, sizeof(m_checksum)) != 0) {
		m_type = NetworkType::Invalid;
	}

	ge_p3 point;
	if ((ge_frombytes_vartime(&point, m_spendPublicKey.h) != 0) || (ge_frombytes_vartime(&point, m_viewPublicKey.h) != 0)) {
		m_type = NetworkType::Invalid;
	}

	return valid();
}

bool Wallet::assign(const hash& spend_pub_key, const hash& view_pub_key, NetworkType type)
{
	ge_p3 point;
	if ((ge_frombytes_vartime(&point, spend_pub_key.h) != 0) || (ge_frombytes_vartime(&point, view_pub_key.h) != 0)) {
		return false;
	}

	switch (type)
	{
	case NetworkType::Mainnet:  m_prefix = valid_prefixes[0]; break;
	case NetworkType::Testnet:  m_prefix = valid_prefixes[1]; break;
	case NetworkType::Stagenet: m_prefix = valid_prefixes[2]; break;
	default:                    m_prefix = 0;                 break;
	}

	m_spendPublicKey = spend_pub_key;
	m_viewPublicKey = view_pub_key;

	uint8_t data[1 + HASH_SIZE * 2];
	data[0] = static_cast<uint8_t>(m_prefix);
	memcpy(data + 1, spend_pub_key.h, HASH_SIZE);
	memcpy(data + 1 + HASH_SIZE, view_pub_key.h, HASH_SIZE);

	uint8_t md[200];
	keccak(data, sizeof(data), md);

	memcpy(&m_checksum, md, sizeof(m_checksum));

	m_type = type;

	return true;
}

void Wallet::encode(char (&buf)[ADDRESS_LENGTH]) const
{
	uint8_t data[1 + HASH_SIZE * 2 + sizeof(m_checksum)];

	data[0] = static_cast<uint8_t>(m_prefix);
	memcpy(data + 1, m_spendPublicKey.h, HASH_SIZE);
	memcpy(data + 1 + HASH_SIZE, m_viewPublicKey.h, HASH_SIZE);
	memcpy(data + 1 + HASH_SIZE * 2, &m_checksum, sizeof(m_checksum));

	for (int i = 0; i <= num_full_blocks; ++i) {
		uint64_t n = 0;
		for (int j = 0; (j < 8) && (i * sizeof(uint64_t) + j < sizeof(data)); ++j) {
			n = (n << 8) | data[i * sizeof(uint64_t) + j];
		}
		for (int j = ((i < num_full_blocks) ? block_sizes.back() : last_block_size) - 1; j >= 0; --j) {
			const int digit = n % alphabet_size;
			n /= alphabet_size;
			buf[i * block_sizes.back() + j] = alphabet[digit];
		}
	}
}

bool Wallet::get_eph_public_key(const hash& txkey_sec, size_t output_index, hash& eph_public_key, uint8_t& view_tag, const uint8_t* expected_view_tag) const
{
	hash derivation;
	if (!generate_key_derivation(m_viewPublicKey, txkey_sec, output_index, derivation, view_tag)) {
		return false;
	}

	if (expected_view_tag && (view_tag != *expected_view_tag)) {
		return false;
	}

	if (!derive_public_key(derivation, output_index, m_spendPublicKey, eph_public_key)) {
		return false;
	}

	return true;
}

} // namespace p2pool
