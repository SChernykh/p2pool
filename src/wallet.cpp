/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2026 SChernykh <https://github.com/SChernykh>
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
#include "coin_config.h"

extern "C" {
#include "crypto-ops.h"
}

#include "fcmp_pp_crypto.h"

LOG_CATEGORY(Wallet)

namespace {

// Kryptokrona public address prefixes (varints). Both encode the same keys;
// the daemon accepts either. There are no sub/integrated addresses here, and
// the same prefix is used on every network (mainnet/testnet).
constexpr uint64_t valid_prefixes[] = { p2pool::coin::ADDRESS_PREFIX_SEKR, p2pool::coin::ADDRESS_PREFIX_XKR };

constexpr std::array<int, 9> block_sizes{ 0, 2, 3, 5, 6, 7, 9, 10, 11 };

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
			if (result.data[static_cast<uint8_t>(alphabet[i])] < 0) {
				result.data[static_cast<uint8_t>(alphabet[i])] = static_cast<int8_t>(i);
				++result.num_symbols;
			}
		}

		return result;
	}
};

constexpr ReverseAlphabet rev_alphabet = ReverseAlphabet::init();

static_assert(rev_alphabet.num_symbols == 58, "Check alphabet");

} // namespace

namespace p2pool {

Wallet::Wallet(const char* address) : m_prefix(0), m_checksum(0), m_type(NetworkType::Invalid), m_subaddress(false)
{
	if (!decode(address) && address) {
		LOGWARN(1, address << " failed to decode");
	}
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
	m_keys[0] = w.m_keys[0];
	m_keys[1] = w.m_keys[1];
	m_checksum = w.m_checksum;
	m_type = w.m_type;
	m_subaddress = w.m_subaddress;

	return *this;
}

bool Wallet::decode(const char* address)
{
	m_type = NetworkType::Invalid;
	m_subaddress = false;

	if (!address) {
		return false;
	}

	// Kryptokrona addresses are 98 (Xkr) or 99 (SEKR) base58 chars; both encode
	// varint(prefix) + spend_pub(32) + view_pub(32) + checksum(4).
	const size_t addr_len = strlen(address);
	if ((addr_len != 98) && (addr_len != 99)) {
		return false;
	}

	// CryptoNote base58 decode of an arbitrary-length address into bytes.
	const int n_blocks = static_cast<int>(addr_len) / block_sizes.back();
	const int last_chars = static_cast<int>(addr_len) % block_sizes.back();
	const int last_bytes = (last_chars == 0) ? 0 : block_sizes_lookup[last_chars];
	if ((last_chars != 0) && (last_bytes < 0)) {
		return false;
	}

	uint8_t data[9 * sizeof(uint64_t)] = {}; // max 72 bytes (99-char address)
	size_t data_size = 0;

	for (int i = 0; i <= n_blocks; ++i) {
		const int chars = (i < n_blocks) ? block_sizes.back() : last_chars;
		if (chars == 0) {
			break;
		}

		uint64_t num = 0;
		uint64_t order = 1;
		for (int j = chars - 1; j >= 0; --j) {
			const int8_t digit = rev_alphabet.data[static_cast<uint8_t>(address[i * block_sizes.back() + j])];
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

		const int nbytes = (i < n_blocks) ? static_cast<int>(sizeof(uint64_t)) : last_bytes;
		for (int j = nbytes - 1; j >= 0; --j) {
			data[data_size++] = static_cast<uint8_t>(num >> (j * 8));
		}
	}

	// Read the varint prefix.
	uint64_t prefix = 0;
	int shift = 0;
	size_t pos = 0;
	for (;;) {
		if (pos >= data_size) {
			return false;
		}
		const uint8_t c = data[pos++];
		prefix |= static_cast<uint64_t>(c & 0x7f) << shift;
		if ((c & 0x80) == 0) {
			break;
		}
		shift += 7;
		if (shift > 63) {
			return false;
		}
	}
	m_prefix = prefix;

	if ((prefix != valid_prefixes[0]) && (prefix != valid_prefixes[1])) {
		return false;
	}

	// Remaining bytes: spend(32) + view(32) + checksum(4).
	if (data_size != pos + HASH_SIZE * 2 + sizeof(m_checksum)) {
		return false;
	}

	memcpy(m_keys[0].h, data + pos, HASH_SIZE);
	memcpy(m_keys[1].h, data + pos + HASH_SIZE, HASH_SIZE);
	memcpy(&m_checksum, data + pos + HASH_SIZE * 2, sizeof(m_checksum));

	// checksum = first 4 bytes of keccak(varint(prefix) + spend + view).
	hash md;
	keccak(data, static_cast<int>(pos + HASH_SIZE * 2), md.h);
	if (memcmp(&m_checksum, md.h, sizeof(m_checksum)) != 0) {
		return false;
	}

	ge_p3 point;
	if ((ge_frombytes_vartime(&point, m_keys[0].h) != 0) || (ge_frombytes_vartime(&point, m_keys[1].h) != 0)) {
		return false;
	}

	// Kryptokrona uses one address prefix for all networks; treat a valid
	// address as belonging to whatever network the pool is running on.
	m_type = NetworkType::Mainnet;

	return valid();
}

bool Wallet::assign(const hash& spend_pub_key, const hash& view_pub_key, NetworkType type, bool /*subaddress*/)
{
	ge_p3 point;
	if ((ge_frombytes_vartime(&point, spend_pub_key.h) != 0) || (ge_frombytes_vartime(&point, view_pub_key.h) != 0)) {
		return false;
	}

	// Kryptokrona uses one prefix for every network; ignore `subaddress` (no
	// subaddresses) and always assign the canonical SEKR prefix.
	m_prefix = coin::ADDRESS_PREFIX_DEFAULT;
	m_subaddress = false;

	m_keys[0] = spend_pub_key;
	m_keys[1] = view_pub_key;

	// data = varint(prefix) + spend + view (checksum is over this)
	uint8_t data[10 + HASH_SIZE * 2];
	size_t n = 0;
	for (uint64_t p = m_prefix; p >= 0x80; p >>= 7) { data[n++] = static_cast<uint8_t>(p & 0x7f) | 0x80; }
	data[n] = static_cast<uint8_t>(m_prefix >> (7 * n)); ++n;
	memcpy(data + n, spend_pub_key.h, HASH_SIZE);
	memcpy(data + n + HASH_SIZE, view_pub_key.h, HASH_SIZE);

	hash md;
	keccak(data, static_cast<int>(n + HASH_SIZE * 2), md.h);
	memcpy(&m_checksum, md.h, sizeof(m_checksum));

	m_type = type;

	return true;
}

int Wallet::encode(char (&buf)[ADDRESS_LENGTH]) const
{
	// Emit the wallet's own prefix so both address formats round-trip exactly:
	// SEKR (4-byte prefix varint) -> 99 chars, Xkr (3-byte prefix) -> 98 chars.
	// Layout: varint(prefix) + spend + view + checksum. Returns the number of
	// base58 characters actually written (<= ADDRESS_LENGTH).
	uint8_t data[10 + HASH_SIZE * 2 + sizeof(m_checksum)] = {};
	size_t n = 0;
	for (uint64_t p = m_prefix; p >= 0x80; p >>= 7) { data[n++] = static_cast<uint8_t>(p & 0x7f) | 0x80; }
	data[n] = static_cast<uint8_t>(m_prefix >> (7 * n)); ++n;
	memcpy(data + n, m_keys[0].h, HASH_SIZE);
	memcpy(data + n + HASH_SIZE, m_keys[1].h, HASH_SIZE);
	// Recompute the checksum for the prefix we emit. The stored m_checksum is
	// prefix-specific; recomputing keeps encode() correct for any m_prefix and
	// makes decode()->encode() a bit-exact round-trip for both SEKR and Xkr.
	hash cs;
	keccak(data, static_cast<int>(n + HASH_SIZE * 2), cs.h);
	memcpy(data + n + HASH_SIZE * 2, cs.h, sizeof(m_checksum));
	const int data_size = static_cast<int>(n + HASH_SIZE * 2 + sizeof(m_checksum));

	const int nblk = data_size / static_cast<int>(sizeof(uint64_t));
	for (int i = 0; i <= nblk; ++i) {
		const int nbytes = (i < nblk) ? static_cast<int>(sizeof(uint64_t)) : (data_size % static_cast<int>(sizeof(uint64_t)));
		if (nbytes == 0) {
			break;
		}
		uint64_t num = 0;
		for (int j = 0; j < nbytes; ++j) {
			num = (num << 8) | data[i * sizeof(uint64_t) + j];
		}
		const int chars = (i < nblk) ? block_sizes.back() : block_sizes[nbytes];
		for (int j = chars - 1; j >= 0; --j) {
			buf[i * block_sizes.back() + j] = alphabet[num % alphabet_size];
			num /= alphabet_size;
		}
	}

	const int rem = data_size % static_cast<int>(sizeof(uint64_t));
	return nblk * block_sizes.back() + (rem ? block_sizes[rem] : 0);
}

bool Wallet::get_eph_public_key(const hash& txkey_sec, size_t output_index, hash& eph_public_key, uint8_t& view_tag, const uint8_t* expected_view_tag) const
{
	hash derivation;
	if (!generate_key_derivation(m_keys[1], txkey_sec, output_index, derivation, view_tag)) {
		return false;
	}

	if (expected_view_tag && (view_tag != *expected_view_tag)) {
		return false;
	}

	if (!derive_public_key(derivation, output_index, m_keys[0], eph_public_key)) {
		return false;
	}

	return true;
}

bool Wallet::torsion_check() const
{
	ge_p3 p1, p2;
	if ((ge_frombytes_vartime(&p1, m_keys[0].h) != 0) || (ge_frombytes_vartime(&p2, m_keys[1].h) != 0)) {
		return false;
	}

	return
		!fcmp_pp::mul8_is_identity(p1) &&
		!fcmp_pp::mul8_is_identity(p2) &&
		fcmp_pp::torsion_check_vartime(p1) &&
		fcmp_pp::torsion_check_vartime(p2);
}

} // namespace p2pool
