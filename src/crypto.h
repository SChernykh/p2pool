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

extern "C" {
#include "crypto-ops.h"
}

namespace p2pool {

struct batch_public_key_input
{
	FORCEINLINE batch_public_key_input(const hash& d, size_t i, const hash& b) : derivation(d), output_index(i), base(b) {}

	hash derivation;
	size_t output_index;
	hash base;
};

// h = a * G and h = a * G + b * T (T is the FCMP++ generator), with the tables init_crypto_cache() builds. Pre-conditions: a[31] <= 127, b[31] <= 127
void ge_scalarmult_base_vartime(ge_p3* h, const uint8_t* a);
void ge_double_scalarmult_base_T_vartime(ge_p3* h, const uint8_t* a, const uint8_t* b);

void generate_keys_deterministic(hash& pub, hash& sec, const uint8_t* entropy, size_t len);
void get_tx_keys(hash& pub, hash& sec, const hash& seed, const hash& monero_block_id);
bool check_keys(const hash& pub, const hash& sec);
bool is_in_main_subgroup(const ge_p3& point);

bool check_public_key(const hash& key);
bool generate_key_derivation(const hash& key1, const hash& key2, size_t output_index, hash& derivation, uint8_t& view_tag);
bool batch_derivations(const std::vector<std::pair<hash, size_t>>& in, const hash& txkey_sec, std::vector<std::pair<hash, int32_t>>& out);
bool derive_public_key(const hash& derivation, size_t output_index, const hash& base, hash& derived_key);
bool batch_public_keys(const std::vector<batch_public_key_input>& in, std::vector<std::pair<hash, bool>>& out);
void derive_view_tag(const hash& derivation, size_t output_index, uint8_t& view_tag);

void init_crypto_cache();
void destroy_crypto_cache();
void clear_crypto_cache(uint64_t timestamp = 0);

// How many Carrot coinbase outputs (different amounts) the cache keeps for one wallet at one Monero height.
// When it's full, a new amount replaces the oldest one
constexpr size_t MAX_COINBASE_OUTPUTS_PER_WALLET = 32;

#ifdef P2POOL_UNIT_TESTS
size_t get_last_coinbase_secrets_batch_size();
size_t get_last_coinbase_output_batch_size();
uint32_t get_from_bytes_cache_state(const hash& public_key);
#endif

} // namespace p2pool
