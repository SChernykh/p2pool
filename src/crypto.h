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

#pragma once

namespace p2pool {

void generate_keys(hash& pub, hash& sec);
bool check_keys(const hash& pub, const hash& sec);
bool generate_key_derivation(const hash& key1, const hash& key2, size_t output_index, hash& derivation, uint8_t& view_tag);
bool derive_public_key(const hash& derivation, size_t output_index, const hash& base, hash& derived_key);
void derive_view_tag(const hash& derivation, size_t output_index, uint8_t& view_tag);

void init_crypto_cache();
void destroy_crypto_cache();
void clear_crypto_cache();

} // namespace p2pool
