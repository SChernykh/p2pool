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

// -----------------------------------------------------------------------------
//  Kryptokrona (XKR) coin configuration
// -----------------------------------------------------------------------------
//
// P2Pool was originally written exclusively for Monero. This header centralizes
// every coin-defining constant so the rest of the code can be ported to
// Kryptokrona (a CryptoNote / TurtleCoin-family coin) without Monero magic
// numbers scattered across the tree.
//
// Values mirror kryptokrona's src/config/cryptonote_config.h. Where Monero and
// Kryptokrona diverge, the Monero value is kept in a comment for reference.
//
// NOTE ON NETWORKS: unlike Monero (which uses distinct address prefixes for
// mainnet / testnet / stagenet), Kryptokrona uses the *same* base58 address
// prefix on every network. Only the daemon RPC/P2P ports differ. The port
// defaults here follow kryptokrona's USE_TESTNET compile switch so a p2pool
// built for testnet talks to a testnet daemon out of the box.

#include <cstddef>
#include <cstdint>

namespace p2pool {
namespace coin {

// Human-readable identity
static constexpr char COIN_NAME[]   = "kryptokrona";
static constexpr char COIN_TICKER[] = "XKR";

// Atomic units. Kryptokrona uses 5 decimal places (Monero uses 12).
//   1 XKR = 100000 atomic units
static constexpr int      DISPLAY_DECIMAL_POINT = 5;   // Monero: 12
static constexpr uint64_t ATOMIC_UNITS          = 100000ULL; // 10^DISPLAY_DECIMAL_POINT

// Target main-chain block time in seconds (kryptokrona DIFFICULTY_TARGET).
// P2Pool historically called this MONERO_BLOCK_TIME (120). Kryptokrona = 90.
static constexpr uint64_t MAIN_CHAIN_BLOCK_TIME = 90;  // Monero: 120

// Base58 public address prefixes. Both encode the SAME keys; the daemon accepts
// either on decode. SEKR is the historical default, Xkr the newer alt prefix.
//   - CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX      = 2239254 -> "SEKR..."
//   - CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX_ALT  =   45239 -> "Xkr..."
static constexpr uint64_t ADDRESS_PREFIX_SEKR = 2239254ULL;
static constexpr uint64_t ADDRESS_PREFIX_XKR  = 45239ULL;
// Which prefix we emit when *encoding* an address for display.
static constexpr uint64_t ADDRESS_PREFIX_DEFAULT = ADDRESS_PREFIX_SEKR;

// Emission / supply (kryptokrona parameters).
static constexpr uint64_t MONEY_SUPPLY          = UINT64_C(100000000000000);
static constexpr unsigned EMISSION_SPEED_FACTOR = 21;
static constexpr uint64_t GENESIS_BLOCK_REWARD  = UINT64_C(0);

// Fees / dust
static constexpr uint64_t MINIMUM_FEE = UINT64_C(10);

// Coinbase / block layout
static constexpr uint64_t COINBASE_BLOB_RESERVED_SIZE = 600;
static constexpr uint64_t MAX_BLOCK_NUMBER            = 500000000ULL;

// tx_extra size limits (kryptokrona splits pool vs block budgets).
static constexpr uint64_t MAX_EXTRA_SIZE_BLOCK = 128;  // excludes Hugin messages
static constexpr uint64_t MAX_EXTRA_SIZE_POOL  = 2200;

// Reward-window / difficulty (informational; consensus lives on the daemon).
static constexpr size_t   REWARD_BLOCKS_WINDOW = 100;

// Coinbase / block serialization (CryptoNote, differs from Monero):
//   - coinbase transaction version is 1 (Monero uses 2)
//   - outputs use TXOUT_TO_KEY tag 0x02 with NO view tag (Monero: 0x03 tagged
//     key + 1 view-tag byte)
//   - there is NO trailing RingCT type byte (Monero appends 0x00)
static constexpr uint8_t  COINBASE_TX_VERSION = 1;
static constexpr uint8_t  TXOUT_TO_KEY        = 2;
// Coinbase unlock window: coinbase.unlock_time = height + this. Kryptokrona uses
// CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW = 20 on mainnet, 1 on testnet. Selected
// at runtime by SideChain::network_type() since p2pool has no compile switch.
static constexpr uint64_t MINED_MONEY_UNLOCK_WINDOW_MAINNET = 20;
static constexpr uint64_t MINED_MONEY_UNLOCK_WINDOW_TESTNET = 1;
// Merge-mining tag depth for the (self-referential) parent block. Always 0:
// there is a single aux chain (the block itself), no branch.
static constexpr uint8_t  PARENT_MM_TAG_DEPTH = 0;

// Default kryptokrona daemon RPC port that p2pool talks to via JSON-RPC.
// Kryptokrona: mainnet RPC 11898, testnet RPC 11899 (P2P is 11897 / 11898).
#ifdef USE_TESTNET
static constexpr int DEFAULT_DAEMON_RPC_PORT = 11899;
#else
static constexpr int DEFAULT_DAEMON_RPC_PORT = 11898;
#endif

// Rough approximate block reward used only for local sanity / weighting
// fallbacks (the authoritative reward always comes from getblocktemplate).
// Emission at genesis is MONEY_SUPPLY >> EMISSION_SPEED_FACTOR atomic units.
static constexpr uint64_t APPROX_BASE_BLOCK_REWARD = MONEY_SUPPLY >> EMISSION_SPEED_FACTOR;

} // namespace coin
} // namespace p2pool
