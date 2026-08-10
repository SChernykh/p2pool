// Copyright (c) 2014-2022, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifdef _MSC_VER
#pragma warning(disable : 4514 4820)
#endif

#include "hardforks.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "blockchain.hardforks"

// Kryptokrona (XKR) block-major-version schedule.
//
// These tables replace Monero's. SideChain::network_major_version() walks them
// (using .version / .height only) and the pool-block parser rejects any received
// block whose major version doesn't match the expected one for its Kryptokrona
// mainchain height (pool_block_parser.inl). The values here MUST agree with the
// kryptokronad daemon's block major_version, which is derived from the
// UPGRADE_HEIGHT_V* constants in kryptokrona src/config/cryptonote_config.h:
//   mainnet: V2 @ height 1, V3 @ 2, V4 @ 3, V5 @ 4 (CN-Turtle v2); capped at V5.
// The daemon never emits a major version above 5, so neither may this table,
// otherwise every relayed block is rejected with parser error 121.
const hardfork_t mainnet_hard_forks[] = {
  { 1, 0, 0, 1541895000 }, // genesis
  { 2, 1, 0, 1541895001 },
  { 3, 2, 0, 1541895002 },
  { 4, 3, 0, 1541895003 }, // CN-Lite Variant 1
  { 5, 4, 0, 1541895004 }, // CN-Turtle Variant 2 (current)
};
const size_t num_mainnet_hard_forks = sizeof(mainnet_hard_forks) / sizeof(mainnet_hard_forks[0]);
const uint64_t mainnet_hard_fork_version_1_till = 0;

// Testnet starts directly on V5 from height 1 (UPGRADE_HEIGHT_V* = 0 in the
// daemon config), so every mined block is major version 5.
const hardfork_t testnet_hard_forks[] = {
  { 1, 0, 0, 1541895000 }, // genesis
  { 5, 1, 0, 1541895001 },
};
const size_t num_testnet_hard_forks = sizeof(testnet_hard_forks) / sizeof(testnet_hard_forks[0]);
const uint64_t testnet_hard_fork_version_1_till = 0;

// Stagenet mirrors mainnet's ramp.
const hardfork_t stagenet_hard_forks[] = {
  { 1, 0, 0, 1541895000 },
  { 2, 1, 0, 1541895001 },
  { 3, 2, 0, 1541895002 },
  { 4, 3, 0, 1541895003 },
  { 5, 4, 0, 1541895004 },
};
const size_t num_stagenet_hard_forks = sizeof(stagenet_hard_forks) / sizeof(stagenet_hard_forks[0]);
