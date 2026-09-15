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

namespace p2pool {

struct PPLNSWindow;
class Wallet;

static constexpr uint64_t PAYOUT_GRID_STEP = 600000000ULL;
static constexpr uint32_t PAYOUT_EVALS = 3;

// Rounds an exact proportional reward split to whole multiples of PAYOUT_GRID_STEP.
//
// On input, "wallets" and "rewards" hold the exact split. On output, only the wallets
// with a non-zero payout are left, in the same relative order.
[[nodiscard]] bool quantize_rewards(
	const PPLNSWindow& window,
	uint64_t reward,
	std::vector<const Wallet*>& wallets,
	std::vector<uint64_t>& rewards
);

} // namespace p2pool
