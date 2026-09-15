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

#include "common.h"
#include "fp64.h"
#include "side_chain.h"
#include "wallet.h"
#include "quantize_rewards.h"

#include "RandomX/src/cpu.hpp"
#include "blake2/blake2.h"
#include "soft_aes.h"

#include <numeric>

LOG_CATEGORY(QuantizeRewards)

namespace p2pool {

constexpr uint64_t T = PAYOUT_GRID_STEP;

#if HAVE_AES
static const bool s_hardwareAes = randomx::Cpu().hasAes();
[[nodiscard]] static FORCEINLINE rx_vec_i128 aes_round(rx_vec_i128 in, rx_vec_i128 key) { return s_hardwareAes ? aesenc<false>(in, key) : aesenc<true>(in, key); }
#else // HAVE_AES
[[nodiscard]] static FORCEINLINE rx_vec_i128 aes_round(rx_vec_i128 in, rx_vec_i128 key) { return aesenc<true>(in, key); }
#endif // HAVE_AES

// u_i: the wallet's uniform draw on [0, T).
[[nodiscard]] static FORCEINLINE uint64_t uniform(const rx_vec_i128 (&seed)[4], const Wallet& w)
{
	// The wallet's 64-byte spend||view key, as four AES blocks
	rx_vec_i128 key[4];
	memcpy(key, w.keys(), sizeof(key));

	// x is 0 in the first round, so it just takes the first key block
	rx_vec_i128 s = aes_round(key[0], seed[0]);

	for (uint32_t r = 1; r < 4; ++r) {
		s = aes_round(rx_xor_vec_i128(s, key[r]), seed[r]);
	}

	// The first 8 bytes as a little-endian uint64, the only byte order P2Pool builds for
	rx_vec_i128 out;
	rx_store_vec_i128(&out, s);

	uint64_t h;
	memcpy(&h, &out, sizeof(h));

	uint64_t hi;
	umul128(h, T, &hi);

	return hi;
}

bool quantize_rewards(const PPLNSWindow& window, uint64_t reward, std::vector<const Wallet*>& wallets, std::vector<uint64_t>& rewards)
{
	const std::vector<MinerShare>& shares = window.m_shares;
	const size_t n = rewards.size();

	if ((n == 0) || (wallets.size() != n) || (shares.size() != n)) {
		LOGERR(1, "invalid input sizes. Check the code!");
		return false;
	}

	rx_vec_i128 seed[4];
	{
		static constexpr char domain[] = "p2pool payout seed";

		blake2b_state state;
		blake2b_init(&state, sizeof(seed));
		blake2b_update(&state, domain, sizeof(domain) - 1);
		blake2b_update(&state, window.m_powHash.h, HASH_SIZE);
		blake2b_final(&state, reinterpret_cast<uint8_t*>(seed), sizeof(seed));
	}

	// a_i: whole grid steps owed, f_i: the fraction of a step owed on top of them
	std::vector<uint64_t> a(n), f(n), u(n);

	uint64_t F = 0;

	for (size_t i = 0; i < n; ++i) {
		a[i] = rewards[i] / T;
		f[i] = rewards[i] % T;
		u[i] = uniform(seed, *wallets[i]);

		F += f[i];
	}

	const uint64_t M = F / T;   // M: how many wallets round up
	const uint64_t rho = F % T; // rho: the one sub-grid remainder, == reward % T

	std::vector<uint64_t> c(n, 0); // c_i: atomic units deducted from f_i

	std::vector<size_t> big; // B: the wallets that can hold the remainder
	big.reserve(n);

	// V at the uncorrected target, over B and over the rest of the ranking
	u128 W1, DZ;

	for (size_t i = 0; i < n; ++i) {
		if (f[i] == 0) {
			continue;
		}

		const uint64_t V = f[i] * (T - f[i]);

		if (a[i] >= 1) {
			big.emplace_back(i);
			W1 += V;
		}
		else {
			DZ += V;
		}
	}

	const uint64_t rho_T = rho * T;

	if (rho && (W1 > u128(rho_T))) {
		// g0 = f, the uncorrected target
		std::vector<uint64_t> g(f);
		std::vector<fp64> w(big.size());
		std::vector<uint64_t> wq(big.size());

		for (uint32_t eval = 0; eval < PAYOUT_EVALS; ++eval) {
			// V at the current target, over B
			u128 Wg;

			for (const size_t i : big) {
				Wg += g[i] * (T - g[i]);
			}

			if (Wg <= u128(rho_T)) {
				break;
			}

			// V over the whole ranking
			const u128 Vall = Wg + DZ;

			const bool refine = (Wg > u128(rho_T + 2 * T * (T - 1)));

			const fp64 Vallf(Vall);
			const fp64 Wgf(Wg);

			bool any = false;
			int64_t es = 0;

			for (size_t k = 0, cnt = big.size(); k < cnt; ++k) {
				const size_t i = big[k];
				const uint64_t V = g[i] * (T - g[i]);

				// A zero weight stays zero: its target is already fully deducted
				if (V == 0) {
					w[k] = fp64();
					continue;
				}

				fp64 x(V);

				if (refine) {
					const uint64_t gT = g[i] * T;

					// Vall*Wg - (Vall + DZ)*g*T == Vall*(Wg - 2*g*T) + Wg*(g*T)
					x *= fp64(Vallf.mul_wide(fp64(Wg - gT * 2)) + Wgf.mul_wide(fp64(gT)));
				}

				w[k] = x;

				if (!any || (x.exponent() > es)) {
					es = x.exponent();
					any = true;
				}
			}

			if (!any) {
				break;
			}

			u128 W;

			for (size_t k = 0, cnt = big.size(); k < cnt; ++k) {
				wq[k] = w[k].at(es);
				W += wq[k];
			}

			if (W == 0) {
				break;
			}

			u128 cum, acc;

			for (size_t k = 0, cnt = big.size(); k < cnt; ++k) {
				cum += wq[k];

				const u128 next_value = cum * rho / W;
				c[big[k]] = (next_value - acc).lo;
				acc = next_value;
			}

			if (acc != u128(rho)) {
				LOGERR(1, "the deductions didn't sum to rho. Check the code!");
				return false;
			}

			for (size_t i = 0; i < n; ++i) {
				if (c[i] > f[i]) {
					LOGERR(1, "the guards didn't keep c_i <= f_i. Check the code!");
					return false;
				}
				g[i] = f[i] - c[i];
			}
		}
	}

	// f'_i: the corrected target. sum(f'_i) == M*T exactly, or == F if a guard skipped the correction
	std::vector<uint64_t> fp(n);
	std::vector<size_t> order;
	order.reserve(n);

	for (size_t i = 0; i < n; ++i) {
		fp[i] = f[i] - c[i];

		if (fp[i]) {
			order.emplace_back(i);
		}
	}

	if (M && (M >= order.size())) {
		LOGERR(1, "more wallets round up than can be ranked. Check the code!");
		return false;
	}

	// Pareto order sampling (Rosen 1997): rank by
	//
	//     Q_i = (u_i / (T - u_i)) * ((T - f'_i) / f'_i)
	//
	// and let the M smallest round up
	std::sort(order.begin(), order.end(),
		[&u, &fp, &shares](size_t x, size_t y)
		{
			// Q_x < Q_y, cross-multiplied
			const u128 qx = u128(u[x] * (T - fp[x])) * ((T - u[y]) * fp[y]);
			const u128 qy = u128(u[y] * (T - fp[y])) * ((T - u[x]) * fp[x]);

			if (qx != qy) {
				return qx < qy;
			}

			// Ties: weight descending, then the order the shares came in
			if (shares[x].m_weight != shares[y].m_weight) {
				return shares[x].m_weight > shares[y].m_weight;
			}

			return x < y;
		});

	// r_i: the payout, before the remainder
	for (size_t i = 0; i < n; ++i) {
		rewards[i] = a[i] * T;
	}

	for (uint64_t k = 0; k < M; ++k) {
		rewards[order[k]] += T;
	}

	// The remainder goes to the wallet that just missed rounding up, which reaches that position with probability c_i/rho - exactly what came off its target
	if (rho) {
		size_t h = n;

		// The first wallet past the cut that is owed at least one whole step
		for (size_t k = M; k < order.size(); ++k) {
			if (a[order[k]] >= 1) {
				h = order[k];
				break;
			}
		}

		// Every wallet past the cut is sub-grid: a wallet owed an exact multiple of T
		if (h == n) {
			for (size_t i = 0; i < n; ++i) {
				if ((fp[i] == 0) && (a[i] >= 1)) {
					h = i;
					break;
				}
			}
		}

		// The wallet on the other side of the cut
		if (h == n) {
			if (order.empty()) {
				LOGERR(1, "rho > 0 but nothing is ranked. Check the code!");
				return false;
			}
			h = order[M ? (M - 1) : 0];
		}

		rewards[h] += rho;
	}

	// Only the wallets with a non-zero payout get an output
	size_t num_outputs = 0;

	for (size_t i = 0; i < n; ++i) {
		if (rewards[i]) {
			wallets[num_outputs] = wallets[i];
			rewards[num_outputs] = rewards[i];
			++num_outputs;
		}
	}

	wallets.resize(num_outputs);
	rewards.resize(num_outputs);

	if (std::accumulate(rewards.begin(), rewards.end(), 0ULL) != reward) {
		LOGERR(1, "miners got incorrect reward. This should never happen because math says so. Check the code!");

		wallets.clear();
		rewards.clear();
		return false;
	}

	return true;
}

} // namespace p2pool
