/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh>
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
#include "side_chain.h"
#include "quantize_rewards.h"
#include "wallet.h"
#include "gtest/gtest.h"

#include "soft_aes.h"
#include "blake2/blake2.h"

#include <cstring>
#include <deque>
#include <fstream>
#include <limits>
#include <numeric>
#include <random>
#include <sstream>

namespace p2pool {

static constexpr uint64_t T = PAYOUT_GRID_STEP;

struct RewardVector
{
	std::string m_name;
	uint64_t m_reward;
	hash m_powHash;

	std::deque<Wallet> m_wallets;
	std::vector<difficulty_type> m_weights;
	std::vector<uint64_t> m_expectedPayouts;
};

static bool parse_hash(const std::string& s, hash& out)
{
	if (s.length() != HASH_SIZE * 2) {
		return false;
	}

	std::stringstream ss;
	ss << s;
	ss >> out;

	return !ss.fail();
}

static void load_vectors(std::vector<RewardVector>& vectors)
{
	std::ifstream file("quantize_rewards_vectors.txt");
	ASSERT_TRUE(file.is_open());

	std::string line;
	uint64_t remaining = 0;

	while (std::getline(file, line)) {
		if (line.empty() || (line[0] == '#')) {
			continue;
		}

		std::stringstream s(line);

		if (line[0] == 'V') {
			ASSERT_EQ(remaining, 0U) << "vector " << vectors.back().m_name << " is short";

			std::string tag, pow_hash;
			uint64_t n;

			vectors.emplace_back();
			RewardVector& v = vectors.back();

			s >> tag >> v.m_name >> v.m_reward >> pow_hash >> n;
			ASSERT_FALSE(s.fail());
			ASSERT_TRUE(parse_hash(pow_hash, v.m_powHash));

			v.m_weights.reserve(n);
			v.m_expectedPayouts.reserve(n);

			remaining = n;
			continue;
		}

		ASSERT_GT(remaining, 0U) << "wallet line outside a vector: " << line;
		ASSERT_FALSE(vectors.empty());

		RewardVector& v = vectors.back();

		std::string key;
		difficulty_type weight;
		uint64_t payout;

		s >> key >> weight >> payout;
		ASSERT_FALSE(s.fail());
		ASSERT_EQ(key.length(), HASH_SIZE * 4) << "a wallet key is spend || view, 64 bytes";

		hash spend_key, view_key;
		ASSERT_TRUE(parse_hash(key.substr(0, HASH_SIZE * 2), spend_key));
		ASSERT_TRUE(parse_hash(key.substr(HASH_SIZE * 2), view_key));

		v.m_wallets.emplace_back(nullptr);
		v.m_wallets.back().assign_unchecked(spend_key, view_key, NetworkType::Mainnet);

		v.m_weights.emplace_back(weight);
		v.m_expectedPayouts.emplace_back(payout);

		--remaining;
	}

	ASSERT_EQ(remaining, 0U);
	ASSERT_FALSE(vectors.empty());
}

static void make_window(const RewardVector& v, PPLNSWindow& window)
{
	window.clear();
	window.m_shares.reserve(v.m_weights.size());
	window.m_powHash = v.m_powHash;

	size_t i = 0;
	for (const Wallet& w : v.m_wallets) {
		window.m_shares.emplace_back(v.m_weights[i++], &w);
	}
}

static void expected_outputs(const RewardVector& v, std::vector<std::pair<const Wallet*, uint64_t>>& out)
{
	out.clear();

	size_t i = 0;
	for (const Wallet& w : v.m_wallets) {
		if (v.m_expectedPayouts[i]) {
			out.emplace_back(&w, v.m_expectedPayouts[i]);
		}
		++i;
	}
}

// quantize_rewards() as it was before std::nth_element replaced its std::sort, the reference for quantize_rewards.same_as_a_full_sort.
// The only other changes: no logging, software AES (it gives the same draws as the hardware path), and branch counters.
struct SortReferenceStats
{
	uint64_t no_round_up = 0;    // M == 0
	uint64_t round_up = 0;       // M > 0
	uint64_t no_remainder = 0;   // rho == 0
	uint64_t tie_weight = 0;     // the ranking had to fall back to comparing weights
	uint64_t tie_index = 0;      // ... and then indices
	uint64_t past_the_cut = 0;   // the remainder went to the first wallet past the cut owed a whole step
	uint64_t exact_multiple = 0; // ... to a wallet owed an exact multiple of T
	uint64_t other_side = 0;     // ... to the wallet on the other side of the cut
};

[[nodiscard]] static uint64_t reference_uniform(const rx_vec_i128 (&seed)[4], const Wallet& w)
{
	rx_vec_i128 key[4];
	memcpy(key, w.keys(), sizeof(key));

	rx_vec_i128 s = aesenc<true>(key[0], seed[0]);

	for (uint32_t r = 1; r < 4; ++r) {
		s = aesenc<true>(rx_xor_vec_i128(s, key[r]), seed[r]);
	}

	rx_vec_i128 out;
	rx_store_vec_i128(&out, s);

	uint64_t h;
	memcpy(&h, &out, sizeof(h));

	uint64_t hi;
	umul128(h, T, &hi);

	return hi;
}

static bool quantize_rewards_with_sort(const PPLNSWindow& window, uint64_t reward, std::vector<const Wallet*>& wallets, std::vector<uint64_t>& rewards, SortReferenceStats& stats)
{
	const std::vector<MinerShare>& shares = window.m_shares;
	const size_t n = rewards.size();

	if ((n == 0) || (wallets.size() != n) || (shares.size() != n)) {
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
		u[i] = reference_uniform(seed, *wallets[i]);

		F += f[i];
	}

	const uint64_t M = F / T;   // M: how many wallets round up
	const uint64_t rho = F % T; // rho: the one sub-grid remainder, == reward % T

	++(M ? stats.round_up : stats.no_round_up);

	if (!rho) {
		++stats.no_remainder;
	}

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
				return false;
			}

			for (size_t i = 0; i < n; ++i) {
				if (c[i] > f[i]) {
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
		return false;
	}

	// Pareto order sampling (Rosen 1997): rank by
	//
	//     Q_i = (u_i / (T - u_i)) * ((T - f'_i) / f'_i)
	//
	// and let the M smallest round up
	std::sort(order.begin(), order.end(),
		[&u, &fp, &shares, &stats](size_t x, size_t y)
		{
			// Q_x < Q_y, cross-multiplied
			const u128 qx = u128(u[x] * (T - fp[x])) * ((T - u[y]) * fp[y]);
			const u128 qy = u128(u[y] * (T - fp[y])) * ((T - u[x]) * fp[x]);

			if (qx != qy) {
				return qx < qy;
			}

			// Ties: weight descending, then the order the shares came in
			if (shares[x].m_weight != shares[y].m_weight) {
				++stats.tie_weight;
				return shares[x].m_weight > shares[y].m_weight;
			}

			++stats.tie_index;
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
				++stats.past_the_cut;
				break;
			}
		}

		// Every wallet past the cut is sub-grid: a wallet owed an exact multiple of T
		if (h == n) {
			for (size_t i = 0; i < n; ++i) {
				if ((fp[i] == 0) && (a[i] >= 1)) {
					h = i;
					++stats.exact_multiple;
					break;
				}
			}
		}

		// The wallet on the other side of the cut
		if (h == n) {
			if (order.empty()) {
				return false;
			}
			h = order[M ? (M - 1) : 0];
			++stats.other_side;
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
		wallets.clear();
		rewards.clear();
		return false;
	}

	return true;
}

TEST(quantize_rewards, conformance_vectors)
{
	std::vector<RewardVector> vectors;
	load_vectors(vectors);
	ASSERT_EQ(vectors.size(), 35U);

	uint64_t total_entries = 0;

	for (const RewardVector& v : vectors) {
		SCOPED_TRACE(testing::Message() << "vector " << v.m_name);

		PPLNSWindow window;
		make_window(v, window);

		std::vector<const Wallet*> wallets;
		std::vector<uint64_t> rewards;

		ASSERT_TRUE(SideChain::split_reward(HARDFORK_VERSION_CARROT, v.m_reward, window, wallets, rewards));

		std::vector<std::pair<const Wallet*, uint64_t>> expected;
		expected_outputs(v, expected);

		ASSERT_EQ(wallets.size(), rewards.size());
		ASSERT_EQ(wallets.size(), expected.size()) << "wrong number of outputs";
		ASSERT_LE(wallets.size(), window.size());

		for (size_t i = 0, n = wallets.size(); i < n; ++i) {
			ASSERT_EQ(*wallets[i], *expected[i].first) << "wrong wallet at index " << i;
			ASSERT_EQ(rewards[i], expected[i].second) << "wrong payout at index " << i;
		}

		ASSERT_EQ(std::accumulate(rewards.begin(), rewards.end(), 0ULL), v.m_reward);

		total_entries += v.m_weights.size();
	}

	ASSERT_EQ(total_entries, 9876U);
}

TEST(quantize_rewards, pre_carrot_is_unchanged)
{
	std::vector<RewardVector> vectors;
	load_vectors(vectors);

	for (const RewardVector& v : vectors) {
		SCOPED_TRACE(testing::Message() << "vector " << v.m_name);

		if (!v.m_reward) {
			continue;
		}

		PPLNSWindow window;
		make_window(v, window);

		std::vector<const Wallet*> wallets;
		std::vector<uint64_t> rewards;

		ASSERT_TRUE(SideChain::split_reward(HARDFORK_VERSION_CARROT - 1, v.m_reward, window, wallets, rewards));

		ASSERT_EQ(wallets.size(), window.size());
		ASSERT_EQ(rewards.size(), window.size());
		ASSERT_EQ(std::accumulate(rewards.begin(), rewards.end(), 0ULL), v.m_reward);

		difficulty_type total_weight;
		for (const MinerShare& s : window.m_shares) {
			total_weight += s.m_weight;
		}

		difficulty_type w;
		uint64_t given = 0;

		for (size_t i = 0, n = window.size(); i < n; ++i) {
			w += window.m_shares[i].m_weight;

			const uint64_t next_value = (w * v.m_reward / total_weight).lo;
			ASSERT_EQ(rewards[i], next_value - given) << "wrong share at index " << i;
			given = next_value;

			ASSERT_EQ(*wallets[i], *window.m_shares[i].m_wallet);
		}
	}
}

TEST(quantize_rewards, payouts_land_on_the_grid)
{
	std::vector<RewardVector> vectors;
	load_vectors(vectors);

	for (const RewardVector& v : vectors) {
		SCOPED_TRACE(testing::Message() << "vector " << v.m_name);

		PPLNSWindow window;
		make_window(v, window);

		std::vector<const Wallet*> wallets;
		std::vector<uint64_t> rewards;

		ASSERT_TRUE(SideChain::split_reward(HARDFORK_VERSION_CARROT, v.m_reward, window, wallets, rewards));

		const uint64_t rho = v.m_reward % T;
		size_t off_grid = 0;

		for (size_t i = 0, n = rewards.size(); i < n; ++i) {
			ASSERT_GT(rewards[i], 0U) << "a zero payout should not get an output";

			if (rewards[i] % T) {
				ASSERT_EQ(rewards[i] % T, rho) << "the only off-grid amount is the remainder";
				++off_grid;
			}
		}

		ASSERT_LE(off_grid, 1U) << "at most one output carries the remainder";
		ASSERT_EQ(off_grid, (rho && !rewards.empty()) ? 1U : 0U);
	}
}

TEST(quantize_rewards, the_seed_picks_the_winners)
{
	std::vector<RewardVector> vectors;
	load_vectors(vectors);

	uint64_t different = 0, compared = 0;

	for (const RewardVector& v : vectors) {
		SCOPED_TRACE(testing::Message() << "vector " << v.m_name);

		PPLNSWindow window;
		make_window(v, window);

		std::vector<const Wallet*> wallets1, wallets2;
		std::vector<uint64_t> rewards1, rewards2;

		PPLNSWindow other = window;
		other.m_powHash.h[0] ^= 1;

		ASSERT_TRUE(SideChain::split_reward(HARDFORK_VERSION_CARROT, v.m_reward, window, wallets1, rewards1));
		ASSERT_TRUE(SideChain::split_reward(HARDFORK_VERSION_CARROT, v.m_reward, other, wallets2, rewards2));

		ASSERT_EQ(std::accumulate(rewards1.begin(), rewards1.end(), 0ULL), v.m_reward);
		ASSERT_EQ(std::accumulate(rewards2.begin(), rewards2.end(), 0ULL), v.m_reward);

		++compared;

		if ((wallets1.size() != wallets2.size()) || !std::equal(rewards1.begin(), rewards1.end(), rewards2.begin())) {
			++different;
		}
	}

	ASSERT_GT(different * 2, compared) << "the seed barely changed anything, check the code";
}

TEST(quantize_rewards, drops_the_dust)
{
	std::vector<RewardVector> vectors;
	load_vectors(vectors);

	for (const RewardVector& v : vectors) {
		if (v.m_name != "typical_mini") {
			continue;
		}

		PPLNSWindow window;
		make_window(v, window);

		std::vector<const Wallet*> wallets;
		std::vector<uint64_t> rewards;

		ASSERT_TRUE(SideChain::split_reward(HARDFORK_VERSION_CARROT, v.m_reward, window, wallets, rewards));

		ASSERT_EQ(window.size(), 731U);
		ASSERT_EQ(wallets.size(), 250U);
		return;
	}

	FAIL() << "typical_mini is missing from the vectors";
}

TEST(quantize_rewards, handles_a_reward_up_to_the_uint64_limit)
{
	std::vector<RewardVector> vectors;
	load_vectors(vectors);

	const RewardVector& v = vectors.front();

	PPLNSWindow window;
	make_window(v, window);

	const size_t n = window.size();
	ASSERT_GE(n, 2U);

	constexpr uint64_t U = std::numeric_limits<uint64_t>::max();

	for (uint64_t reward : { U, U - 1, U - T, U - T * 2, U - T * 2 + 1, U / 2 }) {
		SCOPED_TRACE(testing::Message() << "reward " << reward);

		std::vector<const Wallet*> wallets;
		std::vector<uint64_t> rewards;

		for (size_t i = 0; i < n; ++i) {
			wallets.emplace_back(window.m_shares[i].m_wallet);
			rewards.emplace_back((i == 0) ? (reward - (n - 1)) : 1);
		}

		ASSERT_TRUE(quantize_rewards(window, reward, wallets, rewards));

		ASSERT_EQ(wallets.size(), rewards.size());
		ASSERT_LE(rewards.size(), n);
		ASSERT_EQ(std::accumulate(rewards.begin(), rewards.end(), 0ULL), reward);

		const uint64_t rho = reward % T;
		size_t off_grid = 0;

		for (uint64_t r : rewards) {
			ASSERT_GT(r, 0U);
			ASSERT_LE(r, reward) << "a payout came out bigger than the whole reward";

			if (r % T) {
				ASSERT_EQ(r % T, rho);
				++off_grid;
			}
		}

		ASSERT_EQ(off_grid, rho ? 1U : 0U);
	}
}

TEST(quantize_rewards, input_order_matters)
{
	std::vector<RewardVector> vectors;
	load_vectors(vectors);

	uint64_t different = 0, compared = 0;

	for (const RewardVector& v : vectors) {
		SCOPED_TRACE(testing::Message() << "vector " << v.m_name);

		if (v.m_weights.size() < 2) {
			continue;
		}

		PPLNSWindow window;
		make_window(v, window);

		PPLNSWindow reversed;
		reversed.m_shares.assign(window.m_shares.rbegin(), window.m_shares.rend());
		reversed.m_powHash = window.m_powHash;

		std::vector<const Wallet*> wallets1, wallets2;
		std::vector<uint64_t> rewards1, rewards2;

		ASSERT_TRUE(SideChain::split_reward(HARDFORK_VERSION_CARROT, v.m_reward, window, wallets1, rewards1));
		ASSERT_TRUE(SideChain::split_reward(HARDFORK_VERSION_CARROT, v.m_reward, reversed, wallets2, rewards2));

		ASSERT_EQ(std::accumulate(rewards1.begin(), rewards1.end(), 0ULL), v.m_reward);
		ASSERT_EQ(std::accumulate(rewards2.begin(), rewards2.end(), 0ULL), v.m_reward);

		++compared;

		std::vector<std::pair<const Wallet*, uint64_t>> a, b;
		for (size_t i = 0; i < wallets1.size(); ++i) a.emplace_back(wallets1[i], rewards1[i]);
		for (size_t i = 0; i < wallets2.size(); ++i) b.emplace_back(wallets2[i], rewards2[i]);

		const auto by_key = [](const auto& x, const auto& y) { return memcmp(x.first->keys(), y.first->keys(), HASH_SIZE * 2) < 0; };
		std::sort(a.begin(), a.end(), by_key);
		std::sort(b.begin(), b.end(), by_key);

		if ((a.size() != b.size()) || !std::equal(a.begin(), a.end(), b.begin(),
			[](const auto& x, const auto& y) { return (*x.first == *y.first) && (x.second == y.second); })) {
			++different;
		}
	}

	ASSERT_GT(different, 0U) << "the wallet order changed nothing at all, check the code";
	ASSERT_EQ(compared, 34U);
}

// The std::nth_element ranking must give exactly what the full sort gave. The random windows are shaped to reach every branch of
// the ranking: no wallet rounding up, no remainder, ties decided by weight and by index, and all three places the remainder can go.
TEST(quantize_rewards, same_as_a_full_sort)
{
	std::mt19937_64 rng(20260925);

	auto random_hash = [&rng]() {
		hash h;
		for (size_t k = 0; k < HASH_SIZE / sizeof(uint64_t); ++k) {
			h.u64()[k] = rng();
		}
		return h;
	};

	SortReferenceStats stats;
	uint64_t mini_sized = 0;

	for (uint32_t iter = 0; iter < 50000; ++iter) {
		// Mostly small windows, where every branch is easy to reach, and now and then a mini-sized one
		const bool big = (iter % 250 == 0);
		const size_t n = big ? (1000 + rng() % 1200) : (1 + rng() % 24);
		const uint64_t scenario = rng() % 5;

		mini_sized += big ? 1 : 0;

		// Repeated wallets with the same amount tie in the ranking itself, and then only the weight and the index are left
		const size_t distinct = (scenario == 4) ? (1 + rng() % 3) : n;

		std::deque<Wallet> wallets;
		std::vector<uint64_t> amounts(distinct);

		for (size_t i = 0; i < distinct; ++i) {
			wallets.emplace_back(nullptr);
			wallets.back().assign_unchecked(random_hash(), random_hash(), NetworkType::Mainnet);
			amounts[i] = (rng() % 3) * T + rng() % T;
		}

		PPLNSWindow window;
		window.m_powHash = random_hash();

		std::vector<const Wallet*> ptrs(n);
		std::vector<uint64_t> rewards(n);

		for (size_t i = 0; i < n; ++i) {
			ptrs[i] = &wallets[i % distinct];

			// Only a few different weights, so tied wallets often have the same weight too
			window.m_shares.emplace_back(difficulty_type(1 + rng() % 3), ptrs[i]);

			switch (scenario) {
			case 0: // Whole steps and a fraction
				rewards[i] = (rng() % 8) * T + rng() % T;
				break;
			case 1: // Dust: nobody is owed a whole step
				rewards[i] = rng() % T;
				break;
			case 2: // Exact multiples of T next to dust
				rewards[i] = (rng() & 1) ? ((1 + rng() % 4) * T) : (rng() % T);
				break;
			case 3: // Everything on the grid, except sometimes the first wallet
				rewards[i] = (rng() % 5) * T + (((i == 0) && (rng() & 1)) ? (rng() % T) : 0);
				break;
			default:
				rewards[i] = amounts[i % distinct];
				break;
			}
		}

		const uint64_t reward = std::accumulate(rewards.begin(), rewards.end(), 0ULL);

		std::vector<const Wallet*> wallets1 = ptrs, wallets2 = ptrs;
		std::vector<uint64_t> rewards1 = rewards, rewards2 = rewards;

		const bool ok1 = quantize_rewards(window, reward, wallets1, rewards1);
		const bool ok2 = quantize_rewards_with_sort(window, reward, wallets2, rewards2, stats);

		ASSERT_TRUE(ok2) << "window " << iter;
		ASSERT_EQ(ok1, ok2) << "window " << iter;
		ASSERT_EQ(wallets1, wallets2) << "window " << iter;
		ASSERT_EQ(rewards1, rewards2) << "window " << iter;
	}

	ASSERT_GT(mini_sized, 0U);

	// Every branch of the ranking was reached
	EXPECT_GT(stats.no_round_up, 0U);
	EXPECT_GT(stats.round_up, 0U);
	EXPECT_GT(stats.no_remainder, 0U);
	EXPECT_GT(stats.tie_weight, 0U);
	EXPECT_GT(stats.tie_index, 0U);
	EXPECT_GT(stats.past_the_cut, 0U);
	EXPECT_GT(stats.exact_multiple, 0U);
	EXPECT_GT(stats.other_side, 0U);
}

} // namespace p2pool
