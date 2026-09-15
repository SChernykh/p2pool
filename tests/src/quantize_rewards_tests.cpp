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

#include <cstring>
#include <deque>
#include <fstream>
#include <limits>
#include <numeric>
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

} // namespace p2pool
