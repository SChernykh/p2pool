/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021-2024 SChernykh <https://github.com/SChernykh>
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

class p2pool;

class IMergeMiningClient
{
public:
	struct ChainParameters
	{
		hash aux_id;
		hash aux_hash;
		std::vector<uint8_t> aux_blob;
		difficulty_type aux_diff;
	};

public:
	static IMergeMiningClient* create(p2pool* pool, const std::string& host, const std::string& wallet) noexcept;
	virtual ~IMergeMiningClient() {}

	virtual bool get_params(ChainParameters& out_params) const = 0;
	virtual void submit_solution(const std::vector<uint8_t>& blob, const std::vector<hash>& merkle_proof) = 0;
};

} // namespace p2pool
