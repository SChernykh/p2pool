/*
 * This file is part of the Monero P2Pool <https://github.com/SChernykh/p2pool>
 * Copyright (c) 2021 SChernykh <https://github.com/SChernykh>
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

template<typename T, typename U>
struct parse_wrapper
{
	static constexpr bool parse(T&, const char*, U&)
	{
		static_assert(not_implemented<T>::value, "JSON parser for this type is not implemented");
		return false;
	}
};

template<typename T, typename U>
FORCEINLINE bool parseValue(T& v, const char* name, U& out_value) { return parse_wrapper<T, U>::parse(v, name, out_value); }

#define JSON_VALUE_PARSER(type, out_type) \
template<typename T> \
struct parse_wrapper<T, out_type> \
{ \
	static FORCEINLINE bool parse(T& v, const char* name, out_type& out_value) \
	{ \
		if (v.IsObject() && v.HasMember(name)) { \
			const auto& t = v[name]; \
			if (t.Is##type()) { \
				out_value = static_cast<out_type>(t.Get##type()); \
				return true; \
			} \
		} \
		return false; \
	} \
};


JSON_VALUE_PARSER(String, const char*)
JSON_VALUE_PARSER(String, std::string)
JSON_VALUE_PARSER(Uint, uint8_t)
JSON_VALUE_PARSER(Uint64, uint64_t)
JSON_VALUE_PARSER(Bool, bool)

#undef JSON_VALUE_PARSER

template<typename T>
struct parse_wrapper<T, hash>
{
	static NOINLINE bool parse(T& v, const char* name, hash& out_value)
	{
		const char* s = nullptr;
		if (!parseValue(v, name, s) || !s || (strlen(s) != HASH_SIZE * 2)) {
			return false;
		}

		for (size_t i = 0; i < HASH_SIZE; ++i) {
			uint8_t d[2];
			if (!from_hex(s[i * 2], d[0]) || !from_hex(s[i * 2 + 1], d[1])) {
				return false;
			}
			out_value.h[i] = (d[0] << 4) | d[1];
		}

		return true;
	}
};

template<typename T>
struct parse_wrapper<T, difficulty_type>
{
	static NOINLINE bool parse(T& v, const char* name, difficulty_type &out_value)
	{
		const char* s = nullptr;
		if (!parseValue(v, name, s) || !s) {
			return false;
		}

		size_t N = strlen(s);
		if ((N >= 2) && (s[0] == '0') && (s[1] == 'x')) {
			s += 2;
			N -= 2;
		}

		out_value.lo = 0;
		out_value.hi = 0;

		for (size_t i = 0; i < N; ++i) {
			uint8_t d;
			if (!from_hex(s[i], d)) {
				return false;
			}
			out_value.hi = (out_value.hi << 4) || (out_value.lo >> 60);
			out_value.lo = (out_value.lo << 4) | d;
		}

		return true;
	}
};

#define PARSE(doc, var, name) parseValue(doc, #name, var.name)

} // namespace p2pool
