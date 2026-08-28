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
#include "carrot.h"
#include "crypto.h"
#include "wallet.h"
#include "blake2/blake2.h"

namespace p2pool {

namespace carrot {

bool hash_to_bytes(const void* input, size_t in_len, void* output, size_t out_len, const void* key)
{
	if (!input || !output || !out_len || (out_len > BLAKE2B_OUTBYTES)) {
		return false;
	}

	blake2b_param param{};

	param.digest_length = static_cast<uint8_t>(out_len);
	param.key_length = key ? CARROT_HASH_KEY_BYTES : 0;
	param.fanout = 1;
	param.depth = 1;

	constexpr char personal[] = "Monero";
	memcpy(param.personal, personal, sizeof(personal) - 1);

	blake2b_state state;
	blake2b_init_param(&state, &param);

	if (key) {
		static_assert(CARROT_HASH_KEY_BYTES <= BLAKE2B_BLOCKBYTES);
		uint8_t key_buf[BLAKE2B_BLOCKBYTES];

		memcpy(key_buf, key, CARROT_HASH_KEY_BYTES);
		memset(key_buf + CARROT_HASH_KEY_BYTES, 0, BLAKE2B_BLOCKBYTES - CARROT_HASH_KEY_BYTES);

		blake2b_update(&state, key_buf, BLAKE2B_BLOCKBYTES);
	}

	blake2b_update(&state, input, in_len);
	blake2b_final(&state, output, out_len);

	return true;
}

bool hash_to_scalar(const void *data, const std::size_t data_length, void *hash_out, const void *key)
{
	uint8_t buf[64];

	if (!hash_out || !hash_to_bytes(data, data_length, buf, 64, key)) {
		return false;
	}

	sc_reduce(buf);
	memcpy(hash_out, buf, 32);

	return true;
}

janus_anchor gen_janus_anchor(const hash& txkey_sec, uint8_t retry_counter, const Wallet& w)
{
	auto t = transcript(
		"P2Pool Janus anchor",
		txkey_sec, retry_counter,
		w.spend_public_key(), w.view_public_key()
	);

	janus_anchor result;
	hash_to_bytes(t.data(), t.size(), result.data, CARROT_JANUS_ANCHOR_BYTES);

	return result;
}

bool gen_eph_privkey(const janus_anchor& anchor_norm, uint64_t height, const Wallet& w, hash& eph_priv_key)
{
	auto t = transcript(
		"Carrot sending key normal",
		anchor_norm,
		'C', height, padding<CARROT_INPUT_CONTEXT_PADDING_BYTES>(),
		w.spend_public_key(),
		padding<LEGACY_PAYMENT_ID_BYTES>()
	);

	return hash_to_scalar(t.data(), t.size(), eph_priv_key.h) && !eph_priv_key.empty();
}

bool gen_eph_pubkey(const hash& eph_priv_key, hash& eph_pub_key)
{
	ge_p3 point;
	ge_scalarmult_base_vartime(&point, eph_priv_key.h);

	// ConvertPointE is not defined for the point at infinity (Z - Y = 0 there)
	if (ge_p3_is_point_at_infinity_vartime(&point)) {
		return false;
	}

	ge_p3_to_x25519(eph_pub_key.h, &point);

	return true;
}

bool gen_sender_receiver_secret(const hash& eph_priv_key, const hash& view_public_key, hash& secret)
{
	ge_p3 view_point;
	if ((ge_frombytes_vartime(&view_point, view_public_key.h) != 0) || !is_in_main_subgroup(view_point)) {
		return false;
	}

	ge_p3 point;
	ge_scalarmult_p3(&point, eph_priv_key.h, &view_point);

	if (ge_p3_is_point_at_infinity_vartime(&point)) {
		return false;
	}

	ge_p3_to_x25519(secret.h, &point);

	return true;
}

hash gen_contextualized_sender_receiver_secret(const hash& sender_receiver_secret, const hash& eph_pub_key, uint64_t height)
{
	auto t = transcript(
		"Carrot sender-receiver secret",
		eph_pub_key,
		'C', height, padding<CARROT_INPUT_CONTEXT_PADDING_BYTES>()
	);

	hash result;
	hash_to_bytes(t.data(), t.size(), result.h, HASH_SIZE, sender_receiver_secret.h);

	return result;
}

hash gen_sender_extension_g(const hash& contextualized_sender_receiver_secret, uint64_t amount, const hash& spend_public_key)
{
	auto t = transcript(
		"Carrot coinbase extension G",
		amount, spend_public_key
	);

	hash result;
	hash_to_scalar(t.data(), t.size(), result.h, contextualized_sender_receiver_secret.h);

	return result;
}

hash gen_sender_extension_t(const hash& contextualized_sender_receiver_secret, uint64_t amount, const hash& spend_public_key)
{
	auto t = transcript(
		"Carrot coinbase extension T",
		amount, spend_public_key
	);

	hash result;
	hash_to_scalar(t.data(), t.size(), result.h, contextualized_sender_receiver_secret.h);

	return result;
}

view_tag gen_view_tag(const hash& sender_receiver_secret, uint64_t height, const hash& onetime_address)
{
	auto t = transcript(
		"Carrot view tag",
		'C', height, padding<CARROT_INPUT_CONTEXT_PADDING_BYTES>(),
		onetime_address
	);

	view_tag result;
	hash_to_bytes(t.data(), t.size(), result.data, CARROT_VIEW_TAG_BYTES, sender_receiver_secret.h);

	return result;
}

janus_anchor gen_encrypted_janus_anchor(const hash& contextualized_sender_receiver_secret, const janus_anchor& anchor, const hash& onetime_address)
{
	auto t = transcript(
		"Carrot encryption mask anchor",
		onetime_address
	);

	janus_anchor mask;
	hash_to_bytes(t.data(), t.size(), mask.data, CARROT_JANUS_ANCHOR_BYTES, contextualized_sender_receiver_secret.h);

	janus_anchor result;

	for (size_t i = 0; i < CARROT_JANUS_ANCHOR_BYTES; ++i) {
		result.data[i] = anchor.data[i] ^ mask.data[i];
	}

	return result;
}

} // namespace carrot

} // namespace p2pool
