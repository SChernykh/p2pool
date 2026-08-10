/*
 * Kryptokrona (XKR) Proof-of-Work entry point for P2Pool.
 *
 * Kryptokrona blocks at BLOCK_MAJOR_VERSION_5 and above (the only versions a
 * present-day pool will ever mine) use CryptoNight-Turtle-Lite variant 2 as
 * their PoW long-hash. See kryptokrona's src/cryptonote_core/cached_block.cpp
 * (getBlockLongHash) and src/crypto/hash.h (cn_turtle_lite_slow_hash_v2).
 *
 * This wrapper hides the CryptoNight parameters so the rest of P2Pool only
 * needs a single stateless "hash these bytes" call, replacing Monero's
 * RandomX (which is seed/epoch/dataset based).
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Compute the Kryptokrona v5+ PoW hash of `length` bytes at `data` into `hash`
// (32 bytes). Equivalent to kryptokrona's cn_turtle_lite_slow_hash_v2().
void xkr_cn_turtle_pow(const void* data, size_t length, uint8_t hash[32]);

#ifdef __cplusplus
}
#endif
