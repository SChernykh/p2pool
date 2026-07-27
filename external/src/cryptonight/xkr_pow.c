/*
 * Kryptokrona (XKR) Proof-of-Work entry point for P2Pool. See xkr_pow.h.
 */

#include "xkr_pow.h"
#include "hash-ops.h"

// CryptoNight-Turtle parameters, mirrored from kryptokrona src/crypto/hash.h:
//   #define CN_TURTLE_PAGE_SIZE   262144
//   #define CN_TURTLE_SCRATCHPAD  262144
//   #define CN_TURTLE_ITERATIONS  131072
#define XKR_CN_TURTLE_PAGE_SIZE  262144u
#define XKR_CN_TURTLE_SCRATCHPAD 262144u
#define XKR_CN_TURTLE_ITERATIONS 131072u

void xkr_cn_turtle_pow(const void* data, size_t length, uint8_t hash[32])
{
    // light = 1 (lite scratchpad), variant = 2, prehashed = 0
    //   => kryptokrona's cn_turtle_lite_slow_hash_v2()
    cn_slow_hash(data, length, (char*)hash,
                 /* light      */ 1,
                 /* variant    */ 2,
                 /* prehashed  */ 0,
                 XKR_CN_TURTLE_PAGE_SIZE,
                 XKR_CN_TURTLE_SCRATCHPAD,
                 XKR_CN_TURTLE_ITERATIONS);
}
