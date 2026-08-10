// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2014-2018, The Monero Project
// Copyright (c) 2018-2019, The TurtleCoin Developers
// Copyright (c) 2019, The Kryptokrona Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#if !defined(__cplusplus)

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "common/int_util.h"

static inline void *padd(void *p, size_t i)
{
    return (char *)p + i;
}

static inline const void *cpadd(const void *p, size_t i)
{
    return (const char *)p + i;
}

static_assert(sizeof(size_t) == 4 || sizeof(size_t) == 8, "size_t must be 4 or 8 bytes long");
static inline void place_length(uint8_t *buffer, size_t bufsize, size_t length)
{
    if (sizeof(size_t) == 4)
    {
        *(uint32_t *)padd(buffer, bufsize - 4) = swap32be((uint32_t)length);
    }
    else
    {
        *(uint64_t *)padd(buffer, bufsize - 8) = swap64be(length);
    }
}

#pragma pack(push, 1)
union hash_state
{
    uint8_t b[200];
    uint64_t w[25];
};
#pragma pack(pop)
static_assert(sizeof(union hash_state) == 200, "Invalid structure size");

void hash_permutation(union hash_state *state);
void hash_process(union hash_state *state, const uint8_t *buf, size_t count);

#endif

enum
{
    HASH_SIZE = 32,
    HASH_DATA_AREA = 136,
    SLOW_HASH_CONTEXT_SIZE = 2097552,
    SLOW_HASH_CONTEXT_LITE_SIZE = 1048976 // Suml: Unused for now but this is the right size for 1MB scratchpads.
};

void cn_fast_hash(const void *data, size_t length, char *hash);
void cn_slow_hash(const void *data, size_t length, char *hash, int light, int variant, int prehashed, uint32_t page_size, uint32_t scratchpad, uint32_t iterations);

void hash_extra_blake(const void *data, size_t length, char *hash);
void hash_extra_groestl(const void *data, size_t length, char *hash);
void hash_extra_jh(const void *data, size_t length, char *hash);
void hash_extra_skein(const void *data, size_t length, char *hash);

void tree_hash(const char (*hashes)[HASH_SIZE], size_t count, char *root_hash);
size_t tree_depth(size_t count);
void tree_branch(const char (*hashes)[HASH_SIZE], size_t count, char (*branch)[HASH_SIZE]);
void tree_hash_from_branch(const char (*branch)[HASH_SIZE], size_t depth, const char *leaf, const void *path, char *root_hash);
