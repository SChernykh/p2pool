// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2014-2018, The Monero Project
// Copyright (c) 2018-2019, The TurtleCoin Developers
// Copyright (c) 2019, The Kryptokrona Developers
//
// Please see the included LICENSE file for more information.

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "jh.h"
#include "hash-ops.h"

void hash_extra_jh(const void *data, size_t length, char *hash)
{
    int r = jh_hash(HASH_SIZE * 8, data, 8 * length, (uint8_t *)hash);
    if (r)
    {
    }
    assert(SUCCESS == r);
}
