// Copyright (c) 2012-2017, The CryptoNote developers, The Bytecoin developers
// Copyright (c) 2014-2018, The Monero Project
// Copyright (c) 2018-2019, The TurtleCoin Developers
// Copyright (c) 2019, The Kryptokrona Developers
//
// Please see the included LICENSE file for more information.

#include <stddef.h>
#include <stdint.h>

#include "blake256.h"

void hash_extra_blake(const void *data, size_t length, char *hash)
{
    blake256_hash((uint8_t *)hash, data, length);
}
