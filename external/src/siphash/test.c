/*
   SipHash reference C implementation
   Copyright (c) 2012-2021 Jean-Philippe Aumasson
   <jeanphilippe.aumasson@gmail.com> Copyright (c) 2012 Daniel J. Bernstein
   <djb@cr.yp.to>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.
   You should have received a copy of the CC0 Public Domain Dedication along
   with this software. If not, see
   <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#include "halfsiphash.h"
#include "siphash.h"
#include "vectors.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PRINTHASH(n)                                                           \
    printf("    { ");                                                          \
    for (int j = 0; j < n; ++j) {                                              \
        printf("0x%02x, ", out[j]);                                            \
    }                                                                          \
    printf("},\n");

const char *functions[4] = {
    "const uint8_t vectors_sip64[64][8] =",
    "const uint8_t vectors_sip128[64][16] =",
    "const uint8_t vectors_hsip32[64][4] =",
    "const uint8_t vectors_hsip64[64][8] =",
};

const char *labels[4] = {
    "SipHash-2-4-64",
    "SipHash-2-4-128",
    "HalfSipHash-2-4-32",
    "HalfSipHash-2-4-64",
};

size_t lengths[4] = {8, 16, 4, 8};

int siphash_test() {
    uint8_t in[64], out[16], k[16];
    int i;
    bool any_failed = false;
#ifndef GETVECTORS
    int fails = 0;
#endif

    for (i = 0; i < 16; ++i)
        k[i] = i;

    for (int version = 0; version < 4; ++version) {
#ifdef GETVECTORS
        printf("%s\n{\n", functions[version]);
#else
        printf("%s\n", labels[version]);
#endif

        for (i = 0; i < 64; ++i) {
            in[i] = i;
            int len = lengths[version];
            if (version < 2)
                siphash(in, i, k, out, len);
            else
                halfsiphash(in, i, k, out, len);
#ifdef GETVECTORS
            PRINTHASH(len);
#else
            const uint8_t *v = NULL;
            switch (version) {
            case 0:
                v = (uint8_t *)vectors_sip64;
                break;
            case 1:
                v = (uint8_t *)vectors_sip128;
                break;
            case 2:
                v = (uint8_t *)vectors_hsip32;
                break;
            case 3:
                v = (uint8_t *)vectors_hsip64;
                break;
            default:
                break;
            }

            if (memcmp(out, v + (i * len), len)) {
                printf("fail for %d bytes\n", i);
                fails++;
                any_failed = true;
            }
#endif
        }

#ifdef GETVECTORS
        printf("};\n");
#else
        if (!fails)
            printf("OK\n");

        fails = 0;
#endif
    }

    return any_failed;
}
