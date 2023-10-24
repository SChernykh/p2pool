/*********************************************************************
* Filename:   sha256.h
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Defines the API for the corresponding SHA1 implementation.
*********************************************************************/

#ifndef SHA256_H
#define SHA256_H

/*************************** HEADER FILES ***************************/
#include <stdint.h>

/****************************** MACROS ******************************/
#define SHA256_BLOCK_SIZE 32            // SHA256 outputs a 32 byte digest

typedef struct {
	uint8_t data[64];
	uint32_t datalen;
	uint32_t padding;
	uint64_t bitlen;
	uint32_t state[8];
} SHA256_CTX;

/*********************** FUNCTION DECLARATIONS **********************/
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const uint8_t* data, uint32_t len);
void sha256_final(SHA256_CTX *ctx, uint8_t* hash);

void sha256(const void* data, uint32_t len, uint8_t* hash);

#endif   // SHA256_H
