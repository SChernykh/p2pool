// Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <openssl/mem.h>
#include <openssl/rand.h>

#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include "crypto/fipsmodule/sha/sha256.cc.inc"
#include "crypto/fipsmodule/sha/sha512.cc.inc"

void OPENSSL_cleanse(void* ptr, size_t len)
{
	volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
	while (len--) {
		*p++ = 0;
	}
}

int CRYPTO_memcmp(const void* a, const void* b, size_t len)
{
	const uint8_t* x = static_cast<const uint8_t*>(a);
	const uint8_t* y = static_cast<const uint8_t*>(b);
	uint8_t r = 0;
	for (size_t i = 0; i < len; ++i) {
		r |= static_cast<uint8_t>(x[i] ^ y[i]);
	}
	return r;
}

int RAND_bytes(uint8_t*, size_t)
{
	abort();
}
