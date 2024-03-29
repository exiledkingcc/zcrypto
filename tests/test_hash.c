/*
Copyright (C) 2020-2023 exiledkingcc@gmail.com

This file is part of zcrypto.

zcrypto is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation; either version 3, or (at your option) any later
version.

zcrypto is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
for more details.

You should have received a copy of the GNU General Public License
along with zcrypto; see the file LICENSE.  If not see
<http://www.gnu.org/licenses/>.
*/

#include "zcrypto/hashlib.h"
#include "zcrypto/md5.h"
#include "zcrypto/sha1.h"
#include "zcrypto/sha256.h"
#include "zcrypto/sm3.h"
#include <stdio.h>

static void expect_equal(const char* name, const uint8_t* a, const uint8_t* b, size_t len) {
    if (memcmp(a, b, len) == 0) {
        printf("%s OK!\n", name);
    } else {
        printf("%s FAIL!\n", name);
    }
}

static void sm3_test() {
    uint8_t data1[] = {'a', 'b', 'c'};
    uint8_t digest1[32] = {0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9, 0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
                           0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2, 0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0};
    uint8_t data2[64] = {
        0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
        0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
    };
    uint8_t digest2[32] = {0xde, 0xbe, 0x9f, 0xf9, 0x22, 0x75, 0xb8, 0xa1, 0x38, 0x60, 0x48, 0x89, 0xc1, 0x8e, 0x5a, 0x4d,
                           0x6f, 0xdb, 0x70, 0xe5, 0x38, 0x7e, 0x57, 0x65, 0x29, 0x3d, 0xcb, 0xa3, 0x9c, 0x0c, 0x57, 0x32};
    uint8_t temp[32];

    sm3_ctx_t ctx;
    sm3_init(&ctx);
    sm3_update(&ctx, data1, 3);
    sm3_digest(&ctx, temp);
    expect_equal("sm3 bits=24", digest1, temp, 32);

    sm3_init(&ctx);
    sm3_update(&ctx, data2, 64);
    sm3_digest(&ctx, temp);
    expect_equal("sm3 bits=512", digest2, temp, 32);
}

static void md5_test() {
    uint8_t digest1[16] = {0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e};
    uint8_t digest2[16] = {0x9e, 0x10, 0x7d, 0x9d, 0x37, 0x2b, 0xb6, 0x82, 0x6b, 0xd8, 0x1d, 0x35, 0x42, 0xa4, 0x19, 0xd6};
    uint8_t temp[16];

    md5_ctx_t ctx;
    md5_init(&ctx);
    md5_digest(&ctx, temp);
    expect_equal("md5 bits=0", digest1, temp, 16);

    md5_update(&ctx, (const uint8_t*)"The quick brown fox jumps over the lazy dog", 43);
    md5_digest(&ctx, temp);
    expect_equal("md5 bits=43*8", digest2, temp, 16);
}

static void sha1_test() {
    uint8_t digest1[20] = {0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09};
    uint8_t digest2[20] = {0x2f, 0xd4, 0xe1, 0xc6, 0x7a, 0x2d, 0x28, 0xfc, 0xed, 0x84, 0x9e, 0xe1, 0xbb, 0x76, 0xe7, 0x39, 0x1b, 0x93, 0xeb, 0x12};
    uint8_t temp[20];

    sha1_ctx_t ctx;
    sha1_init(&ctx);
    sha1_digest(&ctx, temp);
    expect_equal("sha1 bits=0", digest1, temp, 20);

    sha1_update(&ctx, (const uint8_t*)"The quick brown fox jumps over the lazy dog", 43);
    sha1_digest(&ctx, temp);
    expect_equal("sha1 bits=43*8", digest2, temp, 20);
}

static void sha256_test() {
    uint8_t digest1[32] = {
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    };
    uint8_t digest2[32] = {0xd7, 0xa8, 0xfb, 0xb3, 0x07, 0xd7, 0x80, 0x94, 0x69, 0xca, 0x9a, 0xbc, 0xb0, 0x08, 0x2e, 0x4f,
                           0x8d, 0x56, 0x51, 0xe4, 0x6d, 0x3c, 0xdb, 0x76, 0x2d, 0x02, 0xd0, 0xbf, 0x37, 0xc9, 0xe5, 0x92};
    uint8_t temp[32];

    sha256_ctx_t ctx;
    sha256_init(&ctx);
    sha256_digest(&ctx, temp);
    expect_equal("sha256 bits=0", digest1, temp, 32);

    sha256_update(&ctx, (const uint8_t*)"The quick brown fox jumps over the lazy dog", 43);
    sha256_digest(&ctx, temp);
    expect_equal("sha256 bits=43*8", digest2, temp, 32);
}

static void hash_test() {
    const char* text[] = {
        "abc",
        "The quick brown fox jumps over the lazy dog",
        "0123456789abcdef0123456789abcdef",
    };

    hash_ctx_t ctx;
    uint8_t hex[80] = {0};

#define _hash_test(ALG)                                              \
    hash_init(&ctx, ALG);                                            \
    memset(hex, 0, 80);                                              \
    hash_hexdigest(&ctx, hex);                                       \
    printf(#ALG " hash %s of <empty>\n", hex);                       \
    for (int i = 0; i < 3; ++i) {                                    \
        hash_init(&ctx, ALG);                                        \
        memset(hex, 0, 80);                                          \
        hash_update(&ctx, (const uint8_t*)text[i], strlen(text[i])); \
        hash_hexdigest(&ctx, hex);                                   \
        printf(#ALG " hash %s of %s\n", hex, text[i]);               \
    }

    _hash_test(HASH_ALG_SM3) _hash_test(HASH_ALG_MD5) _hash_test(HASH_ALG_SHA1) _hash_test(HASH_ALG_SHA256)

#undef _hash_test
}

int main() {
    sm3_test();
    md5_test();
    sha1_test();
    sha256_test();
    hash_test();
}
