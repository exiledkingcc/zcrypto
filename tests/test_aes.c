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

#include "zcrypto/aes.h"
#include <stdio.h>

static void expect_equal(const char* name, const uint8_t* a, const uint8_t* b, size_t len) {
    if (memcmp(a, b, len) == 0) {
        printf("%s OK!\n", name);
    } else {
        printf("%s FAIL!\n", name);
    }
}

static void aes_test(void) {
    uint8_t key[32];
    uint8_t plain[32];
    uint8_t cipher[32] = {0};
    uint8_t plain2[32] = {0};
    uint8_t cipher2[32] = {0x5c, 0x1d, 0xd3, 0xe3, 0xf9, 0xdc, 0x62, 0x5a, 0x70, 0xf0, 0x93, 0x28, 0x21, 0x4d, 0xda, 0x6a,
                           0xaf, 0x0c, 0x91, 0xe4, 0x6f, 0xc8, 0x3c, 0x6d, 0x6d, 0x06, 0x1c, 0x02, 0xa8, 0x27, 0x48, 0x2a};

    for (int i = 0; i < 32; ++i) {
        key[i] = (i * i) & 0xff;
        plain[i] = (i * i * i) & 0xff;
    }

    aes_128_ecb_encrypt(key, 32, plain, cipher);
    expect_equal("aes 128 encrypt", cipher, cipher2, 32);
    aes_128_ecb_decrypt(key, 32, cipher, plain2);
    expect_equal("aes 128 decrypt", plain, plain2, 32);

    aes_192_ecb_encrypt(key, 32, plain, cipher);
    aes_192_ecb_decrypt(key, 32, cipher, plain2);
    expect_equal("aes 192", plain, plain2, 32);

    aes_256_ecb_encrypt(key, 32, plain, cipher);
    aes_256_ecb_decrypt(key, 32, cipher, plain2);
    expect_equal("aes 256", plain, plain2, 32);

#define _aes_with_iv_test(MODE)                             \
    aes_128_##MODE##_encrypt(key, key, 32, plain, cipher);  \
    aes_128_##MODE##_decrypt(key, key, 32, cipher, plain2); \
    expect_equal("aes " #MODE " K128", plain, plain2, 32);  \
    aes_192_##MODE##_encrypt(key, key, 32, plain, cipher);  \
    aes_192_##MODE##_decrypt(key, key, 32, cipher, plain2); \
    expect_equal("aes " #MODE " K192", plain, plain2, 32);  \
    aes_256_##MODE##_encrypt(key, key, 32, plain, cipher);  \
    aes_256_##MODE##_decrypt(key, key, 32, cipher, plain2); \
    expect_equal("aes " #MODE " K256", plain, plain2, 32);

    _aes_with_iv_test(cbc) _aes_with_iv_test(cfb) _aes_with_iv_test(ofb)

#undef _aes_with_iv_test
}

static void aes_ctx_test(int mode, const char* name) {
    uint8_t key[32];
    uint8_t p1[32];
    uint8_t p2[32];
    uint8_t c1[32];

    for (int i = 0; i < 32; ++i) {
        key[i] = (i * i) & 0xff;
        p1[i] = (i * i * i) & 0xff;
    }

    memset(p2, 0, 32);
    memset(c1, 0, 32);

    const uint8_t* iv = NULL;
    if (mode != AES_ECB_MODE) {
        iv = key;
    }

    aes_ctx_t ctx_en;
    aes_ctx_t ctx_de;
    char namex[32] = "";

    size_t keylens[3] = {128, 192, 256};
    for (int i = 0; i < 3; ++i) {
        aes_close(&ctx_en);
        aes_close(&ctx_de);

        size_t keylen = keylens[i];
        int r = aes_init(&ctx_en, mode, keylen, key, iv);
        if (r != 0) {
            printf("aes_init(%s | AES_ENCRYPT, %ld) FAIL!\n", name, keylen);
            continue;
        }

        r = aes_init(&ctx_de, mode, keylen, key, iv);
        if (r != 0) {
            printf("aes_init(%s | AES_DECRYPT, %ld) FAIL!\n", name, keylen);
            continue;
        }

        r = aes_encrypt(&ctx_en, 16, p1, c1);
        r = aes_encrypt(&ctx_en, 16, p1 + 16, c1 + 16);
        if (r != 0) {
            printf("aes_encrypt(%s, %ld) FAIL!\n", name, keylen);
            continue;
        }

        r = aes_decrypt(&ctx_de, 32, c1, p2);
        if (r != 0) {
            printf("aes_decrypt(%s, %ld) FAIL!\n", name, keylen);
            continue;
        }

        sprintf(namex, "%s K%ld", name, keylen);
        expect_equal(namex, p1, p2, 32);
    }
}

int main() {
    aes_test();

    aes_ctx_test(AES_ECB_MODE, "AES_ECB_MODE");
    aes_ctx_test(AES_CBC_MODE, "AES_CBC_MODE");
    aes_ctx_test(AES_CFB_MODE, "AES_CFB_MODE");
    aes_ctx_test(AES_OFB_MODE, "AES_OFB_MODE");
}
