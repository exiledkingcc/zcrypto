#include <stdio.h>
#include "zcrypto/cipher.h"
#include "zcrypto/aes.h"
#include "zcrypto/md5.h"
#include "zcrypto/sha1.h"
#include "zcrypto/sm3.h"
#include "zcrypto/sm4.h"

static void expect_equal(const char *name, const uint8_t *a, const uint8_t *b, size_t len) {
    if (memcmp(a, b, len) == 0) {
        printf("%s OK!\n", name);
    } else {
        printf("%s FAIL!\n", name);
    }
}

static void sm4_test () {
    uint8_t key[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    uint8_t plain[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};
    uint8_t text1[] = {0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46};
    uint8_t text2[] = {0x59, 0x52, 0x98, 0xc7, 0xc6, 0xfd, 0x27, 0x1f, 0x04, 0x02, 0xf8, 0x04, 0xc3, 0x3d, 0x3f, 0x66};
    uint8_t cipher[16];
    uint8_t plain2[16];

    sm4_ecb_encrypt(key, 16, plain, cipher);
    sm4_ecb_decrypt(key, 16, cipher, plain2);
    expect_equal("sm4 encrypt", cipher, text1, 16);
    expect_equal("sm4 decrypt", plain, plain2, 16);

    memset(plain2, 0, 32);
    for (int i = 0; i < 1000000; ++i) {
        sm4_ecb_encrypt(key, 16, plain, cipher);
        memcpy(plain, cipher, 16);
    }
    expect_equal("sm4 encrypt 1000000", cipher, text2, 16);

    uint8_t p1[32];
    uint8_t p2[32];
    uint8_t c1[32];
    for (int i = 0; i < 32; ++i) {
        p1[i] = (i * i) & 0xff;
    }

    memset(p2, 0, 32);
    sm4_cbc_encrypt(key, key, 32, p1, c1);
    sm4_cbc_decrypt(key, key, 32, c1, p2);
    expect_equal("sm4_cbc", p1, p2, 32);

    sm4_cfb_encrypt(key, key, 32, p1, c1);
    sm4_cfb_decrypt(key, key, 32, c1, p2);
    expect_equal("sm4_cfb", p1, p2, 32);

    sm4_ofb_encrypt(key, key, 32, p1, c1);
    sm4_ofb_decrypt(key, key, 32, c1, p2);
    expect_equal("sm4_ofb", p1, p2, 32);
}

static void aes_test () {
    uint8_t key[32];
    uint8_t plain[32];
    uint8_t cipher[32] = {0};
    uint8_t plain2[32] = {0};
    uint8_t cipher2[32] = {
        0x5c, 0x1d, 0xd3, 0xe3, 0xf9, 0xdc, 0x62, 0x5a, 0x70, 0xf0, 0x93, 0x28, 0x21, 0x4d, 0xda, 0x6a,
        0xaf, 0x0c, 0x91, 0xe4, 0x6f, 0xc8, 0x3c, 0x6d, 0x6d, 0x06, 0x1c, 0x02, 0xa8, 0x27, 0x48, 0x2a
    };

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

    #define _aes_with_iv_test(MODE) \
    aes_128_ ## MODE ## _encrypt(key, key, 32, plain, cipher); \
    aes_128_ ## MODE ## _decrypt(key, key, 32, plain, cipher); \
    expect_equal("aes 128 " #MODE, plain, plain2, 32); \
    aes_192_ ## MODE ## _encrypt(key, key, 32, plain, cipher); \
    aes_192_ ## MODE ## _decrypt(key, key, 32, plain, cipher); \
    expect_equal("aes 192 " #MODE, plain, plain2, 32); \
    aes_256_ ## MODE ## _encrypt(key, key, 32, plain, cipher); \
    aes_256_ ## MODE ## _decrypt(key, key, 32, plain, cipher); \
    expect_equal("aes 256 " #MODE, plain, plain2, 32);

    _aes_with_iv_test(cbc)
    _aes_with_iv_test(cfb)
    _aes_with_iv_test(ofb)

    #undef _aes_with_iv_test
}

static void cipher_sm4_test(int mode, const char* name) {
    uint8_t key[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

    uint8_t p1[32];
    uint8_t p2[32];
    uint8_t c1[32];
    for (int i = 0; i < 32; ++i) {
        p1[i] = (i * i) & 0xff;
    }
    memset(p2, 0, 32);
    memset(c1, 0, 32);

    cipher_ctx_t ctx_en;
    cipher_ctx_t ctx_de;
    cipher_init(&ctx_en, ALG_SM4, 128, key, mode, key, false);
    cipher_init(&ctx_de, ALG_SM4, 128, key, mode, key, true);

    cipher_operate(&ctx_en, 32, p1, c1);
    cipher_operate(&ctx_de, 32, c1, p2);

    expect_equal(name, p1, p2, 32);
}

static void cipher_aes_test(int mode, const char* name) {
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

    cipher_ctx_t ctx_en;
    cipher_ctx_t ctx_de;
    char namex[32] = "";

    cipher_init(&ctx_en, ALG_AES, 128, key, mode, key, false);
    cipher_init(&ctx_de, ALG_AES, 128, key, mode, key, true);
    cipher_operate(&ctx_en, 32, p1, c1);
    cipher_operate(&ctx_de, 32, c1, p2);
    sprintf(namex, "128 %s", name);
    expect_equal(namex, p1, p2, 32);

    cipher_init(&ctx_en, ALG_AES, 192, key, mode, key, false);
    cipher_init(&ctx_de, ALG_AES, 192, key, mode, key, true);
    cipher_operate(&ctx_en, 32, p1, c1);
    cipher_operate(&ctx_de, 32, c1, p2);
    sprintf(namex, "192 %s", name);
    expect_equal(namex, p1, p2, 32);

    cipher_init(&ctx_en, ALG_AES, 256, key, mode, key, false);
    cipher_init(&ctx_de, ALG_AES, 256, key, mode, key, true);
    cipher_operate(&ctx_en, 32, p1, c1);
    cipher_operate(&ctx_de, 32, c1, p2);
    sprintf(namex, "256 %s", name);
    expect_equal(namex, p1, p2, 32);
}

static void sm3_test() {
    uint8_t data1[] = {'a', 'b', 'c'};
    uint8_t digest1[32] = {
        0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9, 0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10, 0xe4, 0xe2,
        0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2, 0x29, 0x7d, 0xa0, 0x2b, 0x8f, 0x4b, 0xa8, 0xe0
    };
    uint8_t data2[64] = {
        0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
        0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
        0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
        0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
    };
    uint8_t digest2[32] = {
        0xde, 0xbe, 0x9f, 0xf9, 0x22, 0x75, 0xb8, 0xa1, 0x38, 0x60, 0x48, 0x89, 0xc1, 0x8e, 0x5a, 0x4d,
        0x6f, 0xdb, 0x70, 0xe5, 0x38, 0x7e, 0x57, 0x65, 0x29, 0x3d, 0xcb, 0xa3, 0x9c, 0x0c, 0x57, 0x32
    };
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


int main() {
    sm4_test();
    aes_test();

    cipher_sm4_test(MODE_ECB, "SM4 MODE_ECB");
    cipher_sm4_test(MODE_CBC, "SM4 MODE_CBC");
    cipher_sm4_test(MODE_CFB, "SM4 MODE_CFB");
    cipher_sm4_test(MODE_OFB, "SM4 MODE_OFB");

    cipher_aes_test(MODE_ECB, "AES MODE_ECB");
    cipher_aes_test(MODE_CBC, "AES MODE_CBC");
    cipher_aes_test(MODE_CFB, "AES MODE_CFB");
    cipher_aes_test(MODE_OFB, "AES MODE_OFB");

    sm3_test();
    md5_test();
    sha1_test();
}
