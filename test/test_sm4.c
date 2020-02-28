#include <stdio.h>
#include "zcrypto/sm4.h"

static void expect_equal(const char *name, const uint8_t *a, const uint8_t *b, size_t len) {
    if (memcmp(a, b, len) == 0) {
        printf("%s OK!\n", name);
    } else {
        printf("%s FAIL!\n", name);
    }
}

static void sm4_test(void) {
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

    memset(plain2, 0, 16);
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

static void sm4_ctx_test(int mode, const char* name) {
    uint8_t key[] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

    uint8_t p1[32];
    uint8_t p2[32];
    uint8_t c1[32];
    for (int i = 0; i < 32; ++i) {
        p1[i] = (i * i) & 0xff;
    }
    memset(p2, 0, 32);
    memset(c1, 0, 32);

    const uint8_t *iv = NULL;
    if (mode != SM4_ECB_MODE) {
        iv = key;
    }

    sm4_ctx_t ctx_en;
    sm4_ctx_t ctx_de;
    int r = sm4_init(&ctx_en, mode, key, iv);
    if (r != 0) {
        printf("sm4_init(%s | SM4_ENCRYPT) FAIL!\n", name);
        return;
    }
    r = sm4_init(&ctx_de, mode, key, iv);
    if (r != 0) {
        printf("sm4_init(%s | SM4_DECRYPT) FAIL!\n", name);
        return;
    }

    r = sm4_encrypt(&ctx_en, 16, p1, c1);
    r = sm4_encrypt(&ctx_en, 16, p1 + 16, c1 + 16);
    if (r != 0) {
        printf("sm4_encrypt(%s) FAIL!\n", name);
        return;
    }
    r = sm4_decrypt(&ctx_de, 32, c1, p2);
    if (r != 0) {
        printf("sm4_decrypt(%s) FAIL!\n", name);
        return;
    }

    expect_equal(name, p1, p2, 32);
}

int main() {
    sm4_test();

    sm4_ctx_test(SM4_ECB_MODE, "SM4_ECB_MODE");
    sm4_ctx_test(SM4_CBC_MODE, "SM4_CBC_MODE");
    sm4_ctx_test(SM4_CFB_MODE, "SM4_CFB_MODE");
    sm4_ctx_test(SM4_OFB_MODE, "SM4_OFB_MODE");

}
