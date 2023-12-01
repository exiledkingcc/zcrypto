#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define AES_FUNC_DEF_NO_IV(KEY, MODE, EN) void aes_##KEY##_##MODE##_##EN(const uint8_t*, size_t, const uint8_t*, uint8_t*)
#define AES_FUNC_DEF_HAS_IV(KEY, MODE, EN) void aes_##KEY##_##MODE##_##EN(const uint8_t*, const uint8_t*, size_t, const uint8_t*, uint8_t*)

#define AES_FUNC_DEF(KEY)                   \
    AES_FUNC_DEF_NO_IV(KEY, ecb, encrypt);  \
    AES_FUNC_DEF_NO_IV(KEY, ecb, decrypt);  \
                                            \
    AES_FUNC_DEF_HAS_IV(KEY, cbc, encrypt); \
    AES_FUNC_DEF_HAS_IV(KEY, cbc, decrypt); \
                                            \
    AES_FUNC_DEF_HAS_IV(KEY, cfb, encrypt); \
    AES_FUNC_DEF_HAS_IV(KEY, cfb, decrypt); \
                                            \
    AES_FUNC_DEF_HAS_IV(KEY, ofb, encrypt); \
    AES_FUNC_DEF_HAS_IV(KEY, ofb, decrypt);

AES_FUNC_DEF(128)

AES_FUNC_DEF(192)

AES_FUNC_DEF(256)

#define AES_ECB_MODE 1
#define AES_CBC_MODE 2
#define AES_CFB_MODE 3
#define AES_OFB_MODE 4

typedef struct {
    uint32_t rkey[60];
    uint8_t iv[16];
    size_t keylen;
    uint8_t mode;
} aes_ctx_t;

void aes_close(aes_ctx_t* ctx);
int aes_init(aes_ctx_t* ctx, uint8_t mode, size_t keylen, const uint8_t* key, const uint8_t iv[16]);
int aes_encrypt(aes_ctx_t* ctx, size_t len, const uint8_t* plain, uint8_t* cipher);
int aes_decrypt(aes_ctx_t* ctx, size_t len, const uint8_t* cipher, uint8_t* plain);

#ifdef __cplusplus
}
#endif
