#ifndef _Z_CRYPTO_AES_H_
#define _Z_CRYPTO_AES_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define AES_FUNC_DEF_NO_IV(KEY, MODE, EN) void aes_ ## KEY ## _ ## MODE ## _ ## EN (const uint8_t *, size_t, const uint8_t*, uint8_t*)
#define AES_FUNC_DEF_HAS_IV(KEY, MODE, EN) void aes_ ## KEY ## _ ## MODE ## _ ## EN (const uint8_t *, const uint8_t*, size_t, const uint8_t*, uint8_t*)

#define AES_FUNC_DEF(KEY) \
AES_FUNC_DEF_NO_IV(KEY, ecb, encrypt); \
AES_FUNC_DEF_NO_IV(KEY, ecb, decrypt); \
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


void aes_cipher_gen_key(const uint8_t *key, size_t keylen, uint32_t *rkey, bool decrypt);
void aes_cipher_block_encrypt(const uint32_t *rkey, size_t keylen, const uint8_t *plain, uint8_t *cipher);
void aes_cipher_block_decrypt(const uint32_t *rkey, size_t keylen, const uint8_t *cipher, uint8_t *plain);

# ifdef __cplusplus
}
# endif

#endif
