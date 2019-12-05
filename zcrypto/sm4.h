#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

void sm4_ecb_encrypt(const uint8_t key[16], size_t len, const uint8_t *plain, uint8_t *cipher);
void sm4_ecb_decrypt(const uint8_t key[16], size_t len, const uint8_t *cipher, uint8_t *plain);

void sm4_cbc_encrypt(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t *plain, uint8_t *cipher);
void sm4_cbc_decrypt(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t *cipher, uint8_t *plain);

void sm4_cfb_encrypt(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t *plain, uint8_t *cipher);
void sm4_cfb_decrypt(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t *cipher, uint8_t *plain);

void sm4_ofb_encrypt(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t *plain, uint8_t *cipher);
void sm4_ofb_decrypt(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t *cipher, uint8_t *plain);

void sm4_cipher_gen_key(const uint8_t key[16], size_t keylen, uint32_t rkey[32], bool decrypt);
void sm4_cipher_block_encrypt(const uint32_t rkey[32], size_t keylen, const uint8_t *plain, uint8_t *cipher);

# ifdef __cplusplus
}
# endif
