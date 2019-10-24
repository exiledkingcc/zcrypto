#ifndef _Z_CRYPTO_CIPHER_H_
#define _Z_CRYPTO_CIPHER_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define BLOCK_SIZE 16

#define ALG_AES 1
#define ALG_SM4 2

#define MODE_ECB 1
#define MODE_CBC 2
#define MODE_CFB 3
#define MODE_OFB 4

typedef struct cipher_ctx cipher_ctx_t;

typedef void (*cipher_block_funct_t)(const uint32_t*, size_t keylen, const uint8_t*, uint8_t*);
typedef void (*cipher_mode_func_t)(cipher_ctx_t*, const uint8_t*, uint8_t*);

struct cipher_ctx {
    cipher_block_funct_t blk_func;
    cipher_mode_func_t mode_func;
    uint32_t rkey[60];
    uint8_t blk[BLOCK_SIZE];
    size_t keylen;
};

void cipher_init(cipher_ctx_t *ctx, int alg, size_t key_len, uint8_t *key, int mode, uint8_t *iv, bool decrypt);
void cipher_operate(cipher_ctx_t *ctx, size_t len, const uint8_t *in, uint8_t *out);

# ifdef __cplusplus
}
# endif

#endif
