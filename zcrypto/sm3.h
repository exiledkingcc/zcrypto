#ifndef _Z_CRYPTO_SM3_H_
#define _Z_CRYPTO_SM3_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <string.h>

typedef struct {
    uint64_t len;
    uint32_t hash[8];
    uint8_t blk[64];
} sm3_ctx_t;

void sm3_init(sm3_ctx_t *ctx);
void sm3_update(sm3_ctx_t *ctx, const uint8_t *data, size_t len);
void sm3_digest(sm3_ctx_t *ctx, uint8_t *data);
void sm3_hexdigest(sm3_ctx_t *ctx, uint8_t *data);

void sm3_blk_update(uint32_t hash[8], const uint8_t blk[64]);

# ifdef __cplusplus
}
# endif

#endif
