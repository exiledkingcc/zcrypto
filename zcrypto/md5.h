#ifndef _Z_CRYPTO_MD5_H_
#define _Z_CRYPTO_MD5_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <string.h>

typedef struct {
    uint64_t len;
    uint32_t hash[4];
    uint8_t blk[64];
} md5_ctx_t;

void md5_init(md5_ctx_t *ctx);
void md5_update(md5_ctx_t *ctx, const uint8_t *data, size_t len);
void md5_digest(md5_ctx_t *ctx, uint8_t *data);
void md5_hexdigest(md5_ctx_t *ctx, uint8_t *data);

void md5_blk_update(uint32_t hash[4], const uint8_t blk[64]);

# ifdef __cplusplus
}
# endif

#endif
