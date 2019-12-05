#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <string.h>

typedef struct {
    uint64_t len;
    uint32_t hash[5];
    uint8_t blk[64];
} sha1_ctx_t;

void sha1_init(sha1_ctx_t *ctx);
void sha1_update(sha1_ctx_t *ctx, const uint8_t *data, size_t len);
void sha1_digest(sha1_ctx_t *ctx, uint8_t *data);
void sha1_hexdigest(sha1_ctx_t *ctx, uint8_t *data);

void sha1_hash_init(uint32_t hash[5]);
void sha1_blk_update(uint32_t hash[5], const uint8_t blk[64]);

# ifdef __cplusplus
}
# endif
