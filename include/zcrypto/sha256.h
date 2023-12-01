#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <string.h>

typedef struct {
    uint64_t len;
    uint32_t hash[8];
    uint8_t blk[64];
} sha256_ctx_t;

void sha256_init(sha256_ctx_t* ctx);
void sha256_update(sha256_ctx_t* ctx, const uint8_t* data, size_t len);
void sha256_digest(sha256_ctx_t* ctx, uint8_t* data);
void sha256_hexdigest(sha256_ctx_t* ctx, uint8_t* data);

void sha256_hash_init(uint32_t hash[8]);
void sha256_blk_update(uint32_t hash[8], const uint8_t blk[64]);

#ifdef __cplusplus
}
#endif
