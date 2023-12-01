#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

#define HASH_ALG_SM3 1
#define HASH_ALG_MD5 2
#define HASH_ALG_SHA1 3
#define HASH_ALG_SHA256 4

typedef struct {
    uint64_t len;
    uint32_t hash[8];
    uint8_t blk[64];
    size_t hlen;
    int alg;
} hash_ctx_t;

void hash_init(hash_ctx_t* ctx, int alg);
void hash_update(hash_ctx_t* ctx, const uint8_t* data, size_t len);
void hash_digest(hash_ctx_t* ctx, uint8_t* data);
void hash_hexdigest(hash_ctx_t* ctx, uint8_t* data);

#ifdef __cplusplus
}
#endif
