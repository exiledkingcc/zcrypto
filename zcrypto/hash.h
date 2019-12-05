#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define HASH_BLK_SIZE 64

typedef void (*hash_blk_update_func)(uint32_t*, const uint8_t*);
void _hash_update(hash_blk_update_func blk_update, uint32_t *hash, uint8_t *blk, const uint8_t *data, size_t len, uint64_t *total);
void _hash_done(hash_blk_update_func blk_update, uint32_t *hash, const uint8_t *data, uint64_t total, bool le);

#define _hash_store_len(EE, LEN, DATA) do { \
    LEN *= 8; \
    _store_##EE##_u64(LEN, DATA); \
} while (0)

#define _hash_digest(EE, HASH, LEN, DATA)  do { \
    for (int i = 0; i < LEN; ++i) { \
        _store_##EE##_u32(HASH[i], DATA + i * 4); \
    } \
} while (0)


#define HASH_ALG_SM3    1
#define HASH_ALG_MD5    2
#define HASH_ALG_SHA1   3
#define HASH_ALG_SHA256 4

typedef struct {
    uint64_t len;
    uint32_t hash[8];
    uint8_t blk[64];
    int alg;
    int hlen;
} hash_ctx_t;

void hash_init(hash_ctx_t *ctx, int alg);
void hash_update(hash_ctx_t *ctx, const uint8_t *data, size_t len);
void hash_digest(hash_ctx_t *ctx, uint8_t *data);
void hash_hexdigest(hash_ctx_t *ctx, uint8_t *data);


# ifdef __cplusplus
}
# endif
