#include <assert.h>
#include "hash.h"
#include "utils.h"

void _hash_update(hash_blk_update_func blk_update, uint32_t *hash, uint8_t *blk, const uint8_t *data, size_t len, uint64_t *total) {
    size_t offset = *total % HASH_BLK_SIZE;
    if (offset + len < HASH_BLK_SIZE) {
        memcpy(blk + offset, data, len);
        *total += len;
        return;
    }

    const uint8_t *end = data + len;
    const uint8_t *p = data;
    if (offset != 0) {
        memcpy(blk + offset, p, HASH_BLK_SIZE - offset);
        blk_update(hash, blk);
        p += HASH_BLK_SIZE - offset;
    }
    for (; p + HASH_BLK_SIZE <= end; p += HASH_BLK_SIZE) {
        blk_update(hash, p);
    }
    if (p < end) {
        memcpy(blk, p, (size_t)(end - p));
    }
    *total += len;
}

#define BLK_DATA_SZIE (HASH_BLK_SIZE - 8)

static void hash_store_len(uint64_t len, uint8_t data[8], bool le) {
    if (le) {
        _hash_store_len(le, len, data);
    } else {
        _hash_store_len(be, len, data);
    }
}

void _hash_done(hash_blk_update_func blk_update, uint32_t *hash, const uint8_t *data, uint64_t total, bool le) {
    uint8_t blk[HASH_BLK_SIZE];
    memset(blk, 0, HASH_BLK_SIZE);
    size_t len = total % HASH_BLK_SIZE;
    if (len > 0) {
        memcpy(blk, data, len);
    }

    blk[len] = 0x80;
    if (len < BLK_DATA_SZIE) {
        hash_store_len(total, blk + BLK_DATA_SZIE, le);
        blk_update(hash, blk);
    } else {
        blk_update(hash, blk);
        memset(blk, 0, HASH_BLK_SIZE);
        hash_store_len(total, blk + BLK_DATA_SZIE, le);
        blk_update(hash, blk);
    }
}

extern void sm3_hash_init(uint32_t*);
extern void md5_hash_init(uint32_t*);
extern void sha1_hash_init(uint32_t*);
extern void sha256_hash_init(uint32_t*);

extern void sm3_blk_update(uint32_t *hash, const uint8_t *blk);
extern void md5_blk_update(uint32_t *hash, const uint8_t *blk);
extern void sha1_blk_update(uint32_t *hash, const uint8_t *blk);
extern void sha256_blk_update(uint32_t *hash, const uint8_t *blk);


void hash_init(hash_ctx_t *ctx, int alg) {
    assert(alg == HASH_ALG_SM3 || alg == HASH_ALG_MD5 || alg == HASH_ALG_SHA1 || alg == HASH_ALG_SHA256);
    memset(ctx, 0, sizeof(hash_ctx_t));
    ctx->alg = alg;
    switch (alg) {
        case HASH_ALG_SM3:
            ctx->hlen = 8;
            sm3_hash_init(ctx->hash);
            break;
        case HASH_ALG_MD5:
            ctx->hlen = 4;
            md5_hash_init(ctx->hash);
            break;
        case HASH_ALG_SHA1:
            ctx->hlen = 5;
            sha1_hash_init(ctx->hash);
            break;
        case HASH_ALG_SHA256:
            ctx->hlen = 8;
            sha256_hash_init(ctx->hash);
            break;
    }
}

static hash_blk_update_func BLK_UPDATE_FUNCS[] = {
    NULL,
    sm3_blk_update,
    md5_blk_update,
    sha1_blk_update,
    sha256_blk_update,
};

void hash_update(hash_ctx_t *ctx, const uint8_t *data, size_t len) {
    hash_blk_update_func update = BLK_UPDATE_FUNCS[ctx->alg];
    _hash_update(update, ctx->hash, ctx->blk, data, len, &ctx->len);
}

void hash_digest(hash_ctx_t *ctx, uint8_t *data) {
    uint32_t hash[8];
    memcpy(hash, ctx->hash, ctx->hlen * 4);
    hash_blk_update_func update = BLK_UPDATE_FUNCS[ctx->alg];
    if (ctx->alg == HASH_ALG_MD5) {
        _hash_done(update, hash, ctx->blk, ctx->len, true);
        _hash_digest(le, hash, ctx->hlen, data);
    } else {
        _hash_done(update, hash, ctx->blk, ctx->len, false);
        _hash_digest(be, hash, ctx->hlen, data);
    }
}

void hash_hexdigest(hash_ctx_t *ctx, uint8_t *data) {
    hash_digest(ctx, data);
    _expand_hex(data, ctx->hlen * 4);
}
