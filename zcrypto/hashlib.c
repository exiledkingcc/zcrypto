#include <assert.h>
#include "hash.h"
#include "hashlib.h"
#include "sm3.h"
#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include "utils.h"

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

static const hash_blk_update_func BLK_UPDATE_FUNCS[] = {
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
