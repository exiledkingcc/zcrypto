#include "sha1.h"
#include "utils.h"

static inline uint32_t _f0(uint32_t B, uint32_t C, uint32_t D) {
    return (B & C) | (~B & D);
}

static inline uint32_t _f1(uint32_t B, uint32_t C, uint32_t D) {
    return B ^ C ^ D;
}

static inline uint32_t _f2(uint32_t B, uint32_t C, uint32_t D) {
    return (B & C) | (B & D) | (C & D);
}

static inline uint32_t _f3(uint32_t B, uint32_t C, uint32_t D) {
    return B ^ C ^ D;
}

#define K0 0x5a827999ul
#define K1 0x6ed9eba1ul
#define K2 0x8f1bbcdcul
#define K3 0xca62c1d6ul

static void sha1_blk_update(uint32_t hash[5], const uint8_t data[64]) {
    uint32_t W[80];
    for (int i = 0; i < 16; ++i) {
        W[i] = _load_be_u32(data + i * 4);
    }
    for (int i = 16; i < 80; ++i) {
        W[i] = _lshift(W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16], 1);
    }
    uint32_t A = hash[0];
    uint32_t B = hash[1];
    uint32_t C = hash[2];
    uint32_t D = hash[3];
    uint32_t E = hash[4];

    #define ROUND(N, i) do { \
        uint32_t temp = _lshift(A, 5) + _f##N(B, C, D) + E + W[i] + K##N; \
        E = D; \
        D = C; \
        C = _lshift(B, 30); \
        B = A; \
        A = temp; \
    } while (0)

    for (int i = 0; i < 20; ++i) {
        ROUND(0, i);
    }
    for (int i = 20; i < 40; ++i) {
        ROUND(1, i);
    }
    for (int i = 40; i < 60; ++i) {
        ROUND(2, i);
    }
    for (int i = 60; i < 80; ++i) {
        ROUND(3, i);
    }

    #undef ROUND

    hash[0] += A;
    hash[1] += B;
    hash[2] += C;
    hash[3] += D;
    hash[4] += E;
}

static inline void _store_len(uint64_t len, uint8_t data[8]) {
    len *= 8;
    _store_be_u64(len, data);
}

static void sha1_blk_done(uint32_t hash[5], const uint8_t *data, uint64_t total) {
    uint8_t blk[64];
    size_t len = total % 64;
    if (len == 0) {
        memset(blk, 0, 56);
        blk[0] = 0x80;
        _store_len(total, blk + 56);
        sha1_blk_update(hash, blk);
    } else {
        memcpy(blk, data, len);
        blk[len] = 0x80;
        ++len;
        if (len <= 56) {
            if (len != 56) {
                memset(blk + len, 0, 56 - len);
            }
            _store_len(total, blk + 56);
            sha1_blk_update(hash, blk);
        } else {
            if (len < 64) {
                memset(blk + len, 0, 64 - len);
            }
            sha1_blk_update(hash, blk);
            memset(blk, 0, 56);
            _store_len(total, blk + 56);
            sha1_blk_update(hash, blk);
        }
    }
}


void sha1_init(sha1_ctx_t *ctx) {
    memset(ctx, 0, sizeof(sha1_ctx_t));
    ctx->hash[0] = 0x67452301ul;
    ctx->hash[1] = 0xefcdab89ul;
    ctx->hash[2] = 0x98badcfeul;
    ctx->hash[3] = 0x10325476ul;
    ctx->hash[4] = 0xc3d2e1f0ul;
}

void sha1_update(sha1_ctx_t *ctx, const uint8_t *data, size_t len) {
    const uint8_t *end = data + len;
    const uint8_t *p = data;
    for (; p + 64 <= end; p += 64) {
        sha1_blk_update(ctx->hash, p);
    }
    ctx->len += len;
    if (p < end) {
        memcpy(ctx->blk, p, end - p);
    }
}

void sha1_digest(sha1_ctx_t *ctx, uint8_t *data) {
    uint32_t hash[5];
    memcpy(hash, ctx->hash, 20);
    sha1_blk_done(hash, ctx->blk, ctx->len);
    _store_be_u32(hash[0], data);
    _store_be_u32(hash[1], data + 4);
    _store_be_u32(hash[2], data + 8);
    _store_be_u32(hash[3], data + 12);
    _store_be_u32(hash[4], data + 16);
}

void sha1_hexdigest(sha1_ctx_t *ctx, uint8_t *data) {
    sha1_digest(ctx, data);
    _expand_hex(data, 20);
}
