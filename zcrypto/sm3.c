#include "sm3.h"
#include "utils.h"

#define T0 0x79cc4519ul
#define T1 0x7a879d8aul

static inline uint32_t _p0(uint32_t x) {
    return x ^ _lshift(x, 9) ^ _lshift(x, 17);
}

static inline uint32_t _p1(uint32_t x) {
    return x ^ _lshift(x, 15) ^ _lshift(x, 23);
}

static inline uint32_t _ff0(uint32_t x, uint32_t y, uint32_t z) {
    return x ^ y ^ z;
}

static inline uint32_t _ff1(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) | (x & z) | (y & z);
}

static inline uint32_t _gg0(uint32_t x, uint32_t y, uint32_t z) {
    return x ^ y ^ z;
}

static inline uint32_t _gg1(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) | ((~x) & z);
}

#define CF(A, B, C, D, E, F, G, H, TT, FF, GG, i) \
do { \
    uint32_t SS1 = _lshift(_lshift(A, 12) + E + _lshift(TT, i % 32), 7); \
    uint32_t SS2 = SS1 ^ _lshift(A, 12); \
    uint32_t TT1 = FF(A, B, C) + D + SS2 + (W[i] ^ W[i + 4]);  /* W'(j) = W(j) ^ W(j + 4) */ \
    uint32_t TT2 = GG(E, F, G) + H + SS1 + W[i]; \
    D = C; \
    C = _lshift(B, 9); \
    B = A; \
    A = TT1; \
    H = G; \
    G = _lshift(F, 19); \
    F = E; \
    E = _p0(TT2); \
} while (0)


static void sm3_blk_update(uint32_t hash[8], const uint8_t data[64]) {
    uint32_t W[68];
    for (int i = 0; i < 16; ++i) {
        W[i] = _load_u32(data + i * 4);
    }
    for (int i = 16; i < 68; ++i) {
        W[i] = _p1(W[i - 16] ^ W[i - 9] ^ _lshift(W[i - 3] , 15)) ^ _lshift(W[i - 13], 7) ^ W[i -6];
    }

    uint32_t A = hash[0];
    uint32_t B = hash[1];
    uint32_t C = hash[2];
    uint32_t D = hash[3];
    uint32_t E = hash[4];
    uint32_t F = hash[5];
    uint32_t G = hash[6];
    uint32_t H = hash[7];
    for (int i = 0; i < 16; ++i) {
        CF(A, B, C, D, E, F, G, H, T0, _ff0, _gg0, i);
    }
    for (int i = 16; i < 64; ++i) {
        CF(A, B, C, D, E, F, G, H, T1, _ff1, _gg1, i);
    }
    hash[0] ^= A;
    hash[1] ^= B;
    hash[2] ^= C;
    hash[3] ^= D;
    hash[4] ^= E;
    hash[5] ^= F;
    hash[6] ^= G;
    hash[7] ^= H;
}

static inline void _store_len(uint64_t len, uint8_t data[8]) {
    len *= 8;
    _store_u32(len >> 32, data);
    _store_u32(len & 0xffffffffull, data + 4);
}

static void sm3_blk_done(uint32_t hash[8], const uint8_t *data, uint64_t total) {
    uint8_t blk[64];
    size_t len = total % 64;
    if (len == 0) {
        memset(blk, 0, 56);
        blk[0] = 0x80;
        _store_len(total, blk + 56);
        sm3_blk_update(hash, blk);
    } else {
        memcpy(blk, data, len);
        blk[len] = 0x80;
        ++len;
        if (len <= 56) {
            if (len != 56) {
                memset(blk + len, 0, 56 - len);
            }
            _store_len(total, blk + 56);
            sm3_blk_update(hash, blk);
        } else {
            if (len < 64) {
                memset(blk + len, 0, 64 - len);
            }
            sm3_blk_update(hash, blk);
            memset(blk, 0, 56);
            _store_len(total, blk + 56);
            sm3_blk_update(hash, blk);
        }
    }
}


void sm3_init(sm3_ctx_t *ctx) {
    memset(ctx, 0, sizeof(sm3_ctx_t));
    ctx->hash[0] = 0x7380166ful;
    ctx->hash[1] = 0x4914b2b9ul;
    ctx->hash[2] = 0x172442d7ul;
    ctx->hash[3] = 0xda8a0600ul;
    ctx->hash[4] = 0xa96f30bcul;
    ctx->hash[5] = 0x163138aaul;
    ctx->hash[6] = 0xe38dee4dul;
    ctx->hash[7] = 0xb0fb0e4eul;
}

void sm3_update(sm3_ctx_t *ctx, const uint8_t *data, size_t len) {
    const uint8_t *end = data + len;
    const uint8_t *p = data;
    for (; p + 64 <= end; p += 64) {
        sm3_blk_update(ctx->hash, p);
    }
    ctx->len += len;
    if (p < end) {
        memcpy(ctx->blk, p, end - p);
    }
}

void sm3_digest(sm3_ctx_t *ctx, uint8_t *data) {
    uint32_t hash[8];
    memcpy(hash, ctx->hash, 32);
    sm3_blk_done(hash, ctx->blk, ctx->len);
    _store_u32(hash[0], data);
    _store_u32(hash[1], data + 4);
    _store_u32(hash[2], data + 8);
    _store_u32(hash[3], data + 12);
    _store_u32(hash[4], data + 16);
    _store_u32(hash[5], data + 20);
    _store_u32(hash[6], data + 24);
    _store_u32(hash[7], data + 28);
}

void sm3_hexdigest(sm3_ctx_t *ctx, uint8_t *data) {
    sm3_digest(ctx, data);
    _expand_hex(data, 32);
}
