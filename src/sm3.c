#include "zcrypto/sm3.h"
#include "zcrypto/hash.h"
#include "zcrypto/utils.h"

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


void sm3_blk_update(uint32_t hash[8], const uint8_t data[64]) {
    uint32_t W[68];
    for (int i = 0; i < 16; ++i) {
        W[i] = _load_be_u32(data + i * 4);
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

void sm3_hash_init(uint32_t hash[8]) {
    hash[0] = 0x7380166ful;
    hash[1] = 0x4914b2b9ul;
    hash[2] = 0x172442d7ul;
    hash[3] = 0xda8a0600ul;
    hash[4] = 0xa96f30bcul;
    hash[5] = 0x163138aaul;
    hash[6] = 0xe38dee4dul;
    hash[7] = 0xb0fb0e4eul;
}


void sm3_init(sm3_ctx_t *ctx) {
    memset(ctx, 0, sizeof(sm3_ctx_t));
    sm3_hash_init(ctx->hash);
}

void sm3_update(sm3_ctx_t *ctx, const uint8_t *data, size_t len) {
    _hash_update(sm3_blk_update, ctx->hash, ctx->blk, data, len, &ctx->len);
}

void sm3_digest(sm3_ctx_t *ctx, uint8_t *data) {
    uint32_t hash[8];
    memcpy(hash, ctx->hash, 32);
    _hash_done(sm3_blk_update, hash, ctx->blk, ctx->len, false);
    _hash_digest(be, hash, 8, data);
}

void sm3_hexdigest(sm3_ctx_t *ctx, uint8_t *data) {
    sm3_digest(ctx, data);
    _expand_hex(data, 32);
}