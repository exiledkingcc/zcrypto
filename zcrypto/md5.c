#include "md5.h"
#include "hash.h"
#include "utils.h"

static const uint32_t TT[] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

static inline uint32_t F(uint32_t B, uint32_t C, uint32_t D) {
    return (B & C) | (~B & D);
}

static inline uint32_t G(uint32_t B, uint32_t C, uint32_t D) {
    return (B & D) | (C & ~D);
}

static inline uint32_t H(uint32_t B, uint32_t C, uint32_t D) {
    return B ^ C ^ D;
}

static inline uint32_t I(uint32_t B, uint32_t C, uint32_t D) {
    return C ^ (B | ~D);
}

#define FF(A, B, C, D, X, T, S) A = B + _lshift(A + F(B, C, D) + X + T, S)
#define GG(A, B, C, D, X, T, S) A = B + _lshift(A + G(B, C, D) + X + T, S)
#define HH(A, B, C, D, X, T, S) A = B + _lshift(A + H(B, C, D) + X + T, S)
#define II(A, B, C, D, X, T, S) A = B + _lshift(A + I(B, C, D) + X + T, S)

void md5_blk_update(uint32_t hash[4], const uint8_t data[64]) {
    uint32_t W[16];
    for (int i = 0; i < 16; ++i) {
        W[i] = _load_le_u32(data + i * 4);
    }
    uint32_t A = hash[0];
    uint32_t B = hash[1];
    uint32_t C = hash[2];
    uint32_t D = hash[3];

    // round 1
    FF(A, B, C, D, W[ 0], TT[ 0],  7);
    FF(D, A, B, C, W[ 1], TT[ 1], 12);
    FF(C, D, A, B, W[ 2], TT[ 2], 17);
    FF(B, C, D, A, W[ 3], TT[ 3], 22);
    FF(A, B, C, D, W[ 4], TT[ 4],  7);
    FF(D, A, B, C, W[ 5], TT[ 5], 12);
    FF(C, D, A, B, W[ 6], TT[ 6], 17);
    FF(B, C, D, A, W[ 7], TT[ 7], 22);
    FF(A, B, C, D, W[ 8], TT[ 8],  7);
    FF(D, A, B, C, W[ 9], TT[ 9], 12);
    FF(C, D, A, B, W[10], TT[10], 17);
    FF(B, C, D, A, W[11], TT[11], 22);
    FF(A, B, C, D, W[12], TT[12],  7);
    FF(D, A, B, C, W[13], TT[13], 12);
    FF(C, D, A, B, W[14], TT[14], 17);
    FF(B, C, D, A, W[15], TT[15], 22);
    // round 2
    GG(A, B, C, D, W[ 1], TT[16],  5);
    GG(D, A, B, C, W[ 6], TT[17],  9);
    GG(C, D, A, B, W[11], TT[18], 14);
    GG(B, C, D, A, W[ 0], TT[19], 20);
    GG(A, B, C, D, W[ 5], TT[20],  5);
    GG(D, A, B, C, W[10], TT[21],  9);
    GG(C, D, A, B, W[15], TT[22], 14);
    GG(B, C, D, A, W[ 4], TT[23], 20);
    GG(A, B, C, D, W[ 9], TT[24],  5);
    GG(D, A, B, C, W[14], TT[25],  9);
    GG(C, D, A, B, W[ 3], TT[26], 14);
    GG(B, C, D, A, W[ 8], TT[27], 20);
    GG(A, B, C, D, W[13], TT[28],  5);
    GG(D, A, B, C, W[ 2], TT[29],  9);
    GG(C, D, A, B, W[ 7], TT[30], 14);
    GG(B, C, D, A, W[12], TT[31], 20);
    // round 3
    HH(A, B, C, D, W[ 5], TT[32],  4);
    HH(D, A, B, C, W[ 8], TT[33], 11);
    HH(C, D, A, B, W[11], TT[34], 16);
    HH(B, C, D, A, W[14], TT[35], 23);
    HH(A, B, C, D, W[ 1], TT[36],  4);
    HH(D, A, B, C, W[ 4], TT[37], 11);
    HH(C, D, A, B, W[ 7], TT[38], 16);
    HH(B, C, D, A, W[10], TT[39], 23);
    HH(A, B, C, D, W[13], TT[40],  4);
    HH(D, A, B, C, W[ 0], TT[41], 11);
    HH(C, D, A, B, W[ 3], TT[42], 16);
    HH(B, C, D, A, W[ 6], TT[43], 23);
    HH(A, B, C, D, W[ 9], TT[44],  4);
    HH(D, A, B, C, W[12], TT[45], 11);
    HH(C, D, A, B, W[15], TT[46], 16);
    HH(B, C, D, A, W[ 2], TT[47], 23);
    // round 4
    II(A, B, C, D, W[ 0], TT[48],  6);
    II(D, A, B, C, W[ 7], TT[49], 10);
    II(C, D, A, B, W[14], TT[50], 15);
    II(B, C, D, A, W[ 5], TT[51], 21);
    II(A, B, C, D, W[12], TT[52],  6);
    II(D, A, B, C, W[ 3], TT[53], 10);
    II(C, D, A, B, W[10], TT[54], 15);
    II(B, C, D, A, W[ 1], TT[55], 21);
    II(A, B, C, D, W[ 8], TT[56],  6);
    II(D, A, B, C, W[15], TT[57], 10);
    II(C, D, A, B, W[ 6], TT[58], 15);
    II(B, C, D, A, W[13], TT[59], 21);
    II(A, B, C, D, W[ 4], TT[60], 6);
    II(D, A, B, C, W[11], TT[61], 10);
    II(C, D, A, B, W[ 2], TT[62], 15);
    II(B, C, D, A, W[ 9], TT[63], 21);

    hash[0] += A;
    hash[1] += B;
    hash[2] += C;
    hash[3] += D;
}


void md5_init(md5_ctx_t *ctx) {
    memset(ctx, 0, sizeof(md5_ctx_t));
    ctx->hash[0] = 0x67452301ul;
    ctx->hash[1] = 0xefcdab89ul;
    ctx->hash[2] = 0x98badcfeul;
    ctx->hash[3] = 0x10325476ul;
}

void md5_update(md5_ctx_t *ctx, const uint8_t *data, size_t len) {
    _hash_update(md5_blk_update, ctx->hash, ctx->blk, data, len, &ctx->len);
}

void md5_digest(md5_ctx_t *ctx, uint8_t *data) {
    uint32_t hash[4];
    memcpy(hash, ctx->hash, 16);
    _hash_done(md5_blk_update, hash, ctx->blk, ctx->len, true);
    _hash_digest(le, hash, 4, data);
}

void md5_hexdigest(md5_ctx_t *ctx, uint8_t *data) {
    md5_digest(ctx, data);
    _expand_hex(data, 16);
}
