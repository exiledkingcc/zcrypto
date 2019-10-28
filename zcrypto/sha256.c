#include "sha256.h"
#include "utils.h"

static inline uint32_t CH(uint32_t X, uint32_t Y, uint32_t Z) {
    return (X & Y) ^ (~X & Z);
}

static inline uint32_t MAJ(uint32_t X, uint32_t Y, uint32_t Z) {
    return (X & Y) ^ (X & Z) ^ (Y & Z);
}

static inline uint32_t BSIG0(uint32_t X) {
    return _rshift(X, 2) ^ _rshift(X, 13) ^ _rshift(X, 22);
}

static inline uint32_t BSIG1(uint32_t X) {
    return _rshift(X, 6) ^ _rshift(X, 11) ^ _rshift(X, 25);
}

static inline uint32_t SSIG0(uint32_t X) {
    return _rshift(X, 7) ^ _rshift(X, 18) ^ (X >> 3);
}

static inline uint32_t SSIG1(uint32_t X) {
    return _rshift(X, 17) ^ _rshift(X, 19) ^ (X >> 10);
}

static const uint32_t K[] = {
    0x428a2f98ul, 0x71374491ul, 0xb5c0fbcful, 0xe9b5dba5ul,
    0x3956c25bul, 0x59f111f1ul, 0x923f82a4ul, 0xab1c5ed5ul,
    0xd807aa98ul, 0x12835b01ul, 0x243185beul, 0x550c7dc3ul,
    0x72be5d74ul, 0x80deb1feul, 0x9bdc06a7ul, 0xc19bf174ul,
    0xe49b69c1ul, 0xefbe4786ul, 0x0fc19dc6ul, 0x240ca1ccul,
    0x2de92c6ful, 0x4a7484aaul, 0x5cb0a9dcul, 0x76f988daul,
    0x983e5152ul, 0xa831c66dul, 0xb00327c8ul, 0xbf597fc7ul,
    0xc6e00bf3ul, 0xd5a79147ul, 0x06ca6351ul, 0x14292967ul,
    0x27b70a85ul, 0x2e1b2138ul, 0x4d2c6dfcul, 0x53380d13ul,
    0x650a7354ul, 0x766a0abbul, 0x81c2c92eul, 0x92722c85ul,
    0xa2bfe8a1ul, 0xa81a664bul, 0xc24b8b70ul, 0xc76c51a3ul,
    0xd192e819ul, 0xd6990624ul, 0xf40e3585ul, 0x106aa070ul,
    0x19a4c116ul, 0x1e376c08ul, 0x2748774cul, 0x34b0bcb5ul,
    0x391c0cb3ul, 0x4ed8aa4aul, 0x5b9cca4ful, 0x682e6ff3ul,
    0x748f82eeul, 0x78a5636ful, 0x84c87814ul, 0x8cc70208ul,
    0x90befffaul, 0xa4506cebul, 0xbef9a3f7ul, 0xc67178f2ul,
};

static void sha256_blk_update(uint32_t hash[8], const uint8_t data[64]) {
    uint32_t W[64];
    for (int i = 0; i < 16; ++i) {
        W[i] = _load_be_u32(data + i * 4);
    }
    for (int i = 16; i < 64; ++i) {
        W[i] = SSIG1(W[i - 2]) + W[i - 7] + SSIG0(W[i - 15]) + W[i - 16];
    }
    uint32_t A = hash[0];
    uint32_t B = hash[1];
    uint32_t C = hash[2];
    uint32_t D = hash[3];
    uint32_t E = hash[4];
    uint32_t F = hash[5];
    uint32_t G = hash[6];
    uint32_t H = hash[7];

    for (int i = 0; i < 64; ++i) {
        uint32_t t1 = H + BSIG1(E) + CH(E, F, G) + K[i] + W[i];
        uint32_t t2 = BSIG0(A) + MAJ(A, B, C);
        H = G;
        G = F;
        F = E;
        E = D + t1;
        D = C;
        C = B;
        B = A;
        A = t1 + t2;
    }

    hash[0] += A;
    hash[1] += B;
    hash[2] += C;
    hash[3] += D;
    hash[4] += E;
    hash[5] += F;
    hash[6] += G;
    hash[7] += H;
}

static inline void _store_len(uint64_t len, uint8_t data[8]) {
    len *= 8;
    _store_be_u64(len, data);
}

static void sha256_blk_done(uint32_t hash[8], const uint8_t *data, uint64_t total) {
    uint8_t blk[64];
    size_t len = total % 64;
    if (len == 0) {
        memset(blk, 0, 56);
        blk[0] = 0x80;
        _store_len(total, blk + 56);
        sha256_blk_update(hash, blk);
    } else {
        memcpy(blk, data, len);
        blk[len] = 0x80;
        ++len;
        if (len <= 56) {
            if (len != 56) {
                memset(blk + len, 0, 56 - len);
            }
            _store_len(total, blk + 56);
            sha256_blk_update(hash, blk);
        } else {
            if (len < 64) {
                memset(blk + len, 0, 64 - len);
            }
            sha256_blk_update(hash, blk);
            memset(blk, 0, 56);
            _store_len(total, blk + 56);
            sha256_blk_update(hash, blk);
        }
    }
}


void sha256_init(sha256_ctx_t *ctx) {
    memset(ctx, 0, sizeof(sha256_ctx_t));
    ctx->hash[0] = 0x6a09e667ul;
    ctx->hash[1] = 0xbb67ae85ul;
    ctx->hash[2] = 0x3c6ef372ul;
    ctx->hash[3] = 0xa54ff53aul;
    ctx->hash[4] = 0x510e527ful;
    ctx->hash[5] = 0x9b05688cul;
    ctx->hash[6] = 0x1f83d9abul;
    ctx->hash[7] = 0x5be0cd19ul;
}

void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len) {
    const uint8_t *end = data + len;
    const uint8_t *p = data;
    for (; p + 64 <= end; p += 64) {
        sha256_blk_update(ctx->hash, p);
    }
    ctx->len += len;
    if (p < end) {
        memcpy(ctx->blk, p, end - p);
    }
}

void sha256_digest(sha256_ctx_t *ctx, uint8_t *data) {
    uint32_t hash[8];
    memcpy(hash, ctx->hash, 32);
    sha256_blk_done(hash, ctx->blk, ctx->len);
    _store_be_u32(hash[0], data);
    _store_be_u32(hash[1], data + 4);
    _store_be_u32(hash[2], data + 8);
    _store_be_u32(hash[3], data + 12);
    _store_be_u32(hash[4], data + 16);
    _store_be_u32(hash[5], data + 20);
    _store_be_u32(hash[6], data + 24);
    _store_be_u32(hash[7], data + 28);
}

void sha256_hexdigest(sha256_ctx_t *ctx, uint8_t *data) {
    sha256_digest(ctx, data);
    _expand_hex(data, 32);
}
