#include "zcrypto/oaep.h"
#include "zcrypto/sha256.h"

static void bytes2num(uint32_t* num, const uint8_t* bytes, size_t len) {
    for (size_t j = 0; j < len; j += 4) {
        size_t i = (len - j) / 4 - 1;
        num[i] = bytes[j];
        num[i] <<= 8;
        num[i] |= bytes[j + 1];
        num[i] <<= 8;
        num[i] |= bytes[j + 2];
        num[i] <<= 8;
        num[i] |= bytes[j + 3];
    }
}

static void num2bytes(uint8_t* bytes, const uint32_t* num, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        uint32_t x = num[i];
        size_t j = (len - 1 - i) * 4;
        bytes[j] = (x >> 24) & 0xff;
        bytes[j + 1] = (x >> 16) & 0xff;
        bytes[j + 2] = (x >> 8) & 0xff;
        bytes[j + 3] = (x)&0xff;
    }
}

static void mgf1(uint8_t* mask, size_t mlen, const uint8_t* seed, size_t slen) {
    uint32_t cnt[1] = {0};
    uint8_t bb[4] = {0};
    sha256_ctx_t ctx;
    for (uint32_t i = 0; i < mlen / HASH_BYTES; ++i) {
        num2bytes(bb, cnt, 1);
        sha256_init(&ctx);
        sha256_update(&ctx, seed, slen);
        sha256_update(&ctx, bb, 4);
        sha256_digest(&ctx, mask + HASH_BYTES * i);
        ++cnt[0];
    }
    size_t r = mlen % HASH_BYTES;
    if (r != 0) {
        uint8_t hh[HASH_BYTES] = {0};
        num2bytes(bb, cnt, 1);
        sha256_init(&ctx);
        sha256_update(&ctx, seed, slen);
        sha256_update(&ctx, bb, 4);
        sha256_digest(&ctx, hh);
        memcpy(mask + mlen / HASH_BYTES * HASH_BYTES, hh, r);
    }
}

static inline void _xor(uint8_t* src, const uint8_t* dst, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        src[i] ^= dst[i];
    }
}

static const uint8_t EMPTY_LABLE_HASH[HASH_BYTES] = {
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
};

/*
OAEP padding: https://tools.ietf.org/html/rfc8017

                    +----------+------+--+-------+
               DB = |  lHash   |  PS  |01|   M   |
                    +----------+------+--+-------+
                                   |
         +----------+              |
         |   seed   |              |
         +----------+              |
               |                   |
               |-------> MGF ---> xor
               |                   |
      +--+     V                   |
      |00|    xor <----- MGF <-----|
      +--+     |                   |
        |      |                   |
        V      V                   V
      +--+----------+----------------------------+
EM =  |00|maskedSeed|          maskedDB          |
      +--+----------+----------------------------+

* NOTICE: you has to ensure that message length <= MSG_MAX_LEN
* NOTICE: you has to call `srand` yourself to set rand seed
*/
static void padding(uint8_t EM[RSA_BYTES], const uint8_t* text, size_t len, const char* label) {
    memset(EM, 0, RSA_BYTES);
    uint8_t seed[HASH_BYTES];
    uint8_t dbmask[RSA_BYTES - HASH_BYTES - 1];
    for (size_t i = 0; i < HASH_BYTES; ++i) {
        seed[i] = (uint8_t)(rand() & 0xff);
    }
    mgf1(dbmask, RSA_BYTES - HASH_BYTES - 1, seed, HASH_BYTES);

    if (label == NULL) {
        memcpy(EM + HASH_BYTES + 1, EMPTY_LABLE_HASH, HASH_BYTES);
    } else {
        sha256_ctx_t ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, (const uint8_t*)label, strlen(label));
        sha256_digest(&ctx, EM + HASH_BYTES + 1);
    }
    EM[RSA_BYTES - len - 1] = 0x01;
    memcpy(EM + RSA_BYTES - len, text, len);

    _xor(EM + HASH_BYTES + 1, dbmask, RSA_BYTES - HASH_BYTES - 1);
    mgf1(EM + 1, HASH_BYTES, EM + HASH_BYTES + 1, RSA_BYTES - HASH_BYTES - 1);
    _xor(EM + 1, seed, HASH_BYTES);
}

void rsa_pub_oaep_encrypt(const rsa_ctx_t* ctx, const uint8_t* msg, size_t len, const char* label, uint8_t cipher[RSA_BYTES]) {
    uint32_t P[RSA_SIZE];
    uint32_t C[RSA_SIZE];
    uint8_t EM[RSA_BYTES];
    padding(EM, msg, len, label);
    bytes2num(P, EM, RSA_BYTES);
    rsa_pub_naive(ctx, P, C);
    num2bytes(cipher, C, RSA_SIZE);
}
