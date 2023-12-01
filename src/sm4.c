/*
Copyright (C) 2020-2023 exiledkingcc@gmail.com

This file is part of zcrypto.

zcrypto is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation; either version 3, or (at your option) any later
version.

zcrypto is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
for more details.

You should have received a copy of the GNU General Public License
along with zcrypto; see the file LICENSE.  If not see
<http://www.gnu.org/licenses/>.
*/

#include "zcrypto/sm4.h"
#include "zcrypto/utils.h"

static const uint8_t SBOX[256] = {
    // clang-format off
	0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7,
	0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
	0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
	0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
	0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a,
	0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
	0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95,
	0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
	0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
	0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
	0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b,
	0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
	0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2,
	0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
	0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
	0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
	0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5,
	0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
	0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55,
	0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
	0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
	0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
	0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f,
	0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
	0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f,
	0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
	0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
	0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
	0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e,
	0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
	0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20,
	0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
    // clang-format on
};

static uint32_t _sbox(uint32_t x) {
    uint8_t u[4];
    *(uint32_t*)u = x;
    u[0] = SBOX[u[0]];
    u[1] = SBOX[u[1]];
    u[2] = SBOX[u[2]];
    u[3] = SBOX[u[3]];
    return *(uint32_t*)u;
}

static inline uint32_t _st1(uint32_t x) {
    x = _sbox(x);
    return x ^ _lshift(x, 2) ^ _lshift(x, 10) ^ _lshift(x, 18) ^ _lshift(x, 24);
}

static inline uint32_t _st2(uint32_t x) {
    x = _sbox(x);
    return x ^ _lshift(x, 13) ^ _lshift(x, 23);
}

static const uint32_t FK[4] = {
    0xa3b1bac6,
    0x56aa3350,
    0x677d9197,
    0xb27022dc,
};

static const uint32_t CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269, 0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9, 0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249, 0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229, 0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299, 0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209, 0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
};

static void sm4_calc_key(const uint8_t key[16], uint32_t rkey[32]) {
    uint32_t x[5];
    x[0] = _z_load_be_u32(key);
    x[1] = _z_load_be_u32(key + 4);
    x[2] = _z_load_be_u32(key + 8);
    x[3] = _z_load_be_u32(key + 12);

    x[0] ^= FK[0];
    x[1] ^= FK[1];
    x[2] ^= FK[2];
    x[3] ^= FK[3];

    for (int i = 0; i < 32; ++i) {
        uint32_t* y0 = x + (i % 5);
        uint32_t* y1 = x + ((i + 1) % 5);
        uint32_t* y2 = x + ((i + 2) % 5);
        uint32_t* y3 = x + ((i + 3) % 5);
        uint32_t* y4 = x + ((i + 4) % 5);

        *y4 = *y0 ^ _st2(*y1 ^ *y2 ^ *y3 ^ CK[i]);
        rkey[i] = *y4;
    }
    // memset(x, 0, sizeof(x));
}

static inline void sm4_rev_key(uint32_t rkey[32]) {
    for (int i = 0; i < 16; ++i) {
        uint32_t t = rkey[i];
        rkey[i] = rkey[31 - i];
        rkey[31 - i] = t;
    }
}

static void sm4_calc_block(const uint32_t rkey[32], const uint8_t in[16], uint8_t out[16]) {
    uint32_t x[5];
    x[0] = _z_load_be_u32(in);
    x[1] = _z_load_be_u32(in + 4);
    x[2] = _z_load_be_u32(in + 8);
    x[3] = _z_load_be_u32(in + 12);

    for (int i = 0; i < 32; ++i) {
        uint32_t* y0 = x + (i % 5);
        uint32_t* y1 = x + ((i + 1) % 5);
        uint32_t* y2 = x + ((i + 2) % 5);
        uint32_t* y3 = x + ((i + 3) % 5);
        uint32_t* y4 = x + ((i + 4) % 5);

        *y4 = *y0 ^ _st1(*y1 ^ *y2 ^ *y3 ^ rkey[i]);
    }

    _z_store_be_u32(x[0], out);
    _z_store_be_u32(x[4], out + 4);
    _z_store_be_u32(x[3], out + 8);
    _z_store_be_u32(x[2], out + 12);
    // memset(x, 0, sizeof(x));
}

static inline void _ecb(const uint32_t* rkey, size_t len, const uint8_t* in, uint8_t* out) {
    for (size_t i = 0; i < len; i += 16) {
        sm4_calc_block(rkey, in + i, out + i);
    }
}

static inline void _cbc_encrypt(const uint32_t* rkey, uint8_t* iv, size_t len, const uint8_t* plain, uint8_t* cipher) {
    for (size_t i = 0; i < len; i += 16) {
        _xor_block(iv, plain + i, 16);
        sm4_calc_block(rkey, iv, cipher + i);
        memcpy(iv, cipher + i, 16);
    }
}

static inline void _cbc_decrypt(const uint32_t* rkey, uint8_t* iv, size_t len, const uint8_t* cipher, uint8_t* plain) {
    for (size_t i = 0; i < len; i += 16) {
        sm4_calc_block(rkey, cipher + i, plain + i);
        _xor_block(plain + i, iv, 16);
        memcpy(iv, cipher + i, 16);
    }
}

static inline void _cfb_encrypt(const uint32_t* rkey, uint8_t* iv, size_t len, const uint8_t* plain, uint8_t* cipher) {
    for (size_t i = 0; i < len; i += 16) {
        sm4_calc_block(rkey, iv, cipher + i);
        _xor_block(cipher + i, plain + i, 16);
        memcpy(iv, cipher + i, 16);
    }
}

static inline void _cfb_decrypt(const uint32_t* rkey, uint8_t* iv, size_t len, const uint8_t* cipher, uint8_t* plain) {
    for (size_t i = 0; i < len; i += 16) {
        sm4_calc_block(rkey, iv, plain + i);
        _xor_block(plain + i, cipher + i, 16);
        memcpy(iv, cipher + i, 16);
    }
}

static inline void _ofb(const uint32_t* rkey, uint8_t* iv, size_t len, const uint8_t* in, uint8_t* out) {
    for (size_t i = 0; i < len; i += 16) {
        sm4_calc_block(rkey, iv, out + i);
        memcpy(iv, out + i, 16);
        _xor_block(out + i, in + i, 16);
    }
}

void sm4_ecb_encrypt(const uint8_t key[16], size_t len, const uint8_t* plain, uint8_t* cipher) {
    uint32_t rkey[32];
    sm4_calc_key(key, rkey);
    _ecb(rkey, len, plain, cipher);
    // memset(rkey, 0, sizeof(rkey));
}

void sm4_ecb_decrypt(const uint8_t key[16], size_t len, const uint8_t* cipher, uint8_t* plain) {
    uint32_t rkey[32];
    sm4_calc_key(key, rkey);
    sm4_rev_key(rkey);
    _ecb(rkey, len, cipher, plain);
    // memset(rkey, 0, sizeof(rkey));
}

void sm4_cbc_encrypt(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t* plain, uint8_t* cipher) {
    uint32_t rkey[32];
    sm4_calc_key(key, rkey);
    uint8_t out[16];
    memcpy(out, iv, 16);
    _cbc_encrypt(rkey, out, len, plain, cipher);
    // memset(rkey, 0, sizeof(rkey));
    // memset(out, 0, sizeof(out));
}

void sm4_cbc_decrypt(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t* cipher, uint8_t* plain) {
    uint32_t rkey[32];
    sm4_calc_key(key, rkey);
    sm4_rev_key(rkey);
    uint8_t out[16];
    memcpy(out, iv, 16);
    _cbc_decrypt(rkey, out, len, cipher, plain);
    // memset(rkey, 0, sizeof(rkey));
    // memset(out, 0, sizeof(out));
}

void sm4_cfb_encrypt(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t* plain, uint8_t* cipher) {
    uint32_t rkey[32];
    sm4_calc_key(key, rkey);
    uint8_t out[16];
    memcpy(out, iv, 16);
    _cfb_encrypt(rkey, out, len, plain, cipher);
    // memset(rkey, 0, sizeof(rkey));
    // memset(out, 0, sizeof(out));
}

void sm4_cfb_decrypt(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t* cipher, uint8_t* plain) {
    uint32_t rkey[32];
    sm4_calc_key(key, rkey);
    uint8_t out[16];
    memcpy(out, iv, 16);
    _cfb_decrypt(rkey, out, len, cipher, plain);
    // memset(rkey, 0, sizeof(rkey));
    // memset(out, 0, sizeof(out));
}

void sm4_ofb_encrypt(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t* plain, uint8_t* cipher) {
    uint32_t rkey[32];
    sm4_calc_key(key, rkey);
    uint8_t out[16];
    memcpy(out, iv, 16);
    _ofb(rkey, out, len, plain, cipher);
    // memset(rkey, 0, sizeof(rkey));
    // memset(out, 0, sizeof(out));
}

void sm4_ofb_decrypt(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t* cipher, uint8_t* plain) {
    sm4_ofb_encrypt(key, iv, len, cipher, plain);
}

#define SM4_ENCRYPT 0x10
#define SM4_DECRYPT 0x20

void sm4_close(sm4_ctx_t* ctx) {
    memset(ctx, 0, sizeof(sm4_ctx_t));
}

int sm4_init(sm4_ctx_t* ctx, uint8_t mode, const uint8_t key[16], const uint8_t iv[16]) {
    if (mode < SM4_ECB_MODE || mode > SM4_OFB_MODE) {
        return -1;
    }
    if (mode == SM4_ECB_MODE && iv != NULL) {
        return -1;
    }
    if (mode != SM4_ECB_MODE && iv == NULL) {
        return -1;
    }
    ctx->mode = mode;
    sm4_calc_key(key, ctx->rkey);
    if (iv != NULL) {
        memcpy(ctx->iv, iv, 16);
    } else {
        memset(ctx->iv, 0, 16);
    }
    return 0;
}

int sm4_encrypt(sm4_ctx_t* ctx, size_t len, const uint8_t* plain, uint8_t* cipher) {
    if ((ctx->mode & 0xf0) == 0) {
        ctx->mode |= SM4_ENCRYPT;
    }
    if ((ctx->mode & 0xf0) != SM4_ENCRYPT) {
        return -1;
    }

    uint8_t m = ctx->mode & 0x0f;
    if (m == SM4_ECB_MODE) {
        _ecb(ctx->rkey, len, plain, cipher);
    } else if (m == SM4_CBC_MODE) {
        _cbc_encrypt(ctx->rkey, ctx->iv, len, plain, cipher);
    } else if (m == SM4_CFB_MODE) {
        _cfb_encrypt(ctx->rkey, ctx->iv, len, plain, cipher);
    } else if (m == SM4_OFB_MODE) {
        _ofb(ctx->rkey, ctx->iv, len, plain, cipher);
    } else {
        return -1;
    }
    return 0;
}

int sm4_decrypt(sm4_ctx_t* ctx, size_t len, const uint8_t* cipher, uint8_t* plain) {
    uint8_t m = ctx->mode & 0x0f;
    if ((ctx->mode & 0xf0) == 0) {
        ctx->mode |= SM4_DECRYPT;
        if (m != SM4_CFB_MODE && m != SM4_OFB_MODE) {
            sm4_rev_key(ctx->rkey);
        }
    }
    if ((ctx->mode & 0xf0) != SM4_DECRYPT) {
        return -1;
    }

    if (m == SM4_ECB_MODE) {
        _ecb(ctx->rkey, len, cipher, plain);
    } else if (m == SM4_CBC_MODE) {
        _cbc_decrypt(ctx->rkey, ctx->iv, len, cipher, plain);
    } else if (m == SM4_CFB_MODE) {
        _cfb_decrypt(ctx->rkey, ctx->iv, len, cipher, plain);
    } else if (m == SM4_OFB_MODE) {
        _ofb(ctx->rkey, ctx->iv, len, cipher, plain);
    } else {
        return -1;
    }
    return 0;
}
