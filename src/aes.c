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

#include "zcrypto/aes.h"
#include "zcrypto/utils.h"

static const uint8_t RCBOX[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,

};

static const uint8_t SBOX[16][16] = {
    // clang-format off
    {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
    {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
    {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
    {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
    {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
    {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
    {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
    {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
    {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
    {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
    {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
    {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
    {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
    {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
    {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
    {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16},
    // clang-format on
};

static const uint8_t INV_SBOX[16][16] = {
    // clang-format off
    {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
    {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
    {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
    {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
    {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
    {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
    {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
    {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
    {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
    {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
    {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
    {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
    {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
    {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
    {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
    {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d},
    // clang-format on
};

static inline uint32_t _rot_word(uint32_t x) {
    uint8_t* y = (uint8_t*)&x;
    uint8_t t = y[0];
    y[0] = y[1];
    y[1] = y[2];
    y[2] = y[3];
    y[3] = t;
    return *(uint32_t*)y;
}

static inline uint32_t _sub_word(uint32_t x) {
    uint8_t* y = (uint8_t*)&x;
    y[0] = SBOX[y[0] >> 8][y[0] & 0xff];
    y[1] = SBOX[y[1] >> 8][y[1] & 0xff];
    y[2] = SBOX[y[2] >> 8][y[2] & 0xff];
    y[3] = SBOX[y[3] >> 8][y[3] & 0xff];
    return *(uint32_t*)y;
}

static void aes_set_key(const uint8_t* key, size_t keylen, int round, uint32_t* rkey) {
    memcpy(rkey, key, keylen);
    size_t kn = keylen / 4;
    for (size_t r = kn; r < (size_t)(round + 1) * 4; ++r) {
        if (r % kn == 0) {
            uint32_t rcon = 0;
            *(uint8_t*)&rcon = RCBOX[r / kn];
            rkey[r] = rkey[r - kn] ^ _sub_word(_rot_word(rkey[r - 1])) ^ rcon;
        } else if (r % kn == 4 && r > 6) {
            rkey[r] = rkey[r - kn] ^ _sub_word(rkey[r - 1]);
        } else {
            rkey[r] = rkey[r - kn] ^ rkey[r - 1];
        }
    }
}

static void add_round_key(uint8_t dst[16], const uint32_t* rkey) {
    uint32_t* y = (uint32_t*)dst;
    y[0] ^= rkey[0];
    y[1] ^= rkey[1];
    y[2] ^= rkey[2];
    y[3] ^= rkey[3];
}

static void sub_bytes(uint8_t blk[16]) {
    for (int i = 0; i < 16; ++i) {
        uint8_t val = blk[i];
        blk[i] = SBOX[val >> 8][val & 0xff];
    }
}

static void inv_sub_bytes(uint8_t blk[16]) {
    for (int i = 0; i < 16; ++i) {
        uint8_t val = blk[i];
        blk[i] = INV_SBOX[val >> 8][val & 0xff];
    }
}

static void shift_rows(uint8_t blk[16]) {
    for (int i = 1; i < 4; ++i) {
        uint8_t tt[4] = {blk[i], blk[i + 4], blk[i + 8], blk[i + 12]};
        blk[i] = tt[i];
        blk[i + 4] = tt[(i + 1) % 4];
        blk[i + 8] = tt[(i + 2) % 4];
        blk[i + 12] = tt[(i + 3) % 4];
    }
}

static void inv_shift_rows(uint8_t blk[16]) {
    for (int i = 1; i < 4; ++i) {
        uint8_t tt[4] = {blk[i], blk[i + 4], blk[i + 8], blk[i + 12]};
        blk[i] = tt[4 - i];
        blk[i + 4] = tt[(5 - i) % 4];
        blk[i + 8] = tt[(6 - i) % 4];
        blk[i + 12] = tt[(7 - i) % 4];
    }
}

// static uint8_t _gmul(uint8_t v, uint8_t n) {
//     uint8_t p = 0;
//     for (int i = 0; i < 8; ++i) {
//         if ((n & 1) == 1) {
//             p ^= v;
//         }
//         bool h = v & 0x80;
//         v <<= 1;
//         if (h) {
//             v ^= 0x1b;
//         }
//         n >>= 1;
//     }
//     return p;
// }
//
// _gmul(x, 1) == x
// _gmul(x, 3) == _gmul(x, 2)
// _gmul(x, 9) == _gmul(x, 8) ^ _gmul(x, 1)
// _gmul(x, 11) == _gmul(x, 8) ^ _gmul(x, 2) ^ _gmul(x, 1)
// _gmul(x, 13) == _gmul(x, 8) ^ _gmul(x, 4) ^ _gmul(x, 1)
// _gmul(x, 14) == _gmul(x, 8) ^ _gmul(x, 4) ^ _gmul(x, 2)
// _gmul(x, 4) == _gmul2(_gmul2(x))
// _gmul(x, 8) == _gmul2(_gmul2(_gmul2(x)))
// _gmul2(x ^ y) == _gmul2(x) ^ _gmul2(y)

static inline uint8_t _gmul2(uint8_t v) {
    return (v & 0x80) > 0 ? ((v << 1) ^ 0x1b) : (v << 1);
}

static void mix_columns(uint8_t blk[16]) {
    // | 2 3 1 1 | | b0 |
    // | 1 2 3 1 | | b1 |
    // | 1 1 2 3 | | b2 |
    // | 3 1 1 2 | | b3 |

    // dx = _gmul(x0, 2) ^ _gmul(x1, 3) ^ _gmul(x2, 1) ^ _gmul(x3, 1);
    //    = _gmul(x0, 2) ^ _gmul(x1, 2) ^ x1 ^ x2 ^ x3;
    //    = _gmul(x0, 2) ^ _gmul(x1, 2) ^ (x1 ^ x2 ^ x3 ^ x0) ^ x0;

    for (int r = 0; r < 4; ++r) {
        uint8_t* x = blk + r * 4;
        uint8_t g2[4] = {
            _gmul2(x[0]),
            _gmul2(x[1]),
            _gmul2(x[2]),
            _gmul2(x[3]),
        };
        uint8_t tt = x[0] ^ x[1] ^ x[2] ^ x[3];
        blk[r * 4 + 0] ^= g2[0] ^ g2[1] ^ tt;
        blk[r * 4 + 1] ^= g2[1] ^ g2[2] ^ tt;
        blk[r * 4 + 2] ^= g2[2] ^ g2[3] ^ tt;
        blk[r * 4 + 3] ^= g2[3] ^ g2[0] ^ tt;
    }
}

static void inv_mix_columns(uint8_t blk[16]) {
    // | 14 11 13  9 | | b0 |
    // |  9 14 11 13 | | b1 |
    // | 13  9 14 11 | | b2 |
    // | 11 13  9 14 | | b3 |

    // dx = _gmul(x0, 14) ^ _gmul(x1, 11) ^ _gmul(x2, 13) ^ _gmul(x3, 9);
    //    = _gmul(x0, 8) ^ _gmul(x0, 4) ^ _gmul(x0, 2) ^ _gmul(x1, 8) ^ _gmul(x1, 2) ^ x1 ^ _gmul(x2, 8) ^ _gmul(x2, 4) ^ x2 ^ _gmul(x3, 8) ^ x3;
    //    = _gmul(x0, 8) ^ _gmul(x1, 8) ^ _gmul(x2, 8) ^ _gmul(x3, 8) ^ _gmul(x0, 4) ^ _gmul(x2, 4) ^ _gmul(x0, 2) ^ _gmul(x1, 2) ^ x1 ^ x2 ^ x3;
    //    = _gmul2(_gmul4(x0) ^ _gmul4(x1) ^ _gmul4(x2) ^ _gmul4(x3)) ^ _gmul(x0, 4) ^ _gmul(x2, 4) ^ _gmul(x0, 2) ^ _gmul(x1, 2) ^ x1 ^ x2 ^ x3;
    //    = _gmul2(_gmul2(_gmul2(x0) ^ _gmul2(x1) ^ _gmul2(x2) ^ _gmul2(x3))) ^ _gmul2(_gmul2(x0) ^ _gmul2(x2)) ^ _gmul2(x0) ^ _gmul2(x1) ^ x1 ^ x2 ^ x3;
    //    = _gmul2(_gmul2(....)) ^ _gmul2(_gmul2(x0) ^ _gmul2(x2)) ^ _gmul2(x0) ^ _gmul2(x1) ^ (x1 ^ x2 ^ x3 ^ x0) ^ x0;

    for (int r = 0; r < 4; ++r) {
        uint8_t* x = blk + r * 4;
        uint8_t g2[4] = {
            _gmul2(x[0]),
            _gmul2(x[1]),
            _gmul2(x[2]),
            _gmul2(x[3]),
        };
        uint8_t gg = _gmul2(_gmul2(g2[0] ^ g2[1] ^ g2[2] ^ g2[3]));
        uint8_t tt = x[0] ^ x[1] ^ x[2] ^ x[3];
        blk[r * 4 + 0] ^= gg ^ _gmul2(g2[0] ^ g2[2]) ^ g2[0] ^ g2[1] ^ tt;
        blk[r * 4 + 1] ^= gg ^ _gmul2(g2[1] ^ g2[3]) ^ g2[1] ^ g2[2] ^ tt;
        blk[r * 4 + 2] ^= gg ^ _gmul2(g2[2] ^ g2[0]) ^ g2[2] ^ g2[3] ^ tt;
        blk[r * 4 + 3] ^= gg ^ _gmul2(g2[3] ^ g2[1]) ^ g2[3] ^ g2[0] ^ tt;
    }
}

void aes_blk_encrypt(const uint32_t* rkey, int round, const uint8_t in[16], uint8_t out[16]) {
    memcpy(out, in, 16);

    add_round_key(out, rkey);
    for (int r = 1; r < round; ++r) {
        sub_bytes(out);
        shift_rows(out);
        mix_columns(out);
        add_round_key(out, rkey + r * 4);
    }
    sub_bytes(out);
    shift_rows(out);
    // NO mix_columns
    add_round_key(out, rkey + 4 * round);
}

void aes_blk_decrypt(const uint32_t* rkey, int round, const uint8_t in[16], uint8_t out[16]) {
    memcpy(out, in, 16);

    add_round_key(out, rkey + 4 * round);
    for (int r = round - 1; r > 0; --r) {
        inv_shift_rows(out);
        inv_sub_bytes(out);
        add_round_key(out, rkey + r * 4);
        inv_mix_columns(out);
    }
    inv_shift_rows(out);
    inv_sub_bytes(out);
    // no inv_mix_columns
    add_round_key(out, rkey);
}

typedef void (*block_func_t)(const uint32_t*, int, const uint8_t*, uint8_t*);

static inline void _ecb(block_func_t blk_func, const uint32_t* rkey, int rd, size_t len, const uint8_t* in, uint8_t* out) {
    for (size_t i = 0; i < len; i += 16) {
        blk_func(rkey, rd, in + i, out + i);
    }
}

static inline void _cbc_encrypt(const uint32_t* rkey, int rd, uint8_t* iv, size_t len, const uint8_t* plain, uint8_t* cipher) {
    for (size_t i = 0; i < len; i += 16) {
        _xor_block(iv, plain + i, 16);
        aes_blk_encrypt(rkey, rd, iv, cipher + i);
        memcpy(iv, cipher + i, 16);
    }
}

static inline void _cbc_decrypt(const uint32_t* rkey, int rd, uint8_t* iv, size_t len, const uint8_t* cipher, uint8_t* plain) {
    for (size_t i = 0; i < len; i += 16) {
        aes_blk_decrypt(rkey, rd, cipher + i, plain + i);
        _xor_block(plain + i, iv, 16);
        memcpy(iv, cipher + i, 16);
    }
}

static inline void _cfb_encrypt(const uint32_t* rkey, int rd, uint8_t* iv, size_t len, const uint8_t* plain, uint8_t* cipher) {
    for (size_t i = 0; i < len; i += 16) {
        aes_blk_encrypt(rkey, rd, iv, cipher + i);
        _xor_block(cipher + i, plain + i, 16);
        memcpy(iv, cipher + i, 16);
    }
}

static inline void _cfb_decrypt(const uint32_t* rkey, int rd, uint8_t* iv, size_t len, const uint8_t* cipher, uint8_t* plain) {
    for (size_t i = 0; i < len; i += 16) {
        aes_blk_encrypt(rkey, rd, iv, plain + i);
        _xor_block(plain + i, cipher + i, 16);
        memcpy(iv, cipher + i, 16);
    }
}

static inline void _ofb(const uint32_t* rkey, int rd, uint8_t* iv, size_t len, const uint8_t* in, uint8_t* out) {
    for (size_t i = 0; i < len; i += 16) {
        aes_blk_encrypt(rkey, rd, iv, out + i);
        memcpy(iv, out + i, 16);
        _xor_block(out + i, in + i, 16);
    }
}

#define AES_DEF_ECB(KEY, RN)                                                                              \
    void aes_##KEY##_ecb_encrypt(const uint8_t* key, size_t len, const uint8_t* plain, uint8_t* cipher) { \
        uint32_t rkey[RN * 4 + 4];                                                                        \
        aes_set_key(key, KEY / 8, RN, rkey);                                                              \
        _ecb(aes_blk_encrypt, rkey, RN, len, plain, cipher);                                              \
    }                                                                                                     \
                                                                                                          \
    void aes_##KEY##_ecb_decrypt(const uint8_t* key, size_t len, const uint8_t* cipher, uint8_t* plain) { \
        uint32_t rkey[RN * 4 + 4];                                                                        \
        aes_set_key(key, KEY / 8, RN, rkey);                                                              \
        _ecb(aes_blk_decrypt, rkey, RN, len, cipher, plain);                                              \
    }

AES_DEF_ECB(128, 10)
AES_DEF_ECB(192, 12)
AES_DEF_ECB(256, 14)

#define AES_DEF_CBC(KEY, RN)                                                                                                 \
    void aes_##KEY##_cbc_encrypt(const uint8_t* key, const uint8_t* iv, size_t len, const uint8_t* plain, uint8_t* cipher) { \
        uint32_t rkey[RN * 4 + 4];                                                                                           \
        aes_set_key(key, KEY / 8, RN, rkey);                                                                                 \
        uint8_t out[16];                                                                                                     \
        memcpy(out, iv, 16);                                                                                                 \
        _cbc_encrypt(rkey, RN, out, len, plain, cipher);                                                                     \
    }                                                                                                                        \
                                                                                                                             \
    void aes_##KEY##_cbc_decrypt(const uint8_t* key, const uint8_t* iv, size_t len, const uint8_t* cipher, uint8_t* plain) { \
        uint32_t rkey[RN * 4 + 4];                                                                                           \
        aes_set_key(key, KEY / 8, RN, rkey);                                                                                 \
        uint8_t out[16];                                                                                                     \
        memcpy(out, iv, 16);                                                                                                 \
        _cbc_decrypt(rkey, RN, out, len, cipher, plain);                                                                     \
    }

AES_DEF_CBC(128, 10)
AES_DEF_CBC(192, 12)
AES_DEF_CBC(256, 14)

#define AES_DEF_CFB(KEY, RN)                                                                                                 \
    void aes_##KEY##_cfb_encrypt(const uint8_t* key, const uint8_t* iv, size_t len, const uint8_t* plain, uint8_t* cipher) { \
        uint32_t rkey[RN * 4 + 4];                                                                                           \
        aes_set_key(key, KEY / 8, RN, rkey);                                                                                 \
        uint8_t out[16];                                                                                                     \
        memcpy(out, iv, 16);                                                                                                 \
        _cfb_encrypt(rkey, RN, out, len, plain, cipher);                                                                     \
    }                                                                                                                        \
                                                                                                                             \
    void aes_##KEY##_cfb_decrypt(const uint8_t* key, const uint8_t* iv, size_t len, const uint8_t* cipher, uint8_t* plain) { \
        uint32_t rkey[RN * 4 + 4];                                                                                           \
        aes_set_key(key, KEY / 8, RN, rkey);                                                                                 \
        uint8_t out[16];                                                                                                     \
        memcpy(out, iv, 16);                                                                                                 \
        _cfb_decrypt(rkey, RN, out, len, cipher, plain);                                                                     \
    }

AES_DEF_CFB(128, 10)
AES_DEF_CFB(192, 12)
AES_DEF_CFB(256, 14)

#define AES_DEF_OFB(KEY, RN)                                                                                                 \
    void aes_##KEY##_ofb_encrypt(const uint8_t* key, const uint8_t* iv, size_t len, const uint8_t* plain, uint8_t* cipher) { \
        uint32_t rkey[RN * 4 + 4];                                                                                           \
        aes_set_key(key, KEY / 8, RN, rkey);                                                                                 \
        uint8_t out[16];                                                                                                     \
        memcpy(out, iv, 16);                                                                                                 \
        _ofb(rkey, RN, out, len, plain, cipher);                                                                             \
    }                                                                                                                        \
                                                                                                                             \
    void aes_##KEY##_ofb_decrypt(const uint8_t* key, const uint8_t* iv, size_t len, const uint8_t* cipher, uint8_t* plain) { \
        aes_##KEY##_ofb_encrypt(key, iv, len, cipher, plain);                                                                \
    }

AES_DEF_OFB(128, 10)
AES_DEF_OFB(192, 12)
AES_DEF_OFB(256, 14)

static inline int _get_round(size_t keylen) {
    int rr[] = {10, 12, 14};
    return rr[keylen / 64 - 2];
}

#define AES_ENCRYPT 0x10
#define AES_DECRYPT 0x20

static inline int _round(size_t keylen) {
    return keylen / 32 + 6;
}

void aes_close(aes_ctx_t* ctx) {
    memset(ctx, 0, sizeof(aes_ctx_t));
}

int aes_init(aes_ctx_t* ctx, uint8_t mode, size_t keylen, const uint8_t* key, const uint8_t iv[16]) {
    if (keylen != 128 && keylen != 192 && keylen != 256) {
        return -1;
    }
    if (mode < AES_ECB_MODE || mode > AES_OFB_MODE) {
        return -1;
    }
    if (mode == AES_ECB_MODE && iv != NULL) {
        return -1;
    }
    if (mode != AES_ECB_MODE && iv == NULL) {
        return -1;
    }
    ctx->keylen = keylen;
    ctx->mode = mode;
    aes_set_key(key, keylen / 8, _round(keylen), ctx->rkey);
    if (iv != NULL) {
        memcpy(ctx->iv, iv, 16);
    } else {
        memset(ctx->iv, 0, 16);
    }
    return 0;
}

int aes_encrypt(aes_ctx_t* ctx, size_t len, const uint8_t* plain, uint8_t* cipher) {
    if ((ctx->mode & 0xf0) == 0) {
        ctx->mode |= AES_ENCRYPT;
    }
    if ((ctx->mode & 0xf0) != AES_ENCRYPT) {
        return -1;
    }

    int rd = _round(ctx->keylen);
    uint8_t m = ctx->mode & 0x0f;
    if (m == AES_ECB_MODE) {
        _ecb(aes_blk_encrypt, ctx->rkey, rd, len, plain, cipher);
    } else if (m == AES_CBC_MODE) {
        _cbc_encrypt(ctx->rkey, rd, ctx->iv, len, plain, cipher);
    } else if (m == AES_CFB_MODE) {
        _cfb_encrypt(ctx->rkey, rd, ctx->iv, len, plain, cipher);
    } else if (m == AES_OFB_MODE) {
        _ofb(ctx->rkey, rd, ctx->iv, len, plain, cipher);
    } else {
        return -1;
    }
    return 0;
}

int aes_decrypt(aes_ctx_t* ctx, size_t len, const uint8_t* cipher, uint8_t* plain) {
    if ((ctx->mode & 0xf0) == 0) {
        ctx->mode |= AES_DECRYPT;
    }
    if ((ctx->mode & 0xf0) != AES_DECRYPT) {
        return -1;
    }

    int rd = _round(ctx->keylen);
    uint8_t m = ctx->mode & 0x0f;
    if (m == AES_ECB_MODE) {
        _ecb(aes_blk_decrypt, ctx->rkey, rd, len, cipher, plain);
    } else if (m == AES_CBC_MODE) {
        _cbc_decrypt(ctx->rkey, rd, ctx->iv, len, cipher, plain);
    } else if (m == AES_CFB_MODE) {
        _cfb_decrypt(ctx->rkey, rd, ctx->iv, len, cipher, plain);
    } else if (m == AES_OFB_MODE) {
        _ofb(ctx->rkey, rd, ctx->iv, len, cipher, plain);
    } else {
        return -1;
    }
    return 0;
}
