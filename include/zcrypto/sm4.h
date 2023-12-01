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

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

void sm4_ecb_encrypt(const uint8_t key[16], size_t len, const uint8_t* plain, uint8_t* cipher);
void sm4_ecb_decrypt(const uint8_t key[16], size_t len, const uint8_t* cipher, uint8_t* plain);

void sm4_cbc_encrypt(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t* plain, uint8_t* cipher);
void sm4_cbc_decrypt(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t* cipher, uint8_t* plain);

void sm4_cfb_encrypt(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t* plain, uint8_t* cipher);
void sm4_cfb_decrypt(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t* cipher, uint8_t* plain);

void sm4_ofb_encrypt(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t* plain, uint8_t* cipher);
void sm4_ofb_decrypt(const uint8_t key[16], const uint8_t iv[16], size_t len, const uint8_t* cipher, uint8_t* plain);

#define SM4_MIN_MODE SM4_ECB_MODE
#define SM4_ECB_MODE 1
#define SM4_CBC_MODE 2
#define SM4_CFB_MODE 3
#define SM4_OFB_MODE 4
#define SM4_MAX_MODE SM4_OFB_MODE

typedef struct {
    uint32_t rkey[32];
    uint8_t iv[16];
    uint8_t mode;
} sm4_ctx_t;

void sm4_close(sm4_ctx_t* ctx);
int sm4_init(sm4_ctx_t* ctx, uint8_t mode, const uint8_t key[16], const uint8_t iv[16]);
int sm4_encrypt(sm4_ctx_t* ctx, size_t len, const uint8_t* plain, uint8_t* cipher);
int sm4_decrypt(sm4_ctx_t* ctx, size_t len, const uint8_t* cipher, uint8_t* plain);

#ifdef __cplusplus
}
#endif
