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

#include <stdint.h>

#define RSA_BITS 2048
#define RSA_BYTES (2048 / 8)
#define RSA_SIZE (RSA_BYTES / sizeof(uint32_t))

#ifndef ENABLE_RSA_PRIVATE_KEY
#define ENABLE_RSA_PRIVATE_KEY 1
#endif // !ENABLE_RSA_PRIVATE_KEY

typedef struct {
    uint32_t N[RSA_SIZE];
#if ENABLE_RSA_PRIVATE_KEY
    uint32_t D[RSA_SIZE];
#endif
    uint32_t E;
} rsa_ctx_t;

void rsa_pub_naive(const rsa_ctx_t* ctx, const uint32_t data[RSA_SIZE], uint32_t output[RSA_SIZE]);

#if ENABLE_RSA_PRIVATE_KEY
void rsa_pri_naive(const rsa_ctx_t* ctx, const uint32_t data[RSA_SIZE], uint32_t output[RSA_SIZE]);
#endif

#ifdef __cplusplus
}
#endif
