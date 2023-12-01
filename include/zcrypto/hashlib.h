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

#include <stddef.h>
#include <stdint.h>

#define HASH_ALG_SM3 1
#define HASH_ALG_MD5 2
#define HASH_ALG_SHA1 3
#define HASH_ALG_SHA256 4

typedef struct {
    uint64_t len;
    uint32_t hash[8];
    uint8_t blk[64];
    size_t hlen;
    int alg;
} hash_ctx_t;

void hash_init(hash_ctx_t* ctx, int alg);
void hash_update(hash_ctx_t* ctx, const uint8_t* data, size_t len);
void hash_digest(hash_ctx_t* ctx, uint8_t* data);
void hash_hexdigest(hash_ctx_t* ctx, uint8_t* data);

#ifdef __cplusplus
}
#endif
