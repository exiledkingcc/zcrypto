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
#include <string.h>

typedef struct {
    uint64_t len;
    uint32_t hash[8];
    uint8_t blk[64];
} sm3_ctx_t;

void sm3_init(sm3_ctx_t* ctx);
void sm3_update(sm3_ctx_t* ctx, const uint8_t* data, size_t len);
void sm3_digest(sm3_ctx_t* ctx, uint8_t* data);
void sm3_hexdigest(sm3_ctx_t* ctx, uint8_t* data);

void sm3_hash_init(uint32_t hash[8]);
void sm3_blk_update(uint32_t hash[8], const uint8_t blk[64]);

#ifdef __cplusplus
}
#endif
