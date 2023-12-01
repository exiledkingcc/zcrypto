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

#define _hash_store_len(EE, LEN, DATA)  \
    do {                                \
        LEN *= 8;                       \
        _z_store_##EE##_u64(LEN, DATA); \
    } while (0)

#define _hash_digest(EE, HASH, LEN, DATA)               \
    do {                                                \
        for (size_t i = 0; i < LEN; ++i) {              \
            _z_store_##EE##_u32(HASH[i], DATA + i * 4); \
        }                                               \
    } while (0)

#define HASH_BLK_SIZE 64

typedef void (*hash_blk_update_func)(uint32_t*, const uint8_t*);
void _hash_update(hash_blk_update_func blk_update, uint32_t* hash, uint8_t* blk, const uint8_t* data, size_t len, uint64_t* total);
void _hash_done(hash_blk_update_func blk_update, uint32_t* hash, const uint8_t* data, uint64_t total, bool le);

#ifdef __cplusplus
}
#endif
