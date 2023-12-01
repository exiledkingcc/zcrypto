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
