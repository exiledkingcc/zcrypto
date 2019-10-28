#include "hash.h"
#include "utils.h"

void _hash_update(hash_blk_update_func blk_update, uint32_t *hash, uint8_t *blk, const uint8_t *data, size_t len, uint64_t *total) {
    const uint8_t *end = data + len;
    const uint8_t *p = data;
    for (; p + HASH_BLK_SIZE <= end; p += HASH_BLK_SIZE) {
        blk_update(hash, p);
    }
    *total += len;
    if (p < end) {
        memcpy(blk, p, end - p);
    }
}

#define BLK_DATA_SZIE (HASH_BLK_SIZE - 8)

static void hash_store_len(uint64_t len, uint8_t data[8], bool le) {
    if (le) {
        _hash_store_len(le, len, data);
    } else {
        _hash_store_len(be, len, data);
    }
}

void _hash_done(hash_blk_update_func blk_update, uint32_t *hash, const uint8_t *data, uint64_t total, bool le) {
    uint8_t blk[HASH_BLK_SIZE];
    size_t len = total % HASH_BLK_SIZE;
    if (len == 0) {
        memset(blk, 0, BLK_DATA_SZIE);
        blk[0] = 0x80;
        hash_store_len(total, blk + BLK_DATA_SZIE, le);
        blk_update(hash, blk);
    } else {
        memcpy(blk, data, len);
        blk[len] = 0x80;
        ++len;
        if (len <= BLK_DATA_SZIE) {
            if (len != BLK_DATA_SZIE) {
                memset(blk + len, 0, BLK_DATA_SZIE - len);
            }
            hash_store_len(total, blk + BLK_DATA_SZIE, le);
            blk_update(hash, blk);
        } else {
            if (len < HASH_BLK_SIZE) {
                memset(blk + len, 0, HASH_BLK_SIZE - len);
            }
            blk_update(hash, blk);
            memset(blk, 0, BLK_DATA_SZIE);
            hash_store_len(total, blk + BLK_DATA_SZIE, le);
            blk_update(hash, blk);
        }
    }
}
