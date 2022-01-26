#include <assert.h>
#include "hash.h"
#include "utils.h"

void _hash_update(hash_blk_update_func blk_update, uint32_t *hash, uint8_t *blk, const uint8_t *data, size_t len, uint64_t *total) {
    size_t offset = *total % HASH_BLK_SIZE;
    if (offset + len < HASH_BLK_SIZE) {
        memcpy(blk + offset, data, len);
        *total += len;
        return;
    }

    const uint8_t *end = data + len;
    const uint8_t *p   = data;
    if (offset != 0) {
        memcpy(blk + offset, p, HASH_BLK_SIZE - offset);
        blk_update(hash, blk);
        p += HASH_BLK_SIZE - offset;
    }
    for (; p + HASH_BLK_SIZE <= end; p += HASH_BLK_SIZE) {
        blk_update(hash, p);
    }
    if (p < end) {
        memcpy(blk, p, (size_t)(end - p));
    }
    *total += len;
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
    memset(blk, 0, HASH_BLK_SIZE);
    size_t len = total % HASH_BLK_SIZE;
    if (len > 0) {
        memcpy(blk, data, len);
    }

    blk[len] = 0x80;
    if (len < BLK_DATA_SZIE) {
        hash_store_len(total, blk + BLK_DATA_SZIE, le);
        blk_update(hash, blk);
    } else {
        blk_update(hash, blk);
        memset(blk, 0, HASH_BLK_SIZE);
        hash_store_len(total, blk + BLK_DATA_SZIE, le);
        blk_update(hash, blk);
    }
}
