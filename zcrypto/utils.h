#ifndef _Z_CRYPTO_UTILS_H_
#define _Z_CRYPTO_UTILS_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <string.h>

static inline uint32_t _lshift(uint32_t x, int n) {
    return ( (x) << (n) ) | ( (x) >> (32 - n) );
}

static inline uint32_t _load_u32(const uint8_t bs[4]) {
    return ((uint32_t)bs[0] << 24) | ((uint32_t)bs[1] << 16) | ((uint32_t)bs[2] << 8) | bs[3];
}

static inline void _store_u32(const uint32_t x, uint8_t bs[4]) {
    bs[0] = (x >> 24) & 0xff;
    bs[1] = (x >> 16) & 0xff;
    bs[2] = (x >> 8) & 0xff;
    bs[3] = (x) & 0xff;
}

static inline void _xor_block(uint8_t *out, const uint8_t *in, size_t len) {
    for (int i = 0; i < len; ++i) {
        out[i] ^= in[i];
    }
}

static inline char _hex(uint8_t n) {
    static const char HEX[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };
    return HEX[n];
}

// expand uint8 data to hex format in place, so data should have len * 2 space
static inline void _expand_hex(uint8_t *data, size_t len) {
    for (int i = len; i >= 0; --i) {
        uint8_t x = data[i];
        data[i * 2] = _hex((x >> 4) & 0xf);
        data[i * 2 + 1] = _hex(x & 0xf);
    }
}


# ifdef __cplusplus
}
# endif

#endif
