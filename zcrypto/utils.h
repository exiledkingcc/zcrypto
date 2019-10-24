#ifndef _Z_CRYPTO_UTILS_H_
#define _Z_CRYPTO_UTILS_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <string.h>

static inline uint32_t _rleft(uint32_t x, int n) {
    return ( (x) << (n) ) | ( (x) >> (32 - n) );
}

static inline uint32_t _bs2w(const uint8_t bs[4]) {
    return ((uint32_t)bs[0] << 24) | ((uint32_t)bs[1] << 16) | ((uint32_t)bs[2] << 8) | bs[3];
}

static inline void _w2bs(const uint32_t x, uint8_t bs[4]) {
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

# ifdef __cplusplus
}
# endif

#endif
