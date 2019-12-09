#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#define RSA_BITS 2048
#define RSA_BYTES (2048 / 8)
#define RSA_SIZE (RSA_BYTES / sizeof(uint32_t))

typedef struct {
    uint32_t N[RSA_SIZE];
    uint32_t E;
} rsa_ctx_t;

void rsa_pub_naive(const rsa_ctx_t *ctx, const uint32_t plain[RSA_SIZE], uint32_t cipher[RSA_SIZE]);

# ifdef __cplusplus
}
# endif
