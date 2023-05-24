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

void rsa_pub_naive(const rsa_ctx_t *ctx, const uint32_t data[RSA_SIZE], uint32_t output[RSA_SIZE]);

#if ENABLE_RSA_PRIVATE_KEY
void rsa_pri_naive(const rsa_ctx_t *ctx, const uint32_t data[RSA_SIZE], uint32_t output[RSA_SIZE]);
#endif

# ifdef __cplusplus
}
# endif
