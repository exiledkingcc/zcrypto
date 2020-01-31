#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include "rsa.h"

// see https://tools.ietf.org/html/rfc8017
// using SHA256
// NOTICE: you has to ensure that message length <= MSG_MAX_LEN
// NOTICE: you has to call `srand` yourself to set rand seed
#define HASH_BYTES 32
#define MSG_MAX_LEN (RSA_BYTES - HASH_BYTES * 2 - 2)

void rsa_pub_oaep_encrypt(const rsa_ctx_t *ctx, const uint8_t *msg, size_t len, const char *label, uint8_t cipher[RSA_BYTES]);

# ifdef __cplusplus
}
# endif
