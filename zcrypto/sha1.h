#ifndef _Z_CRYPTO_SHA1_H_
#define _Z_CRYPTO_SHA1_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    uint64_t len;
    uint32_t hash[5];
    uint8_t blk[64];
} sha1_ctx_t;

void sha1_init(sha1_ctx_t *ctx);
void sha1_update(sha1_ctx_t *ctx, const uint8_t *data, size_t len);
void sha1_digest(sha1_ctx_t *ctx, uint8_t *data);
void sha1_hexdigest(sha1_ctx_t *ctx, uint8_t *data);

# ifdef __cplusplus
}
# endif

#endif
