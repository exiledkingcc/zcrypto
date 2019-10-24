#ifndef _Z_CRYPTO_AES_H_
#define _Z_CRYPTO_AES_H_ 1

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define AES_FUNC_DEF_NO_IV(KEY, MODE, EN) void aes_ ## KEY ## _ ## MODE ## _ ## EN (const uint8_t *, size_t, const uint8_t*, uint8_t*)
#define AES_FUNC_DEF_HAS_IV(KEY, MODE, EN) void aes_ ## KEY ## _ ## MODE ## _ ## EN (const uint8_t *, const uint8_t*, size_t, const uint8_t*, uint8_t*)

#define AES_FUNC_DEF(KEY) \
AES_FUNC_DEF_NO_IV(KEY, ecb, encrypt); \
AES_FUNC_DEF_NO_IV(KEY, ecb, decrypt); \
\
AES_FUNC_DEF_HAS_IV(KEY, cbc, decrypt); \
AES_FUNC_DEF_HAS_IV(KEY, cbc, decrypt); \
\
AES_FUNC_DEF_HAS_IV(KEY, cfb, decrypt); \
AES_FUNC_DEF_HAS_IV(KEY, cfb, decrypt); \
\
AES_FUNC_DEF_HAS_IV(KEY, ofb, decrypt); \
AES_FUNC_DEF_HAS_IV(KEY, ofb, decrypt);


AES_FUNC_DEF(128)

AES_FUNC_DEF(192)

AES_FUNC_DEF(256)


# ifdef __cplusplus
}
# endif

#endif
