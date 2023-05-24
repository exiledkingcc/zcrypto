#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>

size_t base64_encode(const void *bin, size_t len, void *text);
size_t base64_decode(const void *text, size_t len, void *bin);

#ifdef __cplusplus
}
#endif
