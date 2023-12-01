/*
Copyright (C) 2020-2023 exiledkingcc@gmail.com

This file is part of zcrypto.

zcrypto is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation; either version 3, or (at your option) any later
version.

zcrypto is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
for more details.

You should have received a copy of the GNU General Public License
along with zcrypto; see the file LICENSE.  If not see
<http://www.gnu.org/licenses/>.
*/

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "rsa.h"
#include <stdlib.h>

// see https://tools.ietf.org/html/rfc8017
// using SHA256
// NOTICE: you has to ensure that message length <= MSG_MAX_LEN
// NOTICE: you has to call `srand` yourself to set rand seed
#define HASH_BYTES 32
#define MSG_MAX_LEN (RSA_BYTES - HASH_BYTES * 2 - 2)

void rsa_pub_oaep_encrypt(const rsa_ctx_t* ctx, const uint8_t* msg, size_t len, const char* label, uint8_t cipher[RSA_BYTES]);

#ifdef __cplusplus
}
#endif
