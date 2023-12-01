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

#include "zcrypto/oaep.h"
#include "zcrypto/utils.h"
#include <stdio.h>
#include <time.h>

static void hex_dump(const char* name, const uint8_t* data, size_t len) {
    static char text[RSA_BYTES * 2 + 2];
    for (size_t i = 0; i < len; ++i) {
        uint8_t x = data[i];
        text[i * 2] = _hex((x >> 4) & 0xf);
        text[i * 2 + 1] = _hex(x & 0xf);
    }
    text[len * 2] = '\0';
    printf("%s: %s\n", name, text);
}

static inline uint32_t hex2num(char c) {
    if (c >= 'a') {
        return (uint32_t)(c - 'a' + 10);
    } else {
        return (uint32_t)(c - '0');
    }
}

static void str2bignum(uint32_t n[RSA_SIZE], const char* text) {
    for (size_t i = 0; i < RSA_SIZE; ++i) {
        size_t j = (RSA_SIZE - 1 - i) * 8;
        uint32_t x = hex2num(text[j]);
        x <<= 4;
        x |= hex2num(text[j + 1]);
        x <<= 4;
        x |= hex2num(text[j + 2]);
        x <<= 4;
        x |= hex2num(text[j + 3]);
        x <<= 4;
        x |= hex2num(text[j + 4]);
        x <<= 4;
        x |= hex2num(text[j + 5]);
        x <<= 4;
        x |= hex2num(text[j + 6]);
        x <<= 4;
        x |= hex2num(text[j + 7]);
        n[i] = x;
    }
}

static const char* find_start(const char* text) {
    const char* p = text;
    while (*p != 'x') {
        ++p;
    }
    ++p;
    return p;
}

int main() {
    rsa_ctx_t rsa;
    char line[RSA_BITS / 4 + 32];
    for (;;) {
        if (feof(stdin)) {
            break;
        }
        if (fgets(line, sizeof(line), stdin) == NULL) {
            break;
        }
        printf("%s", line);
        if (line[0] == 'E' && line[1] == ' ' && line[2] == '=') {
            const char* p = find_start(line);
            rsa.E = strtoul(p, NULL, 16);
        } else if (line[0] == 'N' && line[1] == ' ' && line[2] == '=') {
            const char* p = find_start(line);
            str2bignum(rsa.N, p);
            break;
        }
    }
    printf("\n");

    uint8_t cipher[RSA_BYTES];
    uint8_t text[MSG_MAX_LEN + 1];
    srand(time(NULL));
    for (size_t i = 0; i < MSG_MAX_LEN; ++i) {
        text[i] = rand() % ('~' - '!' + 1) + '!';
    }
    text[MSG_MAX_LEN] = '\0';
    printf("msg: %s\n\n", text);

    for (int i = 0; i < 1000; ++i) {
        size_t len = (size_t)rand() % MSG_MAX_LEN + 1;
        rsa_pub_oaep_encrypt(&rsa, text, len, NULL, cipher);
        printf("len: %3ld  ", len);
        hex_dump("cipher", cipher, RSA_BYTES);
    }
}
