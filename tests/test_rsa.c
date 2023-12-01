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

#include "zcrypto/rsa.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool expect_equal(const char* name, const uint32_t* a, const uint32_t* b, size_t len) {
    if (memcmp(a, b, len * sizeof(uint32_t)) == 0) {
        // printf("%s OK!\n", name);
        return true;
    } else {
        printf("%s FAIL!\n", name);
        return false;
    }
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
    uint32_t M[RSA_SIZE];
    uint32_t M2[RSA_SIZE];
    uint32_t C[RSA_SIZE];
    uint32_t C2[RSA_SIZE];

    char line[RSA_BITS / 4 + 32];
    int cnt = 0, err1 = 0, err2 = 0;
    for (;;) {
        if (feof(stdin)) {
            break;
        }
        if (fgets(line, sizeof(line), stdin) == NULL) {
            break;
        }
        if (line[0] == 'E') {
            const char* p = find_start(line);
            rsa.E = strtoul(p, NULL, 16);
        } else if (line[0] == 'D') {
            const char* p = find_start(line);
            str2bignum(rsa.D, p);
        } else if (line[0] == 'N') {
            const char* p = find_start(line);
            str2bignum(rsa.N, p);
        } else if (line[0] == 'M') {
            const char* p = find_start(line);
            str2bignum(M, p);

            if (fgets(line, sizeof(line), stdin) == NULL) {
                printf("expected C NOT found\n");
                break;
            }
            if (line[0] != 'C') {
                break;
            }
            p = find_start(line);
            str2bignum(C, p);
            ++cnt;

            rsa_pub_naive(&rsa, M, C2);
            if (!expect_equal("rsa_pub_naive", C, C2, RSA_SIZE)) {
                ++err1;
            }

            rsa_pri_naive(&rsa, C2, M2);
            if (!expect_equal("rsa_pri_naive", M, M2, RSA_SIZE)) {
                ++err2;
            }
            printf("%d ok\n", cnt);
        }
    }
    printf("COUNT: %d, ERROR: %d %d\n", cnt, err1, err2);
}
