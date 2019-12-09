#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "zcrypto/rsa.h"

static void expect_equal(const char *name, const uint32_t *a, const uint32_t *b, size_t len) {
    if (memcmp(a, b, len * sizeof(uint32_t)) == 0) {
        printf("%s OK!\n", name);
    } else {
        printf("%s FAIL!\n", name);
    }
}

static inline uint32_t hex2num(char c) {
    if (c >= 'a') {
        return c - 'a' + 10;
    } else {
        return c - '0';
    }
}

static void str2bignum(uint32_t n[RSA_SIZE], const char *text) {
    for (size_t i = RSA_SIZE - 1; i < RSA_SIZE; --i) {
        size_t j = (RSA_SIZE - 1 - i) * 8;
        uint32_t x = hex2num(text[j]);
        x <<= 4; x |= hex2num(text[j + 1]);
        x <<= 4; x |= hex2num(text[j + 2]);
        x <<= 4; x |= hex2num(text[j + 3]);
        x <<= 4; x |= hex2num(text[j + 4]);
        x <<= 4; x |= hex2num(text[j + 5]);
        x <<= 4; x |= hex2num(text[j + 6]);
        x <<= 4; x |= hex2num(text[j + 7]);
        n[i] = x;
    }
}

static const char * find_start(const char *text) {
    const char *p = text;
    while (*p != 'x') {
        ++p;
    }
    ++p;
    return p;
}

int main() {
    rsa_ctx_t rsa;
    uint32_t M[RSA_SIZE];
    uint32_t C[RSA_SIZE];
    uint32_t C2[RSA_SIZE];

    char line[RSA_BITS / 4 + 32];
    for (;;) {
        if (feof(stdin)) {
            break;
        }
        if (fgets(line, sizeof(line), stdin) == NULL) {
            break;
        }
        if (line[0] == 'E') {
            const char *p = find_start(line);
            rsa.E = strtoul(p, NULL, 16);
        } else if (line[0] == 'N') {
            const char *p = find_start(line);
            str2bignum(rsa.N, p);
        } else if (line[0] == 'M') {
            const char *p = find_start(line);
            str2bignum(M, p);

            fgets(line, sizeof(line), stdin);
            if (line[0] != 'C') {
                break;
            }
            p = find_start(line);
            str2bignum(C, p);

            rsa_pub_naive(&rsa, M, C2);
            expect_equal("rsa_pub_naive", C, C2, RSA_SIZE);
        }
    }
}
