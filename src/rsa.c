#include <string.h>
#include "zcrypto/rsa.h"
#include "zcrypto/utils.h"

#define DEBUG_DUMP 0
#if DEBUG_DUMP
#include <stdio.h>

static void _debug(const char *name, const uint32_t *data, size_t len) {
    static char text[RSA_BYTES * 2 + 2];
    for (size_t i = 0; i < len; ++i) {
        size_t j = (len - 1 - i) * 8;
        uint32_t x = data[i];
        text[j] = _hex((x >> 28) & 0xf);
        text[j + 1] = _hex((x >> 24) & 0xf);
        text[j + 2] = _hex((x >> 20) & 0xf);
        text[j + 3] = _hex((x >> 16) & 0xf);
        text[j + 4] = _hex((x >> 12) & 0xf);
        text[j + 5] = _hex((x >> 8) & 0xf);
        text[j + 6] = _hex((x >> 4) & 0xf);
        text[j + 7] = _hex(x & 0xf);
    }
    text[len * 8] = '\0';
    printf("%s = 0x%s\n", name, text);
}
#else
#define _debug(...)
#endif

typedef union {
    uint64_t u64;
    struct {
#if __ZCRYPO_BYTE_ORDER__ == 1
        uint32_t low;
        uint32_t high;
#elif __ZCRYPO_BYTE_ORDER__ == 2
        uint32_t high;
        uint32_t low;
#else
    #error Unknown endianness, please define __ZCRYPO_BYTE_ORDER__ to 1(little endian) or 2(big endian)
    // #define __ZCRYPO_BYTE_ORDER__ 1
    // #define __ZCRYPO_BYTE_ORDER__ 2
#endif
    } u32;
} uintz_t;

typedef union {
    int64_t i64;
    struct {
#if __ZCRYPO_BYTE_ORDER__ == 1
        uint32_t low;
        int32_t high;
#elif __ZCRYPO_BYTE_ORDER__ == 2
        int32_t high;
        uint32_t low;
#else
    #error Unknown endianness, please define __ZCRYPO_BYTE_ORDER__ to 1(little endian) or 2(big endian)
    // #define __ZCRYPO_BYTE_ORDER__ 1
    // #define __ZCRYPO_BYTE_ORDER__ 2
#endif
    } i32;
} intz_t;


static inline void _zeros(uint32_t *X, size_t len) {
    memset(X, 0, sizeof(uint32_t) * len);
}

static inline void _copy(uint32_t *dst, const uint32_t *src, size_t len) {
    memcpy(dst, src, sizeof(uint32_t) * len);
}

// X += Y;
static void _add(uint32_t *X, const uint32_t *Y, size_t n) {
    uintz_t c = {0};
    for (size_t i = 0; i < n; ++i) {
        c.u64 = (uint64_t)X[i] + Y[i] + c.u32.high;
        X[i] = c.u32.low;
    }
    if (c.u32.high > 0) {
        X[n] += c.u32.high;
    }
}

// X -= Y;
static void _sub(uint32_t *X, const uint32_t *Y, size_t n) {
    intz_t c = {0};
    for (size_t i = 0; i < n; ++i) {
        c.i64 = (int64_t)X[i] - Y[i] + c.i32.high;
        X[i] = c.i32.low;
    }
    if (c.i32.high < 0) {
        X[n] += (uint32_t)c.i32.high;
    }
}

// X *= y
static void _mul1(uint32_t *X, uint32_t y, size_t n) {
    uintz_t c = {0};
    for (size_t i = 0; i < n; ++i) {
        c.u64 = (uint64_t)X[i] * y + c.u32.high;
        X[i] = c.u32.low;
    }
    X[n] = c.u32.high;
}

static inline size_t _len(const uint32_t *X, size_t m) {
    while (m > 0 && X[m - 1] == 0) {
        --m;
    }
    return m;
}

static int _cmp(const uint32_t *X, const uint32_t *Y, size_t n) {
    for (size_t i = n - 1; i < n; --i) {
        uint32_t x = X[i];
        uint32_t y = Y[i];
        if (x > y) {
            return 1;
        } else if (x < y) {
            return -1;
        }
    }
    return 0;
}

// X %= Y
static void _mod(uint32_t *X, size_t m, const uint32_t *Y, size_t n) {
    uint32_t dd[RSA_SIZE + 1];
    _zeros(dd, RSA_SIZE + 1);

    m = _len(X, m);
    n = _len(Y, n);
    uint64_t yy = ((uint64_t)Y[n - 1] << 32) + Y[n - 2];
    uint32_t *px = X + m - n;
    while (px >= X) {
        if (px[n] == 0 && _cmp(px, Y, n) < 0) {
            --px;
            continue;
        }
        uint32_t b = 0;
        if (px[n] > 0) {
            uint64_t a = ((uint64_t)px[n] << 32) + px[n - 1];
            b = a / Y[n - 1];
        } else {
            uint64_t a = ((uint64_t)px[n - 1] << 32) + px[n - 2];
            b = a / yy;
        }
        _copy(dd, Y, n);
        dd[n] = 0;
        if (b > 1) {
            _mul1(dd, b, n);
        }
        while (_cmp(px, dd, n + 1) < 0) {
            _sub(dd, Y, n);
        }
        _sub(px, dd, n + 1);
    }
}

// X = A * R % C; R = (2^32) ^ RSA_SIZE
static void _modx(uint32_t *X, const uint32_t *C, const uint32_t *A) {
    uint32_t dd[RSA_SIZE * 2 + 1];
    _zeros(dd, RSA_SIZE * 2 + 1);
    _copy(dd + RSA_SIZE, A, RSA_SIZE);
    _mod(dd, RSA_SIZE * 2, C, RSA_SIZE);
    _copy(X, dd, RSA_SIZE);
}

static void _montgomery(uint32_t X[RSA_SIZE], const uint32_t C[RSA_SIZE], const uint32_t A[RSA_SIZE], const uint32_t B[RSA_SIZE], uint32_t m) {
    uint32_t tempx[RSA_SIZE * 2 + 2];
    _zeros(tempx, RSA_SIZE * 2 + 2);
    uint32_t dd[RSA_SIZE + 1];
    _zeros(dd, RSA_SIZE + 1);
    uint32_t *px = tempx;
    _debug("A", A, RSA_SIZE);
    _debug("C", C, RSA_SIZE);

    uint32_t mm = UINT32_MAX - m + 1;
    for (size_t i = 0; i < RSA_SIZE; ++i) {
        // dd = A * B[i] + C * q; dd[0] == 0; m * C == 1 (mod R); R = 2^32
        // => dd[0] = A[0]*B[i] + C*q == 0 (mod R)
        // => C*q = -A[0]*B[i] (mod R)
        // => q = -m*A[0]*B[i] (mod R)
        // => q = (R - m)*A[0]*B[i] (mod R)
        uint32_t q = (A[0] * B[i] + px[0]) * mm;

        _copy(dd, C, RSA_SIZE);
        _mul1(dd, q, RSA_SIZE);
        _add(px, dd, RSA_SIZE + 1);

        _copy(dd, A, RSA_SIZE);
        _mul1(dd, B[i], RSA_SIZE);
        _add(px, dd, RSA_SIZE + 1);

        // _debug("px", px, RSA_SIZE + 1);
        ++px;
    }
    _debug("px", px, RSA_SIZE + 2);
    _mod(px, RSA_SIZE + 2, C, RSA_SIZE);
    _copy(X, px, RSA_SIZE);
    _debug("X", X, RSA_SIZE);
}

static inline void _swap(uint32_t **px, uint32_t **py) {
    uint32_t *pz = *px;
    *px = *py;
    *py = pz;
}

static inline int _highest_bit_idx(uint32_t x) {
    for (int i = 31; i > 0; --i) {
        if (x >> i) {
            return i;
        }
    }
    return 0;
}

// x = a^(-1) mod 2^32
static uint32_t _inv(uint32_t a) {
    int64_t r0 = (int64_t)1u << 32;
    int64_t r1 = a;
    int64_t t0 = 0, t1 = 1;
    while (r1 != 0) {
        int64_t q = r0 / r1;
        int64_t temp = t1;
        temp = t1;
        t1 = t0 - q * t1;
        t0 = temp;

        temp = r1;
        r1 = r0 - q * r1;
        r0 = temp;
    }
    if (r1 > 1) {
        return 0;
    }
    if (t0 < 0) {
        t0 += (int64_t)1u << 32;
    }
    return (uint32_t)t0;
}


static void _exp_mod(uint32_t X[RSA_SIZE], const uint32_t C[RSA_SIZE], const uint32_t A[RSA_SIZE], const uint32_t B[], int blen) {
    _debug("A", A, RSA_SIZE);
    _debug("C", C, RSA_SIZE);
    uint32_t tempA[RSA_SIZE];
    _modx(tempA, C, A);
    _debug("tempA", tempA, RSA_SIZE);

    uint32_t tempx[RSA_SIZE];
    uint32_t *px = tempx;
    _copy(px, tempA, RSA_SIZE);

    uint32_t tempy[RSA_SIZE];
    uint32_t *py = tempy;
    // _zeros(py, RSA_SIZE);

    uint32_t m = _inv(C[0]);

    int idx = 0;
    for (int j = blen - 1; j >= 0; --j) {
        if (B[j] != 0) {
            idx = _highest_bit_idx(B[j]) + j * 32;
            break;
        }
    }
    for (int i = idx - 1; i >= 0; --i) {
        _montgomery(py, C, px, px, m);
        _swap(&px, &py);

        int j = i / 32;
        int k = i % 32;
        if ((B[j] >> k) & 0x1) {
            _montgomery(py, C, px, tempA, m);
            _swap(&px, &py);
        }
    }
    _zeros(py, RSA_SIZE);
    py[0] = 1u;
    _montgomery(X, C, px, py, m);
}

void rsa_pub_naive(const rsa_ctx_t *ctx, const uint32_t data[RSA_SIZE], uint32_t output[RSA_SIZE]) {
    uint32_t B[1] = {ctx->E};
    _exp_mod(output, ctx->N, data, B, 1);
}

#if ENABLE_RSA_PRIVATE_KEY
void rsa_pri_naive(const rsa_ctx_t *ctx, const uint32_t data[RSA_SIZE], uint32_t output[RSA_SIZE]) {
    _exp_mod(output, ctx->N, data, ctx->D, RSA_SIZE);
}
#endif
