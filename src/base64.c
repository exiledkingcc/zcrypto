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

#include "zcrypto/base64.h"
#include <stdint.h>

static const uint8_t ASCII[] = {
    "ABCDEFGHIJKLMNOP"
    "QRSTUVWXYZabcdef"
    "ghijklmnopqrstuv"
    "wxyz0123456789+/" // make clang-format happy
};

static const uint8_t BIN[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /*  0-15 */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* 16-31 */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 62,   0xff, 0xff, 0xff, 63,   /* 32-47 */
    52,   53,   54,   55,   56,   57,   58,   59,   60,   61,   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* 48-63 */
    0xff, 0,    1,    2,    3,    4,    5,    6,    7,    8,    9,    10,   11,   12,   13,   14,   /* 64-79 */
    15,   16,   17,   18,   19,   20,   21,   22,   23,   24,   25,   0xff, 0xff, 0xff, 0xff, 0xff, /* 80-95 */
    0xff, 26,   27,   28,   29,   30,   31,   32,   33,   34,   35,   36,   37,   38,   39,   40,   /* 96-111 */
    41,   42,   43,   44,   45,   46,   47,   48,   49,   50,   51,   0xff, 0xff, 0xff, 0xff, 0xff, /* 112-127 */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* 128-143 */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* 144-159 */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* 160-175 */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* 176-191 */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* 192-207 */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* 208-223 */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* 224-239 */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* 240-255 */
};

size_t base64_encode(const void* bin, size_t len, void* text) {
    const uint8_t* bb = (const uint8_t*)(bin);
    //
    uint8_t* tt0 = (uint8_t*)(text);
    uint8_t* tt = tt0;
    for (size_t n = len / 3; n--;) {
        *tt++ = ASCII[(bb[0] & 0xfcu) >> 2u];
        *tt++ = ASCII[((bb[0] & 0x03u) << 4u) + ((bb[1] & 0xf0u) >> 4u)];
        *tt++ = ASCII[((bb[2] & 0xc0u) >> 6u) + ((bb[1] & 0x0fu) << 2u)];
        *tt++ = ASCII[bb[2] & 0x3fu];
        bb += 3;
    }

    switch (len % 3) {
    case 2:
        *tt++ = ASCII[(bb[0] & 0xfcu) >> 2u];
        *tt++ = ASCII[((bb[0] & 0x03u) << 4u) + ((bb[1] & 0xf0u) >> 4u)];
        *tt++ = ASCII[(bb[1] & 0x0fu) << 2u];
        *tt++ = '=';
        break;

    case 1:
        *tt++ = ASCII[(bb[0] & 0xfcu) >> 2u];
        *tt++ = ASCII[((bb[0] & 0x03u) << 4u)];
        *tt++ = '=';
        *tt++ = '=';
        break;

    case 0:
        break;
    }
    return (size_t)(tt - tt0);
}

size_t base64_decode(const void* text, size_t len, void* bin) {
    uint8_t* bb0 = (uint8_t*)(bin);
    uint8_t* bb = bb0;
    //
    const uint8_t* tt0 = (const uint8_t*)(text);
    const uint8_t* end = tt0 + (len / 4) * 4;
    const uint8_t* tt = tt0;
    for (; tt < end; tt += 4) {
        uint8_t c4[] = {
            BIN[tt[0]],
            BIN[tt[1]],
            BIN[tt[2]],
            BIN[tt[3]],
        };
        if ((c4[0] | c4[1] | c4[2] | c4[3]) == 0xffu) {
            break;
        }

        *bb++ = (((c4[0] & 0xffu) << 2u) + ((c4[1] & 0x30u) >> 4u));
        *bb++ = ((c4[1] & 0xfu) << 4u) + ((c4[2] & 0x3cu) >> 2u);
        *bb++ = ((c4[2] & 0x3u) << 6u) + c4[3];
    }
    if (tt == end) {
        return (size_t)(bb - bb0);
    }
    uint8_t c4[4];
    c4[0] = BIN[tt[0]];
    c4[1] = BIN[tt[1]];
    c4[2] = tt[2] == '=' ? 0u : BIN[tt[2]];
    c4[3] = tt[3] == '=' ? 0u : BIN[tt[3]];
    if ((c4[0] | c4[1] | c4[2] | c4[3]) == 0xffu) {
        // ERROR
        return (size_t)(bb - bb0);
    }
    *bb++ = (((c4[0] & 0xffu) << 2u) + ((c4[1] & 0x30u) >> 4u));
    if (tt[2] == '=') {
        return (size_t)(bb - bb0);
    }
    *bb++ = ((c4[1] & 0xfu) << 4u) + ((c4[2] & 0x3cu) >> 2u);
    return (size_t)(bb - bb0);
}
