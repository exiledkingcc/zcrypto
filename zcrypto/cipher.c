#include <assert.h>

#include "cipher.h"
#include "aes.h"
#include "sm4.h"
#include "utils.h"

static void cipher_mode_ecb_encrypt(cipher_ctx_t* ctx, const uint8_t *in, uint8_t *out);
// static void cipher_mode_ecb_decrypt(cipher_ctx_t* ctx, const uint8_t *in, uint8_t *out);

static void cipher_mode_cbc_encrypt(cipher_ctx_t* ctx, const uint8_t *in, uint8_t *out);
static void cipher_mode_cbc_decrypt(cipher_ctx_t* ctx, const uint8_t *in, uint8_t *out);

static void cipher_mode_cfb_encrypt(cipher_ctx_t* ctx, const uint8_t *in, uint8_t *out);
static void cipher_mode_cfb_decrypt(cipher_ctx_t* ctx, const uint8_t *in, uint8_t *out);

static void cipher_mode_ofb_encrypt(cipher_ctx_t* ctx, const uint8_t *in, uint8_t *out);
// static void cipher_mode_ofb_decrypt(cipher_ctx_t* ctx, const uint8_t *in, uint8_t *out);

static cipher_mode_func_t ENCRYPT_MODES[] = {
    NULL,
    cipher_mode_ecb_encrypt,
    cipher_mode_cbc_encrypt,
    cipher_mode_cfb_encrypt,
    cipher_mode_ofb_encrypt,
};

static cipher_mode_func_t DECRYPT_MODES[] = {
    NULL,
    cipher_mode_ecb_encrypt,
    cipher_mode_cbc_decrypt,
    cipher_mode_cfb_decrypt,
    cipher_mode_ofb_encrypt,
};


void cipher_init(cipher_ctx_t *ctx, int alg, size_t keylen, uint8_t *key, int mode, uint8_t *iv, bool decrypt) {
    assert(alg == ALG_AES || alg == ALG_SM4);
    assert(mode == MODE_ECB || mode == MODE_CBC || mode == MODE_CFB || mode == MODE_OFB);
    assert(ctx != NULL && key != NULL);

    if (decrypt) {
        ctx->mode_func = DECRYPT_MODES[mode];
    } else {
        ctx->mode_func = ENCRYPT_MODES[mode];
    }

    if (mode != MODE_ECB) {
        assert(iv != NULL);
        memcpy(ctx->blk, iv, BLOCK_SIZE);

        // CFB and OFB use block encrypt for decrypt
        if (mode == MODE_CFB || mode == MODE_OFB) {
            decrypt = false;
        }
    }

    if (alg == ALG_AES) {
        assert(keylen == 128 || keylen == 192 || keylen == 256);
        aes_cipher_gen_key(key, keylen, ctx->rkey, decrypt);
        if (decrypt) {
            ctx->blk_func = aes_cipher_block_decrypt;
        } else {
            ctx->blk_func = aes_cipher_block_encrypt;
        }

    } else if (alg == ALG_SM4) {
        assert(keylen == 128);

        sm4_cipher_gen_key(key, keylen, ctx->rkey, decrypt);
        ctx->blk_func = sm4_cipher_block_encrypt;
    }
    ctx->keylen = keylen;
}

void cipher_operate(cipher_ctx_t *ctx, size_t len, const uint8_t *in, uint8_t *out) {
    assert(len % BLOCK_SIZE == 0);
    for (size_t i = 0; i < len; i += BLOCK_SIZE) {
        ctx->mode_func(ctx, in + i, out + i);
    }
}

static void cipher_mode_ecb_encrypt(cipher_ctx_t* ctx, const uint8_t *in, uint8_t *out) {
    ctx->blk_func(ctx->rkey, ctx->keylen, in, out);
}

static void cipher_mode_cbc_encrypt(cipher_ctx_t* ctx, const uint8_t *in, uint8_t *out) {
    _xor_block(ctx->blk, in, BLOCK_SIZE);
    ctx->blk_func(ctx->rkey, ctx->keylen, ctx->blk, out);
    memcpy(ctx->blk, out, BLOCK_SIZE);
}

static void cipher_mode_cbc_decrypt(cipher_ctx_t* ctx, const uint8_t *in, uint8_t *out) {
    ctx->blk_func(ctx->rkey, ctx->keylen, in, out);
    _xor_block(out, ctx->blk, BLOCK_SIZE);
    memcpy(ctx->blk, in, BLOCK_SIZE);
}

static void cipher_mode_cfb_encrypt(cipher_ctx_t* ctx, const uint8_t *in, uint8_t *out) {
    ctx->blk_func(ctx->rkey, ctx->keylen, ctx->blk, out);
    _xor_block(out, in, BLOCK_SIZE);
    memcpy(ctx->blk, out, BLOCK_SIZE);
}

static void cipher_mode_cfb_decrypt(cipher_ctx_t* ctx, const uint8_t *in, uint8_t *out) {
    ctx->blk_func(ctx->rkey, ctx->keylen, ctx->blk, out);
    _xor_block(out, in, BLOCK_SIZE);
    memcpy(ctx->blk, in, BLOCK_SIZE);
}

static void cipher_mode_ofb_encrypt(cipher_ctx_t* ctx, const uint8_t *in, uint8_t *out) {
    ctx->blk_func(ctx->rkey, ctx->keylen, ctx->blk, out);
    memcpy(ctx->blk, out, BLOCK_SIZE);
    _xor_block(out, in, BLOCK_SIZE);
}
