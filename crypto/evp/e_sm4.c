/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 * Ported from Ribose contributions from Botan.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#ifndef OPENSSL_NO_SM4
# include <openssl/evp.h>
# include <openssl/modes.h>
# include "crypto/sm4.h"
# include "crypto/evp.h"
# include "crypto/sm4_platform.h"
# include "evp_local.h"
# include "modes_local.h"



typedef struct {
    union {
        double align;
        SM4_KEY ks;
    } ks;
    block128_f block;
    union {
        ecb128_f ecb;
        cbc128_f cbc;
        ctr128_f ctr;
    } stream;
} EVP_SM4_KEY;

# define BLOCK_CIPHER_generic(nid,blocksize,ivlen,nmode,mode,MODE,flags) \
static const EVP_CIPHER sm4_##mode = { \
        nid##_##nmode,blocksize,128/8,ivlen, \
        flags|EVP_CIPH_##MODE##_MODE,   \
        sm4_init_key,                   \
        sm4_##mode##_cipher,            \
        NULL,                           \
        sizeof(EVP_SM4_KEY),            \
        NULL,NULL,NULL,NULL }; \
const EVP_CIPHER *EVP_sm4_##mode(void) \
{ return &sm4_##mode; }

#define BLOCK_CIPHER_generic_pack(nid,flags)             \
        BLOCK_CIPHER_generic(nid,16,16,cbc,cbc,CBC,flags|EVP_CIPH_FLAG_DEFAULT_ASN1)     \
        BLOCK_CIPHER_generic(nid,16,0,ecb,ecb,ECB,flags|EVP_CIPH_FLAG_DEFAULT_ASN1)      \
        BLOCK_CIPHER_generic(nid,1,16,ofb128,ofb,OFB,flags|EVP_CIPH_FLAG_DEFAULT_ASN1)   \
        BLOCK_CIPHER_generic(nid,1,16,cfb128,cfb,CFB,flags|EVP_CIPH_FLAG_DEFAULT_ASN1)   \
        BLOCK_CIPHER_generic(nid,1,16,ctr,ctr,CTR,flags)

static int sm4_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                        const unsigned char *iv, int enc)
{
    int mode;
    EVP_SM4_KEY *dat = EVP_C_DATA(EVP_SM4_KEY, ctx);

    mode = EVP_CIPHER_CTX_mode(ctx);
    if ((mode == EVP_CIPH_ECB_MODE || mode == EVP_CIPH_CBC_MODE) && !enc) {
#ifdef HWSM4_CAPABLE
        if (HWSM4_CAPABLE) {
            HWSM4_set_decrypt_key(key, &dat->ks.ks);
            dat->block = (block128_f) HWSM4_decrypt;
            dat->stream.cbc = NULL;
# ifdef HWSM4_cbc_encrypt
            if (mode == EVP_CIPH_CBC_MODE)
                dat->stream.cbc = (cbc128_f) HWSM4_cbc_encrypt;
# endif
# ifdef HWSM4_ecb_encrypt
            if (mode == EVP_CIPH_ECB_MODE)
                dat->stream.ecb = (ecb128_f) HWSM4_ecb_encrypt;
# endif
        } else
#endif
#ifdef VPSM4_EX_CAPABLE
        if (VPSM4_EX_CAPABLE) {
            vpsm4_ex_set_decrypt_key(key, &dat->ks.ks);
            dat->block = (block128_f) vpsm4_ex_decrypt;
            if (mode == EVP_CIPH_ECB_MODE)
                dat->stream.ecb = (ecb128_f) vpsm4_ex_ecb_encrypt;
        } else
#endif
        {
            dat->block = (block128_f)SM4_decrypt;
            SM4_set_key(key, EVP_CIPHER_CTX_get_cipher_data(ctx));
        }
    } else {
#ifdef HWSM4_CAPABLE
        if (HWSM4_CAPABLE) {
            HWSM4_set_encrypt_key(key, &dat->ks.ks);
            dat->block = (block128_f) HWSM4_encrypt;
            dat->stream.cbc = NULL;
# ifdef HWSM4_cbc_encrypt
            if (mode == EVP_CIPH_CBC_MODE)
                dat->stream.cbc = (cbc128_f) HWSM4_cbc_encrypt;
            else
# endif
# ifdef HWSM4_ecb_encrypt
            if (mode == EVP_CIPH_ECB_MODE)
                dat->stream.ecb = (ecb128_f) HWSM4_ecb_encrypt;
            else
# endif
# ifdef HWSM4_ctr32_encrypt_blocks
            if (mode == EVP_CIPH_CTR_MODE)
                dat->stream.ctr = (ctr128_f) HWSM4_ctr32_encrypt_blocks;
            else
# endif
                (void)0;            /* terminate potentially open 'else' */
        } else
#endif
#ifdef VPSM4_EX_CAPABLE
        if (VPSM4_EX_CAPABLE) {
            vpsm4_ex_set_encrypt_key(key, &dat->ks.ks);
            dat->block = (block128_f) vpsm4_ex_encrypt;
            if (mode == EVP_CIPH_ECB_MODE)
                dat->stream.ecb = (ecb128_f) vpsm4_ex_ecb_encrypt;
        } else
#endif
        {
            dat->block = (block128_f)SM4_encrypt;
            SM4_set_key(key, EVP_CIPHER_CTX_get_cipher_data(ctx));
        }
    }
    return 1;
}

static int sm4_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    EVP_SM4_KEY *dat = EVP_C_DATA(EVP_SM4_KEY,ctx);

    if (dat->stream.cbc)
        (*dat->stream.cbc) (in, out, len, &dat->ks.ks, ctx->iv,
                            EVP_CIPHER_CTX_encrypting(ctx));
    else if (EVP_CIPHER_CTX_encrypting(ctx))
        CRYPTO_cbc128_encrypt(in, out, len, &dat->ks.ks,
                              EVP_CIPHER_CTX_iv_noconst(ctx), dat->block);
    else
        CRYPTO_cbc128_decrypt(in, out, len, &dat->ks.ks,
                              EVP_CIPHER_CTX_iv_noconst(ctx), dat->block);
    return 1;
}

static int sm4_cfb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    EVP_SM4_KEY *dat = EVP_C_DATA(EVP_SM4_KEY,ctx);
    int num = EVP_CIPHER_CTX_num(ctx);

    CRYPTO_cfb128_encrypt(in, out, len, &dat->ks.ks,
                          ctx->iv, &num,
                          EVP_CIPHER_CTX_encrypting(ctx), dat->block);
    EVP_CIPHER_CTX_set_num(ctx, num);

    return 1;
}

static int sm4_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    size_t bl = EVP_CIPHER_CTX_block_size(ctx);
    size_t i;
    EVP_SM4_KEY *dat = EVP_C_DATA(EVP_SM4_KEY,ctx);

    if (len < bl){
        return 1;
    }
    if (dat->stream.ecb != NULL)
        (*dat->stream.ecb) (in, out, len, &dat->ks.ks,
                            EVP_CIPHER_CTX_encrypting(ctx));
    else
        for (i = 0, len -= bl; i <= len; i += bl)
            (*dat->block) (in + i, out + i, &dat->ks.ks);
    return 1;
}

static int sm4_ofb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    EVP_SM4_KEY *dat = EVP_C_DATA(EVP_SM4_KEY,ctx);
    int num = EVP_CIPHER_CTX_num(ctx);

    CRYPTO_ofb128_encrypt(in, out, len, &dat->ks.ks,
                          ctx->iv, &num, dat->block);
    EVP_CIPHER_CTX_set_num(ctx, num);
    return 1;
}

static int sm4_ctr_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    int n = EVP_CIPHER_CTX_num(ctx);
    unsigned int num;
    EVP_SM4_KEY *dat = EVP_C_DATA(EVP_SM4_KEY,ctx);

    if (n < 0)
        return 0;
    num = (unsigned int)n;

    if (dat->stream.ctr)
        CRYPTO_ctr128_encrypt_ctr32(in, out, len, &dat->ks,
                                    ctx->iv,
                                    EVP_CIPHER_CTX_buf_noconst(ctx),
                                    &num, dat->stream.ctr);
    else
        CRYPTO_ctr128_encrypt(in, out, len, &dat->ks.ks,
                                ctx->iv,
                                EVP_CIPHER_CTX_buf_noconst(ctx), &num,
                                dat->block);
    EVP_CIPHER_CTX_set_num(ctx, num);
    return 1;
}

BLOCK_CIPHER_generic_pack(NID_sm4, 0)

typedef struct {
    union {
        double align;
        SM4_KEY ks;
    } ks1, ks2;                 /* sm4 key schedules to use */
    XTS128_CONTEXT xts;
    int std;                    /* 0 for xts mode in GB/T 17964-2021    */
                                /* 1 for xts mode in IEEE Std 1619-2007 */
    void (*stream_gb) (const unsigned char *in,
                    unsigned char *out, size_t length,
                    const SM4_KEY *key1, const SM4_KEY *key2,
                    const unsigned char iv[16]);   /* stream for xts mode in GB/T 17964-2021     */
    void (*stream) (const unsigned char *in,
                    unsigned char *out, size_t length,
                    const SM4_KEY *key1, const SM4_KEY *key2,
                    const unsigned char iv[16]);   /* stream for xts mode in IEEE Std 1619-2007   */
} EVP_SM4_XTS_CTX;

static int sm4_xts_ctrl(EVP_CIPHER_CTX *c, int type, int arg, void *ptr)
{
    EVP_SM4_XTS_CTX *xctx = EVP_C_DATA(EVP_SM4_XTS_CTX, c);
 
    if (type == EVP_CTRL_COPY) {
        EVP_CIPHER_CTX *out = ptr;
        EVP_SM4_XTS_CTX *xctx_out = EVP_C_DATA(EVP_SM4_XTS_CTX,out);
 
        if (xctx->xts.key1) {
            if (xctx->xts.key1 != &xctx->ks1)
                return 0;
            xctx_out->xts.key1 = &xctx_out->ks1;
        }
        if (xctx->xts.key2) {
            if (xctx->xts.key2 != &xctx->ks2)
                return 0;
            xctx_out->xts.key2 = &xctx_out->ks2;
        }
        return 1;
    } else if (type == EVP_CTRL_XTS_STANDARD) {
        if ((arg < 0) || (arg > 1))
            return 0;
        xctx->std = arg;
        return 1;
    } else if (type != EVP_CTRL_INIT)
        return -1;
    /* key1 and key2 are used as an indicator both key and IV are set */
    xctx->xts.key1 = NULL;
    xctx->xts.key2 = NULL;
    return 1;
}
 
static int sm4_xts_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                            const unsigned char *iv, int enc)
{
    EVP_SM4_XTS_CTX *xctx = EVP_C_DATA(EVP_SM4_XTS_CTX,ctx);
 
    if (!iv && !key)
        return 1;
 
    if (key)
        do {
            /* The key is two half length keys in reality */
            const int bytes = EVP_CIPHER_CTX_key_length(ctx) / 2;
            xctx->stream_gb = NULL;
            xctx->stream = NULL;
#ifdef HWSM4_CAPABLE
            if (HWSM4_CAPABLE) {
                if (enc) {
                    HWSM4_set_encrypt_key(key, &xctx->ks1.ks);
                    xctx->xts.block1 = (block128_f) HWSM4_encrypt;
# ifdef HWSM4_xts_encrypt_gb
                    xctx->stream_gb = HWSM4_xts_encrypt_gb;
# endif
# ifdef HWSM4_xts_encrypt
                    xctx->stream = HWSM4_xts_encrypt;
# endif
                } else {
                    HWSM4_set_decrypt_key(key, &xctx->ks1.ks);
                    xctx->xts.block1 = (block128_f) HWSM4_decrypt;
# ifdef HWSM4_xts_decrypt_gb
                    xctx->stream_gb = HWSM4_xts_decrypt_gb;
# endif
# ifdef HWSM4_xts_decrypt
                    xctx->stream = HWSM4_xts_decrypt;
# endif
                }
                HWSM4_set_encrypt_key(key + bytes, &xctx->ks2.ks);
                xctx->xts.block2 = (block128_f) HWSM4_encrypt;

                xctx->xts.key1 = &xctx->ks1;
                break;
            } else
#endif
#ifdef VPSM4_EX_CAPABLE
            if (VPSM4_EX_CAPABLE) {
                if (enc) {
                    vpsm4_ex_set_encrypt_key(key, &xctx->ks1.ks);
                    xctx->xts.block1 = (block128_f) vpsm4_ex_encrypt;
                    xctx->stream_gb = vpsm4_ex_xts_encrypt_gb;
                    xctx->stream = vpsm4_ex_xts_encrypt;
                } else {
                    vpsm4_ex_set_decrypt_key(key, &xctx->ks1.ks);
                    xctx->xts.block1 = (block128_f) vpsm4_ex_decrypt;
                    xctx->stream_gb = vpsm4_ex_xts_decrypt_gb;
                    xctx->stream = vpsm4_ex_xts_decrypt;
                }
                vpsm4_ex_set_encrypt_key(key + bytes, &xctx->ks2.ks);
                xctx->xts.block2 = (block128_f) vpsm4_ex_encrypt;

                xctx->xts.key1 = &xctx->ks1;
                break;
            } else
#endif
            (void)0;        /* terminate potentially open 'else' */

            if (enc) {
                SM4_set_key(key, &xctx->ks1.ks);
                xctx->xts.block1 = (block128_f) SM4_encrypt;
            } else {
                SM4_set_key(key, &xctx->ks1.ks);
                xctx->xts.block1 = (block128_f) SM4_decrypt;
            }
 
            SM4_set_key(key + bytes, &xctx->ks2.ks);
            xctx->xts.block2 = (block128_f) SM4_encrypt;
 
            xctx->xts.key1 = &xctx->ks1;
        } while (0);
 
    if (iv) {
        xctx->xts.key2 = &xctx->ks2;
        memcpy(EVP_CIPHER_CTX_iv_noconst(ctx), iv, 16);
    }
 
    return 1;
}

static int sm4_xts_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    EVP_SM4_XTS_CTX *xctx = EVP_C_DATA(EVP_SM4_XTS_CTX,ctx);
    if (!xctx->xts.key1 || !xctx->xts.key2)
        return 0;
    if (!out || !in || len < SM4_BLOCK_SIZE)
        return 0;
    if (xctx->std) {
        if (xctx->stream)
            (*xctx->stream) (in, out, len,
                            xctx->xts.key1, xctx->xts.key2,
                            EVP_CIPHER_CTX_iv_noconst(ctx));
        else if (CRYPTO_xts128_encrypt(&xctx->xts, EVP_CIPHER_CTX_iv_noconst(ctx),
                                    in, out, len,
                                    EVP_CIPHER_CTX_encrypting(ctx)))
            return 0;
    } else {
        if (xctx->stream_gb)
            (*xctx->stream_gb) (in, out, len,
                            xctx->xts.key1, xctx->xts.key2,
                            EVP_CIPHER_CTX_iv_noconst(ctx));
        else if (CRYPTO_xts128gb_encrypt(&xctx->xts, EVP_CIPHER_CTX_iv_noconst(ctx),
                                    in, out, len,
                                    EVP_CIPHER_CTX_encrypting(ctx)))
            return 0;
    }
    return 1;
}
 
#define SM4_XTS_BLOCK_SIZE 1
#define SM4_XTS_IV_LENGTH 16
#define SM4_XTS_KEY_LENGTH 32
 
#define XTS_FLAGS       (EVP_CIPH_FLAG_DEFAULT_ASN1 | EVP_CIPH_CUSTOM_IV \
                         | EVP_CIPH_ALWAYS_CALL_INIT | EVP_CIPH_CTRL_INIT \
                         | EVP_CIPH_CUSTOM_COPY | EVP_CIPH_XTS_MODE)
 
static const EVP_CIPHER sm4_xts_mode = {
        NID_sm4_xts,
        SM4_XTS_BLOCK_SIZE,
        SM4_XTS_KEY_LENGTH,
        SM4_XTS_IV_LENGTH,
        XTS_FLAGS,
        sm4_xts_init_key,
        sm4_xts_cipher,
        NULL,
        sizeof(EVP_SM4_XTS_CTX),
        NULL, NULL, sm4_xts_ctrl, NULL
};
 
const EVP_CIPHER *EVP_sm4_xts(void)
{
    return &sm4_xts_mode;
}

#endif
