#include "sm4.h"
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

/* Get external SM4 methods */
const EVP_CIPHER *get_external_sm4_cbc_method(void)
{
    return EVP_sm4_cbc();
}

const EVP_CIPHER *get_external_sm4_ecb_method(void)
{
    return EVP_sm4_ecb();
}

int sm_sm4_cbc_impl_ctx_size(void)
{
    const EVP_CIPHER *ext = get_external_sm4_cbc_method();
    if (!ext) return 0;
    int sz = (int)EVP_CIPHER_impl_ctx_size(ext);
    return sz;
}

int sm_sm4_ecb_impl_ctx_size(void)
{
    const EVP_CIPHER *ext = get_external_sm4_ecb_method();
    if (!ext) return 0;
    int sz = (int)EVP_CIPHER_impl_ctx_size(ext);
    return sz;
}

int sm_sm4_cbc_init(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
    const EVP_CIPHER *cipher = get_external_sm4_cbc_method();
    if (!cipher) {
        return 0;
    }
    int (*fn)(EVP_CIPHER_CTX *, const unsigned char *, const unsigned char *, int);
    fn = EVP_CIPHER_meth_get_init(cipher);
    if (!fn) {
        return 1;
    }
    return fn(ctx, key, iv, enc);
}

int sm_sm4_ecb_init(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
    const EVP_CIPHER *cipher = get_external_sm4_ecb_method();
    if (!cipher) {
        return 0;
    }
    int (*fn)(EVP_CIPHER_CTX *, const unsigned char *, const unsigned char *, int);
    fn = EVP_CIPHER_meth_get_init(cipher);
    if (!fn) {
        return 1;
    }
    return fn(ctx, key, iv, enc);
}

int sm_sm4_cbc_cleanup(EVP_CIPHER_CTX *ctx)
{
    const EVP_CIPHER *cipher = get_external_sm4_cbc_method();
    if (!cipher) {
        return 0;
    }
    int (*fn)(EVP_CIPHER_CTX *) = EVP_CIPHER_meth_get_cleanup(cipher);
    if (!fn) {
        return 1;
    }
    return fn(ctx);
}

int sm_sm4_ecb_cleanup(EVP_CIPHER_CTX *ctx)
{
    const EVP_CIPHER *cipher = get_external_sm4_ecb_method();
    if (!cipher) {
        return 0;
    }
    int (*fn)(EVP_CIPHER_CTX *) = EVP_CIPHER_meth_get_cleanup(cipher);
    if (!fn) {
        return 1;
    }
    return fn(ctx);
}

int sm_sm4_block_size_cbc(void)
{
    const EVP_CIPHER *ext = get_external_sm4_cbc_method();
    return ext ? EVP_CIPHER_block_size(ext) : 0;
}

int sm_sm4_block_size_ecb(void)
{
    const EVP_CIPHER *ext = get_external_sm4_ecb_method();
    return ext ? EVP_CIPHER_block_size(ext) : 0;
}

int sm_sm4_key_length(void)
{
    const EVP_CIPHER *ext = get_external_sm4_ecb_method();
    return ext ? EVP_CIPHER_key_length(ext) : 0;
}

int sm_sm4_iv_length_cbc(void)
{
    const EVP_CIPHER *ext = get_external_sm4_cbc_method();
    return ext ? EVP_CIPHER_iv_length(ext) : 0;
}

int sm_sm4_iv_length_ecb(void)
{
    const EVP_CIPHER *ext = get_external_sm4_ecb_method();
    return ext ? EVP_CIPHER_iv_length(ext) : 0;
}

unsigned long sm_sm4_flags_cbc(void)
{
    const EVP_CIPHER *ext = get_external_sm4_cbc_method();
    return ext ? EVP_CIPHER_flags(ext) : 0;
}

unsigned long sm_sm4_flags_ecb(void)
{
    const EVP_CIPHER *ext = get_external_sm4_ecb_method();
    return ext ? EVP_CIPHER_flags(ext) : 0;
}

int sm_sm4_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
{
    const EVP_CIPHER *cipher = get_external_sm4_cbc_method();
    if (!cipher) {
        return 0;
    }
    int (*fn)(EVP_CIPHER_CTX *, unsigned char *, const unsigned char *, size_t);
    fn = EVP_CIPHER_meth_get_do_cipher(cipher);
    if (!fn) {
        return 1;
    }
    return fn(ctx, out, in, inl);
}

int sm_sm4_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
{
    const EVP_CIPHER *cipher = get_external_sm4_ecb_method();
    if (!cipher) {
        return 0;
    }
    int (*fn)(EVP_CIPHER_CTX *, unsigned char *, const unsigned char *, size_t);
    fn = EVP_CIPHER_meth_get_do_cipher(cipher);
    if (!fn) {
        return 1;
    }
    return fn(ctx, out, in, inl);
}