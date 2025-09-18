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

const EVP_CIPHER *get_external_sm4_gcm_method(void)
{
    // return EVP_sm4_gcm();
    return NULL;
}

/* OpenSSL EVP interface implementations */
int sm4_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
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

int sm4_cbc_init(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
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

int sm4_ecb_init(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
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

int sm4_cbc_cleanup(EVP_CIPHER_CTX *ctx)
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

int sm4_ecb_cleanup(EVP_CIPHER_CTX *ctx)
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

int sm4_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
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

int sm4_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
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

int sm4_gcm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
{
    const EVP_CIPHER *cipher = get_external_sm4_gcm_method();
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
