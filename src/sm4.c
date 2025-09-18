#include "sm4.h"
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

/* Get external SM4 methods */
const EVP_CIPHER *GetExternalSm4CbcMethod(void)
{
    return EVP_sm4_cbc();
}

const EVP_CIPHER *GetExternalSm4EcbMethod(void)
{
    return EVP_sm4_ecb();
}

int SmSm4CbcImplCtxSize(void)
{
    const EVP_CIPHER *ext = GetExternalSm4CbcMethod();
    if (!ext) { return 0; }
    int sz = (int)EVP_CIPHER_impl_ctx_size(ext);
    return sz;
}

int SmSm4EcbImplCtxSize(void)
{
    const EVP_CIPHER *ext = GetExternalSm4EcbMethod();
    if (!ext) { return 0; }
    int sz = (int)EVP_CIPHER_impl_ctx_size(ext);
    return sz;
}

int SmSm4CbcInit(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
    const EVP_CIPHER *cipher = GetExternalSm4CbcMethod();
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

int SmSm4EcbInit(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
{
    const EVP_CIPHER *cipher = GetExternalSm4EcbMethod();
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

int SmSm4CbcCleanup(EVP_CIPHER_CTX *ctx)
{
    const EVP_CIPHER *cipher = GetExternalSm4CbcMethod();
    if (!cipher) {
        return 0;
    }
    int (*fn)(EVP_CIPHER_CTX *) = EVP_CIPHER_meth_get_cleanup(cipher);
    if (!fn) {
        return 1;
    }
    return fn(ctx);
}

int SmSm4EcbCleanup(EVP_CIPHER_CTX *ctx)
{
    const EVP_CIPHER *cipher = GetExternalSm4EcbMethod();
    if (!cipher) {
        return 0;
    }
    int (*fn)(EVP_CIPHER_CTX *) = EVP_CIPHER_meth_get_cleanup(cipher);
    if (!fn) {
        return 1;
    }
    return fn(ctx);
}

int SmSm4BlockSizeCbc(void)
{
    const EVP_CIPHER *ext = GetExternalSm4CbcMethod();
    return ext ? EVP_CIPHER_block_size(ext) : 0;
}

int SmSm4BlockSizeEcb(void)
{
    const EVP_CIPHER *ext = GetExternalSm4EcbMethod();
    return ext ? EVP_CIPHER_block_size(ext) : 0;
}

int SmSm4KeyLength(void)
{
    const EVP_CIPHER *ext = GetExternalSm4EcbMethod();
    return ext ? EVP_CIPHER_key_length(ext) : 0;
}

int SmSm4IvLengthCbc(void)
{
    const EVP_CIPHER *ext = GetExternalSm4CbcMethod();
    return ext ? EVP_CIPHER_iv_length(ext) : 0;
}

int SmSm4IvLengthEcb(void)
{
    const EVP_CIPHER *ext = GetExternalSm4EcbMethod();
    return ext ? EVP_CIPHER_iv_length(ext) : 0;
}

unsigned long SmSm4FlagsCbc(void)
{
    const EVP_CIPHER *ext = GetExternalSm4CbcMethod();
    return ext ? EVP_CIPHER_flags(ext) : 0;
}

unsigned long SmSm4FlagsEcb(void)
{
    const EVP_CIPHER *ext = GetExternalSm4EcbMethod();
    return ext ? EVP_CIPHER_flags(ext) : 0;
}

int SmSm4CbcCipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
{
    const EVP_CIPHER *cipher = GetExternalSm4CbcMethod();
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

int SmSm4EcbCipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
{
    const EVP_CIPHER *cipher = GetExternalSm4EcbMethod();
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