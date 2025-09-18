#include "sm3.h"
#include <string.h>
#include <openssl/crypto.h>

/* Get external SM3 method */
const EVP_MD *get_external_sm3_method(void)
{
    return EVP_sm3();
}

/* OpenSSL EVP interface implementations */
int sm3_init(EVP_MD_CTX *ctx)
{
    const EVP_MD *md = get_external_sm3_method();
    if (!md) {
        return 0;
    }
    int (*fn)(EVP_MD_CTX *) = EVP_MD_meth_get_init(md);
    if (!fn) {
        return 1;
    }
    return fn(ctx);
}

int sm3_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    const EVP_MD *md = get_external_sm3_method();
    if (!md) {
        return 0;
    }
    int (*fn)(EVP_MD_CTX *, const void *, size_t) = EVP_MD_meth_get_update(md);
    if (!fn) {
        return 1;
    }
    return fn(ctx, data, count);
}

int sm3_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    const EVP_MD *md_method = get_external_sm3_method();
    if (!md_method) {
        return 0;
    }
    int (*fn)(EVP_MD_CTX *, unsigned char *) = EVP_MD_meth_get_final(md_method);
    if (!fn) {
        return 1;
    }
    return fn(ctx, md);
}

int sm3_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
    const EVP_MD *md = get_external_sm3_method();
    if (!md) {
        return 0;
    }
    int (*fn)(EVP_MD_CTX *, const EVP_MD_CTX *) = EVP_MD_meth_get_copy(md);
    if (!fn) {
        return 1;
    }
    return fn(to, from);
}

int sm3_cleanup(EVP_MD_CTX *ctx)
{
    const EVP_MD *md = get_external_sm3_method();
    if (!md) {
        return 0;
    }
    int (*fn)(EVP_MD_CTX *) = EVP_MD_meth_get_cleanup(md);
    if (!fn) {
        return 1;
    }
    return fn(ctx);
}
