#include "sm3.h"
#include <string.h>
#include <openssl/crypto.h>

/* Get external SM3 method */
const EVP_MD *GetExternalSm3Method(void)
{
    return EVP_sm3();
}

int SmSm3ResultSize(void)
{
    const EVP_MD *md = GetExternalSm3Method();
    if (!md) { return 0; }
    int sz = EVP_MD_size(md);
    return sz;
}

int SmSm3AppDatasize(void)
{
    const EVP_MD *md = GetExternalSm3Method();
    if (!md) { return 0; }
    int sz = EVP_MD_meth_get_app_datasize(md);
    return sz;
}

int SmSm3PkeyType(void)
{
    const EVP_MD *md = GetExternalSm3Method();
    if (!md) { return NID_undef; }
    return EVP_MD_pkey_type(md);
}

/* OpenSSL EVP interface implementations */
int SmSm3Init(EVP_MD_CTX *ctx)
{
    const EVP_MD *md = GetExternalSm3Method();
    if (!md) {
        return 0;
    }
    int (*fn)(EVP_MD_CTX *) = EVP_MD_meth_get_init(md);
    if (!fn) {
        return 1;
    }
    return fn(ctx);
}

int SmSm3Update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    const EVP_MD *md = GetExternalSm3Method();
    if (!md) {
        return 0;
    }
    int (*fn)(EVP_MD_CTX *, const void *, size_t) = EVP_MD_meth_get_update(md);
    if (!fn) {
        return 1;
    }
    return fn(ctx, data, count);
}

int SmSm3Final(EVP_MD_CTX *ctx, unsigned char *md)
{
    const EVP_MD *mdMethod = GetExternalSm3Method();
    if (!mdMethod) {
        return 0;
    }
    int (*fn)(EVP_MD_CTX *, unsigned char *) = EVP_MD_meth_get_final(mdMethod);
    if (!fn) {
        return 1;
    }
    return fn(ctx, md);
}

int SmSm3Copy(EVP_MD_CTX *to, const EVP_MD_CTX *from)
{
    const EVP_MD *md = GetExternalSm3Method();
    if (!md) {
        return 0;
    }
    int (*fn)(EVP_MD_CTX *, const EVP_MD_CTX *) = EVP_MD_meth_get_copy(md);
    if (!fn) {
        return 1;
    }
    return fn(to, from);
}

int SmSm3Cleanup(EVP_MD_CTX *ctx)
{
    const EVP_MD *md = GetExternalSm3Method();
    if (!md) {
        return 0;
    }
    int (*fn)(EVP_MD_CTX *) = EVP_MD_meth_get_cleanup(md);
    if (!fn) {
        return 1;
    }
    return fn(ctx);
}