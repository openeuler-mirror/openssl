#ifndef SM3_H
#define SM3_H

#include <openssl/evp.h>
#include <openssl/engine.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SM3 property helpers (sourced from external method) */
int SmSm3ResultSize(void);
int SmSm3AppDatasize(void);
int SmSm3PkeyType(void);
int SmSm3Flags(void);
int SmSm3BlockSize(void);

/* OpenSSL EVP interface wrappers */
int SmSm3Init(EVP_MD_CTX *ctx);
int SmSm3Update(EVP_MD_CTX *ctx, const void *data, size_t count);
int SmSm3Final(EVP_MD_CTX *ctx, unsigned char *md);
int SmSm3Copy(EVP_MD_CTX *to, const EVP_MD_CTX *from);
int SmSm3Cleanup(EVP_MD_CTX *ctx);
int SmSm3MdCtrl(EVP_MD_CTX *ctx, int cmd, int p1, void *p2);

/* Get external SM3 method */
const EVP_MD *GetExternalSm3Method(void);

#ifdef __cplusplus
}
#endif

#endif /* SM3_H */