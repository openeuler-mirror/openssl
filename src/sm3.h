#ifndef SM3_H
#define SM3_H

#include <openssl/evp.h>
#include <openssl/engine.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SM3 property helpers (sourced from external method) */
int sm_sm3_result_size(void);
int sm_sm3_app_datasize(void);
int sm_sm3_pkey_type(void);

/* OpenSSL EVP interface wrappers */
int sm_sm3_init(EVP_MD_CTX *ctx);
int sm_sm3_update(EVP_MD_CTX *ctx, const void *data, size_t count);
int sm_sm3_final(EVP_MD_CTX *ctx, unsigned char *md);
int sm_sm3_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from);
int sm_sm3_cleanup(EVP_MD_CTX *ctx);

/* Get external SM3 method */
const EVP_MD *get_external_sm3_method(void);

#ifdef __cplusplus
}
#endif

#endif /* SM3_H */