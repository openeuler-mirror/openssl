#ifndef SM3_H
#define SM3_H

#include <openssl/evp.h>
#include <openssl/engine.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SM3 digest size */
#define SM3_DIGEST_LENGTH 32

/* SM3 context structure (placeholder) */
typedef struct {
    unsigned char data[64];  /* Placeholder for external library context */
} SM3_CTX;

/* OpenSSL EVP interface wrappers */
int sm3_init(EVP_MD_CTX *ctx);
int sm3_update(EVP_MD_CTX *ctx, const void *data, size_t count);
int sm3_final(EVP_MD_CTX *ctx, unsigned char *md);
int sm3_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from);
int sm3_cleanup(EVP_MD_CTX *ctx);

/* Get external SM3 method */
const EVP_MD *get_external_sm3_method(void);

#ifdef __cplusplus
}
#endif

#endif /* SM3_H */