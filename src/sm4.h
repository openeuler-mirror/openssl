#ifndef SM4_H
#define SM4_H

#include <openssl/evp.h>
#include <openssl/engine.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SM4 key and block size */
#define SM4_KEY_SIZE 16
#define SM4_BLOCK_SIZE 16

/* SM4 context structure (placeholder) */
typedef struct {
    unsigned char data[128];  /* Placeholder for external library context */
} SM4_KEY;

/* OpenSSL EVP interface wrappers */
int sm4_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
int sm4_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);
int sm4_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);
int sm4_gcm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);

/* SM4 init/cleanup wrappers (moved from sm_engine.c) */
int sm4_cbc_init(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
int sm4_ecb_init(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
int sm4_cbc_cleanup(EVP_CIPHER_CTX *ctx);
int sm4_ecb_cleanup(EVP_CIPHER_CTX *ctx);

/* Get external SM4 methods */
const EVP_CIPHER *get_external_sm4_cbc_method(void);
const EVP_CIPHER *get_external_sm4_ecb_method(void);
const EVP_CIPHER *get_external_sm4_gcm_method(void);

#ifdef __cplusplus
}
#endif

#endif /* SM4_H */
