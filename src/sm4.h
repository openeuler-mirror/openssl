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

/* OpenSSL EVP interface wrappers */
int sm_sm4_cbc_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);
int sm_sm4_ecb_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);
int sm4_gcm_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);

/* SM4 init/cleanup wrappers (moved from sm_engine.c) */
int sm_sm4_cbc_init(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
int sm_sm4_ecb_init(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
int sm_sm4_cbc_cleanup(EVP_CIPHER_CTX *ctx);
int sm_sm4_ecb_cleanup(EVP_CIPHER_CTX *ctx);

/* SM4 impl ctx size helpers */
int sm_sm4_cbc_impl_ctx_size(void);
int sm_sm4_ecb_impl_ctx_size(void);

/* SM4 property helpers (read from external method) */
int sm_sm4_block_size_cbc(void);
int sm_sm4_block_size_ecb(void);
int sm_sm4_key_length(void);
int sm_sm4_iv_length_cbc(void);
int sm_sm4_iv_length_ecb(void);
unsigned long sm_sm4_flags_cbc(void);
unsigned long sm_sm4_flags_ecb(void);

/* Get external SM4 methods */
const EVP_CIPHER *get_external_sm4_cbc_method(void);
const EVP_CIPHER *get_external_sm4_ecb_method(void);

#ifdef __cplusplus
}
#endif

#endif /* SM4_H */