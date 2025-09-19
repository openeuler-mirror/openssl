#ifndef SM4_H
#define SM4_H

#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/asn1.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SM4 key and block size */
#define SM4_KEY_SIZE 16
#define SM4_BLOCK_SIZE 16

/* OpenSSL EVP interface wrappers */
int SmSm4CbcCipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);
int SmSm4EcbCipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);
int Sm4GcmCipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl);

/* SM4 init/cleanup wrappers (moved from sm_engine.c) */
int SmSm4CbcInit(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
int SmSm4EcbInit(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc);
int SmSm4CbcCleanup(EVP_CIPHER_CTX *ctx);
int SmSm4EcbCleanup(EVP_CIPHER_CTX *ctx);

/* SM4 impl ctx size helpers */
int SmSm4CbcImplCtxSize(void);
int SmSm4EcbImplCtxSize(void);

/* SM4 ASN.1 and ctrl wrappers */
int SmSm4CbcSetAsn1Params(EVP_CIPHER_CTX *ctx, ASN1_TYPE *asn1Type);
int SmSm4CbcGetAsn1Params(EVP_CIPHER_CTX *ctx, ASN1_TYPE *asn1Type);
int SmSm4EcbSetAsn1Params(EVP_CIPHER_CTX *ctx, ASN1_TYPE *asn1Type);
int SmSm4EcbGetAsn1Params(EVP_CIPHER_CTX *ctx, ASN1_TYPE *asn1Type);
int SmSm4CbcCtrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
int SmSm4EcbCtrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
/* SM4 property helpers (read from external method) */
int SmSm4BlockSizeCbc(void);
int SmSm4BlockSizeEcb(void);
int SmSm4KeyLength(void);
int SmSm4IvLengthCbc(void);
int SmSm4IvLengthEcb(void);
unsigned long SmSm4FlagsCbc(void);
unsigned long SmSm4FlagsEcb(void);

/* Get external SM4 methods */
const EVP_CIPHER *GetExternalSm4CbcMethod(void);
const EVP_CIPHER *GetExternalSm4EcbMethod(void);

#ifdef __cplusplus
}
#endif

#endif /* SM4_H */