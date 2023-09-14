/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_SM4_PLATFORM_H
# define OSSL_SM4_PLATFORM_H
# pragma once

# if defined(OPENSSL_CPUID_OBJ)
#  if (defined(__arm__) || defined(__arm) || defined(__aarch64__))
#   include "arm_arch.h"
#   if __ARM_MAX_ARCH__>=7
#    if defined(VPSM4_EX_ASM)
#     define VPSM4_EX_CAPABLE (OPENSSL_armcap_P & ARMV8_AES)
#    endif
#     define HWSM4_CAPABLE (OPENSSL_armcap_P & ARMV8_SM4)
#     define HWSM4_set_encrypt_key sm4_v8_set_encrypt_key
#     define HWSM4_set_decrypt_key sm4_v8_set_decrypt_key
#     define HWSM4_encrypt sm4_v8_encrypt
#     define HWSM4_decrypt sm4_v8_decrypt
#     define HWSM4_cbc_encrypt sm4_v8_cbc_encrypt
#     define HWSM4_ecb_encrypt sm4_v8_ecb_encrypt
#     define HWSM4_ctr32_encrypt_blocks sm4_v8_ctr32_encrypt_blocks
#   endif
#  endif
# endif /* OPENSSL_CPUID_OBJ */

# if defined(HWSM4_CAPABLE)
int HWSM4_set_encrypt_key(const unsigned char *userKey, SM4_KEY *key);
int HWSM4_set_decrypt_key(const unsigned char *userKey, SM4_KEY *key);
void HWSM4_encrypt(const unsigned char *in, unsigned char *out,
                   const SM4_KEY *key);
void HWSM4_decrypt(const unsigned char *in, unsigned char *out,
                   const SM4_KEY *key);
void HWSM4_cbc_encrypt(const unsigned char *in, unsigned char *out,
                       size_t length, const SM4_KEY *key,
                       unsigned char *ivec, const int enc);
void HWSM4_ecb_encrypt(const unsigned char *in, unsigned char *out,
                       size_t length, const SM4_KEY *key,
                       const int enc);
void HWSM4_ctr32_encrypt_blocks(const unsigned char *in, unsigned char *out,
                                size_t len, const void *key,
                                const unsigned char ivec[16]);
# endif /* HWSM4_CAPABLE */

#ifdef VPSM4_EX_CAPABLE
void vpsm4_ex_set_encrypt_key(const unsigned char *userKey, SM4_KEY *key);
void vpsm4_ex_set_decrypt_key(const unsigned char *userKey, SM4_KEY *key);
#define vpsm4_ex_encrypt SM4_encrypt
#define vpsm4_ex_decrypt SM4_encrypt
void vpsm4_ex_ecb_encrypt(
    const unsigned char *in, unsigned char *out, size_t length, const SM4_KEY *key, const int enc);
/* xts mode in GB/T 17964-2021 */
void vpsm4_ex_xts_encrypt_gb(const unsigned char *in, unsigned char *out, size_t length, const SM4_KEY *key1,
    const SM4_KEY *key2, const uint8_t iv[16]);
void vpsm4_ex_xts_decrypt_gb(const unsigned char *in, unsigned char *out, size_t length, const SM4_KEY *key1,
    const SM4_KEY *key2, const uint8_t iv[16]);
/* xts mode in IEEE Std 1619-2007 */
void vpsm4_ex_xts_encrypt(const unsigned char *in, unsigned char *out, size_t length, const SM4_KEY *key1,
    const SM4_KEY *key2, const uint8_t iv[16]);
void vpsm4_ex_xts_decrypt(const unsigned char *in, unsigned char *out, size_t length, const SM4_KEY *key1,
    const SM4_KEY *key2, const uint8_t iv[16]);
#endif /* VPSM4_EX_CAPABLE */

#endif /* OSSL_SM4_PLATFORM_H */
