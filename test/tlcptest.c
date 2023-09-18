/*
 * Copyright 2022 Huawei Technologies Co., Ltd. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "internal/nelem.h"
#include "ssltestlib.h"
#include "testutil.h"

#ifndef OPENSSL_NO_TLCP

typedef enum {
    IDX_SM2_ROOT_CERT = 0,
    IDX_SM2_SERVER_SIG_CERT,
    IDX_SM2_SERVER_SIG_KEY,
    IDX_SM2_SERVER_ENC_CERT,
    IDX_SM2_SERVER_ENC_KEY,
    IDX_SM2_CLIENT_SIG_CERT,
    IDX_SM2_CLIENT_SIG_KEY,
    IDX_SM2_CLIENT_ENC_CERT,
    IDX_SM2_CLIENT_ENC_KEY,
    IDX_ECDSA_ROOT_CERT,
    IDX_ECDSA_SERVER_CERT,
    IDX_ECDSA_SERVER_KEY,
    IDX_ECDSA_CLIENT_CERT,
    IDX_ECDSA_CLIENT_KEY,
    IDX_MAX
} TEST_FILES_IDX;

#define OPTION_IS_CA              0x00000001U
#define OPTION_IS_CERT            0x00000002U
#define OPTION_IS_KEY             0x00000004U
#define OPTION_USE_NEWAPI         0x00000008U
#define OPTION_USE_EXTRA          0x00000010U
#define OPTION_IS_SIG             0x00000020U
#define OPTION_IS_ENC             0x00000040U

typedef struct {
    TEST_FILES_IDX idx;
    int flag;
} LOAD_OPTION;

typedef struct {
    const char *method_name;
    const char *sid_ctx;
    int verify_mode;
    int ssl_options;
    int set_version;
    LOAD_OPTION load_options[IDX_MAX];
} SSL_CTX_OPTION;
typedef struct {
    const char *case_name;
    SSL_CTX_OPTION server;
    SSL_CTX_OPTION client;
    const char *ciphersuite;
    const char *expected_version;
    const char *expected_cipher;
    int regenotiate;
    int reuse_session;
} TLCP_TEST_CASE;

static const TLCP_TEST_CASE tlcp_test_cases[] = {
    {   "test_ecc_and_cert_position",
        {
            "TLS_server", NULL, SSL_VERIFY_PEER, SSL_OP_ENCCERT_SECOND_POSITION, 0,
            {
                {IDX_SM2_ROOT_CERT, OPTION_IS_CA},
                {IDX_SM2_SERVER_SIG_CERT, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_CERT },
                {IDX_SM2_SERVER_SIG_KEY, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_KEY },
                {IDX_SM2_SERVER_ENC_CERT, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_CERT },
                {IDX_SM2_SERVER_ENC_KEY, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_KEY }
            }
        },
        {
            "TLCP_client", NULL, SSL_VERIFY_PEER, SSL_OP_ENCCERT_SECOND_POSITION, 0,
            {
                {IDX_SM2_ROOT_CERT, OPTION_IS_CA},
                {IDX_SM2_CLIENT_SIG_CERT, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_CERT },
                {IDX_SM2_CLIENT_SIG_KEY, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_KEY },
                {IDX_SM2_CLIENT_ENC_CERT, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_CERT },
                {IDX_SM2_CLIENT_ENC_KEY, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_KEY }
            }
        },
        "ECC-SM4-CBC-SM3",
        "TLCP",
        "ECC-SM4-CBC-SM3",
        0, 0
    },
    {   "test_extra_cert",
        {
            "TLS_server", NULL, SSL_VERIFY_NONE, 0, 0,
            {
                {IDX_SM2_ROOT_CERT, OPTION_IS_CA | OPTION_USE_EXTRA},
                {IDX_SM2_SERVER_SIG_CERT, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_CERT },
                {IDX_SM2_SERVER_SIG_KEY, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_KEY },
                {IDX_SM2_SERVER_ENC_CERT, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_CERT },
                {IDX_SM2_SERVER_ENC_KEY, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_KEY }
            }
        },
        {
            "TLCP_client", NULL, SSL_VERIFY_NONE, 0, 0,
            {
                {IDX_SM2_ROOT_CERT, OPTION_IS_CA | OPTION_USE_EXTRA},
                {IDX_SM2_CLIENT_SIG_CERT, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_CERT },
                {IDX_SM2_CLIENT_SIG_KEY, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_KEY },
                {IDX_SM2_CLIENT_ENC_CERT, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_CERT },
                {IDX_SM2_CLIENT_ENC_KEY, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_KEY }
            }
        },
        "ECC-SM4-CBC-SM3",
        "TLCP",
        "ECC-SM4-CBC-SM3",
        0, 0
    },
    {   "test_ssl_op_no",
        {
            "TLS_server", NULL, SSL_VERIFY_PEER, SSL_OP_NO_TLSv1_3 | SSL_OP_NO_TLSv1_2 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1 | SSL_OP_NO_SSLv3, 0,
            {
                {IDX_SM2_ROOT_CERT, OPTION_IS_CA},
                {IDX_SM2_SERVER_SIG_CERT, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_CERT },
                {IDX_SM2_SERVER_SIG_KEY, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_KEY },
                {IDX_SM2_SERVER_ENC_CERT, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_CERT },
                {IDX_SM2_SERVER_ENC_KEY, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_KEY }
            }
        },
        {
            "TLS_client", NULL, SSL_VERIFY_PEER, SSL_OP_NO_TLSv1_3 | SSL_OP_NO_TLSv1_2 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1 | SSL_OP_NO_SSLv3, 0,
            {
                {IDX_SM2_ROOT_CERT, OPTION_IS_CA},
                {IDX_SM2_CLIENT_SIG_CERT, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_CERT },
                {IDX_SM2_CLIENT_SIG_KEY, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_KEY },
                {IDX_SM2_CLIENT_ENC_CERT, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_CERT },
                {IDX_SM2_CLIENT_ENC_KEY, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_KEY }
            }
        },
        "ECC-SM4-CBC-SM3",
        "TLCP",
        "ECC-SM4-CBC-SM3",
        0, 0
    },
    {   "test_set_version_bound",
        {
            "TLCP_server", NULL, SSL_VERIFY_PEER, 0, TLCP_VERSION,
            {
                {IDX_SM2_ROOT_CERT, OPTION_IS_CA},
                {IDX_SM2_SERVER_SIG_CERT, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_CERT },
                {IDX_SM2_SERVER_SIG_KEY, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_KEY },
                {IDX_SM2_SERVER_ENC_CERT, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_CERT },
                {IDX_SM2_SERVER_ENC_KEY, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_KEY }
            }
        },
        {
            "TLS_client", NULL, SSL_VERIFY_PEER, 0, TLCP_VERSION,
            {
                {IDX_SM2_ROOT_CERT, OPTION_IS_CA},
                {IDX_SM2_CLIENT_SIG_CERT, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_CERT },
                {IDX_SM2_CLIENT_SIG_KEY, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_KEY },
                {IDX_SM2_CLIENT_ENC_CERT, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_CERT },
                {IDX_SM2_CLIENT_ENC_KEY, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_KEY }
            }
        },
        NULL,
        "TLCP",
        "ECC-SM4-CBC-SM3",
        0, 0
    },
    {   "test_use_old_api_and_other_certs",
        {
            "TLS_server", NULL, SSL_VERIFY_PEER, 0, 0,
            {
                {IDX_SM2_ROOT_CERT, OPTION_IS_CA},
                {IDX_SM2_SERVER_SIG_CERT, OPTION_IS_SIG | OPTION_IS_CERT },
                {IDX_SM2_SERVER_SIG_KEY, OPTION_IS_SIG | OPTION_IS_KEY },
                {IDX_SM2_SERVER_ENC_CERT, OPTION_IS_ENC | OPTION_IS_CERT },
                {IDX_SM2_SERVER_ENC_KEY, OPTION_IS_ENC | OPTION_IS_KEY },
                {IDX_ECDSA_ROOT_CERT, OPTION_IS_CA},
                {IDX_ECDSA_SERVER_CERT, OPTION_IS_CERT},
                {IDX_ECDSA_SERVER_KEY, OPTION_IS_KEY}
            }
        },
        {
            "TLCP_client", NULL, SSL_VERIFY_PEER, 0, 0,
            {
                {IDX_SM2_ROOT_CERT, OPTION_IS_CA},
                {IDX_SM2_CLIENT_SIG_CERT, OPTION_IS_SIG | OPTION_IS_CERT },
                {IDX_SM2_CLIENT_SIG_KEY, OPTION_IS_SIG | OPTION_IS_KEY },
                {IDX_SM2_CLIENT_ENC_CERT, OPTION_IS_ENC | OPTION_IS_CERT },
                {IDX_SM2_CLIENT_ENC_KEY, OPTION_IS_ENC | OPTION_IS_KEY },
                {IDX_ECDSA_ROOT_CERT, OPTION_IS_CA},
                {IDX_ECDSA_CLIENT_CERT, OPTION_IS_CERT},
                {IDX_ECDSA_CLIENT_KEY, OPTION_IS_KEY}
            }
        },
        NULL,
        "TLCP",
        "ECC-SM4-CBC-SM3",
        0, 0
    },
    {   "test_sm2dhe_and_cert_position",
        {
            "TLS_server", NULL, SSL_VERIFY_PEER, SSL_OP_ENCCERT_SECOND_POSITION, 0,
            {
                {IDX_SM2_ROOT_CERT, OPTION_IS_CA},
                {IDX_SM2_SERVER_SIG_CERT, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_CERT },
                {IDX_SM2_SERVER_SIG_KEY, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_KEY },
                {IDX_SM2_SERVER_ENC_CERT, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_CERT },
                {IDX_SM2_SERVER_ENC_KEY, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_KEY }
            }
        },
        {
            "TLCP_client", NULL, SSL_VERIFY_PEER, SSL_OP_ENCCERT_SECOND_POSITION, 0,
            {
                {IDX_SM2_ROOT_CERT, OPTION_IS_CA},
                {IDX_SM2_CLIENT_SIG_CERT, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_CERT },
                {IDX_SM2_CLIENT_SIG_KEY, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_KEY },
                {IDX_SM2_CLIENT_ENC_CERT, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_CERT },
                {IDX_SM2_CLIENT_ENC_KEY, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_KEY }
            }
        },
        "ECDHE-SM4-CBC-SM3",
        "TLCP",
        "ECDHE-SM4-CBC-SM3",
        0, 0
    },
    {   "test_ecc_regenotiate",
        {
            "TLS_server", NULL, SSL_VERIFY_PEER, SSL_OP_ENCCERT_SECOND_POSITION, 0,
            {
                {IDX_SM2_ROOT_CERT, OPTION_IS_CA},
                {IDX_SM2_SERVER_SIG_CERT, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_CERT },
                {IDX_SM2_SERVER_SIG_KEY, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_KEY },
                {IDX_SM2_SERVER_ENC_CERT, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_CERT },
                {IDX_SM2_SERVER_ENC_KEY, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_KEY }
            }
        },
        {
            "TLCP_client", NULL, SSL_VERIFY_PEER, SSL_OP_ENCCERT_SECOND_POSITION, 0,
            {
                {IDX_SM2_ROOT_CERT, OPTION_IS_CA},
                {IDX_SM2_CLIENT_SIG_CERT, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_CERT },
                {IDX_SM2_CLIENT_SIG_KEY, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_KEY },
                {IDX_SM2_CLIENT_ENC_CERT, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_CERT },
                {IDX_SM2_CLIENT_ENC_KEY, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_KEY }
            }
        },
        "ECC-SM4-CBC-SM3",
        "TLCP",
        "ECC-SM4-CBC-SM3",
        1, 0
    },
    {   "test_sm2dhe_regenotiate",
        {
            "TLS_server", NULL, SSL_VERIFY_PEER, SSL_OP_ENCCERT_SECOND_POSITION, 0,
            {
                {IDX_SM2_ROOT_CERT, OPTION_IS_CA},
                {IDX_SM2_SERVER_SIG_CERT, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_CERT },
                {IDX_SM2_SERVER_SIG_KEY, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_KEY },
                {IDX_SM2_SERVER_ENC_CERT, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_CERT },
                {IDX_SM2_SERVER_ENC_KEY, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_KEY }
            }
        },
        {
            "TLCP_client", NULL, SSL_VERIFY_PEER, SSL_OP_ENCCERT_SECOND_POSITION, 0,
            {
                {IDX_SM2_ROOT_CERT, OPTION_IS_CA},
                {IDX_SM2_CLIENT_SIG_CERT, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_CERT },
                {IDX_SM2_CLIENT_SIG_KEY, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_KEY },
                {IDX_SM2_CLIENT_ENC_CERT, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_CERT },
                {IDX_SM2_CLIENT_ENC_KEY, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_KEY }
            }
        },
        "ECDHE-SM4-CBC-SM3",
        "TLCP",
        "ECDHE-SM4-CBC-SM3",
        1, 0
    },
    {   "test_ecc_reused_sessionid",
        {
            "TLS_server", "TEST", SSL_VERIFY_PEER, SSL_OP_NO_TICKET | SSL_OP_ENCCERT_SECOND_POSITION, 0,
            {
                {IDX_SM2_ROOT_CERT, OPTION_IS_CA},
                {IDX_SM2_SERVER_SIG_CERT, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_CERT },
                {IDX_SM2_SERVER_SIG_KEY, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_KEY },
                {IDX_SM2_SERVER_ENC_CERT, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_CERT },
                {IDX_SM2_SERVER_ENC_KEY, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_KEY }
            }
        },
        {
            "TLCP_client", NULL, SSL_VERIFY_PEER, SSL_OP_NO_TICKET | SSL_OP_ENCCERT_SECOND_POSITION, 0,
            {
                {IDX_SM2_ROOT_CERT, OPTION_IS_CA},
                {IDX_SM2_CLIENT_SIG_CERT, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_CERT },
                {IDX_SM2_CLIENT_SIG_KEY, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_KEY },
                {IDX_SM2_CLIENT_ENC_CERT, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_CERT },
                {IDX_SM2_CLIENT_ENC_KEY, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_KEY }
            }
        },
        "ECC-SM4-CBC-SM3",
        "TLCP",
        "ECC-SM4-CBC-SM3",
        0, 1
    },
    {   "test_sm2dhe_reused_sessionid",
        {
            "TLS_server", "TEST", SSL_VERIFY_PEER, SSL_OP_NO_TICKET | SSL_OP_ENCCERT_SECOND_POSITION, 0,
            {
                {IDX_SM2_ROOT_CERT, OPTION_IS_CA},
                {IDX_SM2_SERVER_SIG_CERT, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_CERT },
                {IDX_SM2_SERVER_SIG_KEY, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_KEY },
                {IDX_SM2_SERVER_ENC_CERT, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_CERT },
                {IDX_SM2_SERVER_ENC_KEY, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_KEY }
            }
        },
        {
            "TLCP_client", NULL, SSL_VERIFY_PEER, SSL_OP_NO_TICKET | SSL_OP_ENCCERT_SECOND_POSITION, 0,
            {
                {IDX_SM2_ROOT_CERT, OPTION_IS_CA},
                {IDX_SM2_CLIENT_SIG_CERT, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_CERT },
                {IDX_SM2_CLIENT_SIG_KEY, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_KEY },
                {IDX_SM2_CLIENT_ENC_CERT, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_CERT },
                {IDX_SM2_CLIENT_ENC_KEY, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_KEY }
            }
        },
        "ECDHE-SM4-CBC-SM3",
        "TLCP",
        "ECDHE-SM4-CBC-SM3",
        0, 1
    },
    {   "test_ecc_reused_ticket",
        {
            "TLS_server", NULL, SSL_VERIFY_NONE, SSL_OP_ENCCERT_SECOND_POSITION, 0,
            {
                {IDX_SM2_ROOT_CERT, OPTION_IS_CA},
                {IDX_SM2_SERVER_SIG_CERT, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_CERT },
                {IDX_SM2_SERVER_SIG_KEY, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_KEY },
                {IDX_SM2_SERVER_ENC_CERT, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_CERT },
                {IDX_SM2_SERVER_ENC_KEY, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_KEY }
            }
        },
        {
            "TLCP_client", NULL, SSL_VERIFY_NONE, SSL_OP_ENCCERT_SECOND_POSITION, 0,
            {
                {IDX_SM2_ROOT_CERT, OPTION_IS_CA},
                {IDX_SM2_CLIENT_SIG_CERT, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_CERT },
                {IDX_SM2_CLIENT_SIG_KEY, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_KEY },
                {IDX_SM2_CLIENT_ENC_CERT, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_CERT },
                {IDX_SM2_CLIENT_ENC_KEY, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_KEY }
            }
        },
        "ECC-SM4-CBC-SM3",
        "TLCP",
        "ECC-SM4-CBC-SM3",
        0, 1
    },
    {   "test_sm2dhe_reused_ticket",
        {
            "TLS_server", NULL, SSL_VERIFY_NONE, SSL_OP_ENCCERT_SECOND_POSITION, 0,
            {
                {IDX_SM2_ROOT_CERT, OPTION_IS_CA},
                {IDX_SM2_SERVER_SIG_CERT, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_CERT },
                {IDX_SM2_SERVER_SIG_KEY, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_KEY },
                {IDX_SM2_SERVER_ENC_CERT, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_CERT },
                {IDX_SM2_SERVER_ENC_KEY, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_KEY }
            }
        },
        {
            "TLCP_client", NULL, SSL_VERIFY_NONE, SSL_OP_ENCCERT_SECOND_POSITION, 0,
            {
                {IDX_SM2_ROOT_CERT, OPTION_IS_CA},
                {IDX_SM2_CLIENT_SIG_CERT, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_CERT },
                {IDX_SM2_CLIENT_SIG_KEY, OPTION_USE_NEWAPI | OPTION_IS_SIG | OPTION_IS_KEY },
                {IDX_SM2_CLIENT_ENC_CERT, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_CERT },
                {IDX_SM2_CLIENT_ENC_KEY, OPTION_USE_NEWAPI | OPTION_IS_ENC | OPTION_IS_KEY }
            }
        },
        "ECDHE-SM4-CBC-SM3",
        "TLCP",
        "ECDHE-SM4-CBC-SM3",
        0, 1
    },
};

static const char *test_files[IDX_MAX];

static X509 *PEM_file_to_X509(const char *file)
{
    BIO *in;
    X509 *x = NULL;

    in = BIO_new(BIO_s_file());
    if (in == NULL || BIO_read_filename(in, file) <= 0)
        goto err;

    x = PEM_read_bio_X509(in, NULL, NULL, NULL);
err:
    BIO_free(in);
    return x;
}

static EVP_PKEY *PEM_file_to_PrivateKey(const char *file)
{
    BIO *in;
    EVP_PKEY *pkey = NULL;

    in = BIO_new(BIO_s_file());
    if (in == NULL || BIO_read_filename(in, file) <= 0)
        goto err;

    pkey = PEM_read_bio_PrivateKey(in, NULL, NULL, NULL);
err:
    BIO_free(in);
    return pkey;
}

static int use_extra_cert_file(SSL_CTX *ctx, const char *file)
{
    X509 *x;

    x = PEM_file_to_X509(file);

    if (x == NULL)
        return 0;

    if (!SSL_CTX_add_extra_chain_cert(ctx, x)) {
        X509_free(x);
        return 0;
    }
    return 1;
}

static int load_test_file_by_option(SSL_CTX *ctx, LOAD_OPTION opt)
{
    int usage = -1;
    if (opt.idx >= IDX_MAX)
        return 0;

    if (opt.flag & OPTION_IS_CA) {
        return (opt.flag & OPTION_USE_EXTRA) 
                    ? use_extra_cert_file(ctx, test_files[opt.idx])
                    : SSL_CTX_load_verify_locations(ctx, test_files[opt.idx], NULL);
    }

    if (opt.flag & OPTION_IS_SIG) {
        usage = SSL_USAGE_SIG;
    } else if (opt.flag & OPTION_IS_ENC) {
        usage = SSL_USAGE_ENC;
    }

    if (opt.flag & OPTION_IS_CERT) {
        return (opt.flag & OPTION_USE_NEWAPI) 
                    ? SSL_CTX_use_gm_certificate_file(ctx, test_files[opt.idx], SSL_FILETYPE_PEM, usage)
                    : SSL_CTX_use_certificate_file(ctx, test_files[opt.idx], SSL_FILETYPE_PEM);
    } else if (opt.flag & OPTION_IS_KEY){
        return (opt.flag & OPTION_USE_NEWAPI) 
                    ? SSL_CTX_use_gm_PrivateKey_file(ctx, test_files[opt.idx], SSL_FILETYPE_PEM, usage)
                    : SSL_CTX_use_PrivateKey_file(ctx, test_files[opt.idx], SSL_FILETYPE_PEM);
    }
    return 1;
}

static int load_test_files(SSL_CTX *ctx, LOAD_OPTION *opt, size_t optlen)
{
    size_t i;
    for (i = 0; i < optlen; ++i) {
        if (!load_test_file_by_option(ctx, opt[i])) {
            return 0;
        }
    }
    return 1;
}

static SSL_CTX *SSL_CTX_create_by_option(const SSL_CTX_OPTION *opt)
{
    SSL_CTX *ctx = NULL;
    if (opt == NULL)
        return NULL;

    if (strcmp(opt->method_name, "TLS_server") == 0) {
        ctx = SSL_CTX_new(TLS_server_method());
    } else if (strcmp(opt->method_name, "TLS_client") == 0) {
        ctx = SSL_CTX_new(TLS_client_method());
    } else if (strcmp(opt->method_name, "TLCP_server") == 0) {
        ctx = SSL_CTX_new(TLCP_server_method());
    } else if (strcmp(opt->method_name, "TLCP_client") == 0) {
        ctx = SSL_CTX_new(TLCP_client_method());
    }
    if (ctx == NULL)
        return NULL;

    SSL_CTX_set_verify(ctx, opt->verify_mode, NULL);
    SSL_CTX_set_options(ctx, opt->ssl_options);
    SSL_CTX_set_min_proto_version(ctx, opt->set_version);
    SSL_CTX_set_max_proto_version(ctx, opt->set_version);

    if (opt->sid_ctx
            && SSL_CTX_set_session_id_context(ctx, (unsigned char*)opt->sid_ctx, strlen(opt->sid_ctx)) != 1) {
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (!load_test_files(ctx, (LOAD_OPTION *)opt->load_options, OSSL_NELEM(opt->load_options))) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

static int test_tlcp_regenotiate(SSL *server_ssl, SSL *client_ssl)
{
    SSL_SESSION *sess_pre;
    SSL_SESSION *sess_post;

    if (!TEST_ptr(sess_pre = SSL_get0_session(server_ssl)))
        return 0;

    if (!TEST_int_eq(SSL_renegotiate(client_ssl), 1)
            || !TEST_int_eq(SSL_renegotiate_pending(client_ssl), 1))
        return 0;

    for (int i = 0; i < 3; i++) {
        unsigned char buf;
        size_t readbytes;
        int ret = SSL_read_ex(client_ssl, &buf, sizeof(buf), &readbytes);
        if ((ret > 0 && !TEST_ulong_eq(readbytes, 0))
                || (ret <= 0 && !TEST_int_eq(SSL_get_error(client_ssl, 0), SSL_ERROR_WANT_READ))) {
            return 0;
        }

        ret = SSL_read_ex(server_ssl, &buf, sizeof(buf), &readbytes);
        if ((ret > 0 && !TEST_ulong_eq(readbytes, 0))
                || (ret <= 0 && SSL_get_error(server_ssl, 0) != SSL_ERROR_WANT_READ)) {
            if (!strcmp("ECDHE-SM4-CBC-SM3", SSL_CIPHER_get_name(SSL_get_current_cipher(client_ssl))))
                return 1;
            return 0;
        }
    }

    if (!TEST_false(SSL_renegotiate_pending(client_ssl))
            || !TEST_int_eq(SSL_session_reused(client_ssl), 0)
            || !TEST_int_eq(SSL_session_reused(server_ssl), 0)
            || !TEST_ptr(sess_post = SSL_get0_session(server_ssl))
            || !TEST_ptr_ne(sess_pre, sess_post))
        return 0;

    return 1;
}

static int test_tlcp_reuse_session(SSL **p_server_ssl, SSL **p_client_ssl)
{
    int ret = 0;
    SSL *server_ssl = *p_server_ssl;
    SSL *client_ssl = *p_client_ssl;
    SSL_CTX *server_ctx;
    SSL_CTX *client_ctx;
    SSL_SESSION *sess_pre;
    SSL_SESSION *sess_post;
    SSL_SESSION *sess;
    const unsigned char *sess_pre_id;
    unsigned int sess_pre_id_len;
    const unsigned char *sess_post_id;
    unsigned int sess_post_id_len;
    const char *ciph_name = SSL_CIPHER_get_name(SSL_get_current_cipher(client_ssl));

    if (!TEST_ptr(server_ctx = SSL_get_SSL_CTX(server_ssl))
            || !TEST_ptr(client_ctx = SSL_get_SSL_CTX(client_ssl)))
        return 0;

    if (!TEST_ptr(sess_pre = SSL_get0_session(server_ssl)))
        return 0;
    
    if (!TEST_ptr(sess = SSL_get1_session(client_ssl)))
        return 0;

    shutdown_ssl_connection(server_ssl, client_ssl);
    *p_server_ssl = NULL;
    *p_client_ssl = NULL;
    
    if (!TEST_int_eq(create_ssl_objects(server_ctx, client_ctx, p_server_ssl, p_client_ssl, NULL, NULL), 1))
        goto out;

    server_ssl = *p_server_ssl;
    client_ssl = *p_client_ssl;

    if (!TEST_int_eq(SSL_set_session(client_ssl, sess), 1))
        goto out;

    if (!TEST_int_eq(create_ssl_connection(server_ssl, client_ssl, SSL_ERROR_NONE), 1))
        goto out;

    if (!TEST_int_eq(SSL_session_reused(client_ssl), 1)
            || !TEST_int_eq(SSL_session_reused(server_ssl), 1))
        goto out;

    if (!TEST_ptr(sess_post = SSL_get0_session(server_ssl))
            || !TEST_str_eq(ciph_name, SSL_CIPHER_get_name(SSL_get_current_cipher(client_ssl))))
        goto out;
    
    if ((SSL_get_options(client_ssl) & SSL_OP_NO_TICKET) && (SSL_get_options(server_ssl) & SSL_OP_NO_TICKET)
            && !TEST_ptr_eq(sess_pre, sess_post))
        goto out;

    sess_post_id = SSL_SESSION_get_id(sess_post, &sess_post_id_len);
    sess_pre_id = SSL_SESSION_get_id(sess, &sess_pre_id_len);

    if (!TEST_mem_eq(sess_pre_id, sess_pre_id_len, sess_post_id, sess_post_id_len))
        goto out;

    ret = 1;

out:
    SSL_SESSION_free(sess);

    return ret;
}

static int test_tlcp_ciphersuites(int idx)
{
    int result = 0;
    SSL_CTX *server_ctx = NULL;
    SSL_CTX *client_ctx = NULL;
    SSL *server_ssl = NULL;
    SSL *client_ssl = NULL;
    const TLCP_TEST_CASE *case_ptr;

    case_ptr = &tlcp_test_cases[idx];
    if (!TEST_ptr(server_ctx = SSL_CTX_create_by_option(&case_ptr->server))
            || !TEST_ptr(client_ctx = SSL_CTX_create_by_option(&case_ptr->client)))
        goto err;

    if (case_ptr->ciphersuite != NULL &&
            !TEST_int_eq(SSL_CTX_set_cipher_list(client_ctx, case_ptr->ciphersuite), 1))
        goto err;

    if (!TEST_int_eq(create_ssl_objects(server_ctx, client_ctx
            , &server_ssl, &client_ssl, NULL, NULL), 1))
        goto err;

    if (!TEST_int_eq(create_ssl_connection(server_ssl, client_ssl, SSL_ERROR_NONE), 1))
        goto err;

    if (case_ptr->expected_version != NULL &&
            !TEST_str_eq(SSL_get_version(client_ssl), case_ptr->expected_version))
        goto err;

    if (case_ptr->expected_cipher &&
            !TEST_str_eq(SSL_get_cipher(client_ssl), case_ptr->expected_cipher))
        goto err;

    if (case_ptr->regenotiate
            && !TEST_int_eq(test_tlcp_regenotiate(server_ssl, client_ssl), 1))
        goto err;

    if (case_ptr->reuse_session
            && !TEST_int_eq(test_tlcp_reuse_session(&server_ssl, &client_ssl), 1))
        goto err;

    result = 1;
err:
    if (server_ssl != NULL)
        SSL_shutdown(server_ssl);
    if (client_ssl != NULL)
        SSL_shutdown(client_ssl);
    SSL_free(server_ssl);
    SSL_free(client_ssl);
    SSL_CTX_free(server_ctx);
    SSL_CTX_free(client_ctx);
    return result;
}

static int test_use_certs_and_keys(void)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    X509 *x = NULL;
    EVP_PKEY *pkey = NULL;
    int result = 0;

    ctx = SSL_CTX_new(TLCP_method());
    if (ctx == NULL)
        goto err;
    
    ssl = SSL_new(ctx);
    if (ssl == NULL)
        goto err;

    if (!TEST_int_ne(SSL_use_gm_certificate_file(ssl, test_files[IDX_ECDSA_SERVER_CERT], 
            SSL_FILETYPE_PEM, SSL_USAGE_SIG), 1)
        || !TEST_int_ne(SSL_use_gm_PrivateKey_file(ssl, test_files[IDX_ECDSA_CLIENT_KEY], 
            SSL_FILETYPE_PEM, SSL_USAGE_SIG), 1)) {
        goto err;
    }

    if (!TEST_int_eq(SSL_use_certificate_file(ssl, test_files[IDX_SM2_SERVER_SIG_CERT], 
            SSL_FILETYPE_PEM), 1)
        || !TEST_int_eq(SSL_use_gm_PrivateKey_file(ssl, test_files[IDX_SM2_SERVER_SIG_KEY], 
            SSL_FILETYPE_PEM, SSL_USAGE_SIG), 1)
        || !TEST_int_eq(SSL_use_gm_certificate_file(ssl, test_files[IDX_SM2_SERVER_ENC_CERT], 
            SSL_FILETYPE_PEM, SSL_USAGE_ENC), 1)
        || !TEST_int_eq(SSL_use_PrivateKey_file(ssl, test_files[IDX_SM2_SERVER_ENC_KEY], 
            SSL_FILETYPE_PEM), 1)){
        goto err;
    }

    if (!TEST_ptr(x = PEM_file_to_X509(test_files[IDX_SM2_CLIENT_SIG_CERT]))
        || !TEST_ptr(pkey = PEM_file_to_PrivateKey(test_files[IDX_SM2_CLIENT_SIG_KEY]))
        || !TEST_int_eq(SSL_use_gm_cert_and_key(ssl, x, pkey, NULL, 1, SSL_USAGE_SIG), 1)) {
        goto err;
    }
    result = 1;
err:
    X509_free(x);

    EVP_PKEY_free(pkey);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return result;
}

#endif

int setup_tests(void)
{
#ifndef OPENSSL_NO_TLCP
    int argc;

    for (argc = 0; argc < IDX_MAX; ++argc) {
        if (!TEST_ptr(test_files[argc] = test_get_argument(argc))) {
            return 0;
        }
    }

    ADD_ALL_TESTS(test_tlcp_ciphersuites, OSSL_NELEM(tlcp_test_cases));
    ADD_TEST(test_use_certs_and_keys);
#endif 
    return 1;
}
