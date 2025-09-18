#include "sm3.h"
#include "sm4.h"
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>

/* Engine control commands */
#define ENGINE_CTRL_SET_LOG_LEVEL 1000

/* Define NIDs for SM algorithms */

static const char *engineSmId = "sm_ce_engine";
static const char *engineSmName = "SM3/SM4 Engine (Static Library)";

/* Dynamic method objects (opaque in OpenSSL 1.1.1) */
static EVP_MD *gSm3Md = NULL;
static EVP_CIPHER *gSm4Cbc = NULL;
static EVP_CIPHER *gSm4Ecb = NULL;

/* SM3 digest function */
static int SmDigests(ENGINE *e, const EVP_MD **digest, const int **nids,
                     int nid) {
    (void)e;
    static int sm3Nids[] = {NID_sm3, 0};
    if (digest == NULL) {
        *nids = sm3Nids;
        return 1;
    }
    switch (nid) {
        case NID_sm3:
            if (digest) {
                *digest = gSm3Md;
                if (*digest == NULL) {
                    return 0;
                }
                return 1;
            }
            return 0;
        default:
            return 0;
    }
}

/* SM4 cipher function */
static int SmCiphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids,
                     int nid) {
    (void)e;
    static int sm4Nids[] = {NID_sm4_cbc, NID_sm4_ecb, 0};
    if (cipher == NULL) {
        *nids = sm4Nids;
        return 2;
    }
    switch (nid) {
        case NID_sm4_cbc:
            if (cipher) {
                *cipher = gSm4Cbc;
                if (*cipher == NULL) {
                    return 0;
                }
                return 1;
            }
            return 0;
        case NID_sm4_ecb:
            if (cipher) {
                *cipher = gSm4Ecb;
                if (*cipher == NULL) {
                    return 0;
                }
                return 1;
            }
            return 0;
        default:
            return 0;
    }
}

/* Initialize SM3 digest method */
static int InitSm3Digest(void) {
    gSm3Md = EVP_MD_meth_new(NID_sm3, SmSm3PkeyType());
    if (!gSm3Md) {
        return 0;
    }
    if (!EVP_MD_meth_set_result_size(gSm3Md, SmSm3ResultSize())) {
        return 0;
    }
    if (!EVP_MD_meth_set_app_datasize(gSm3Md, SmSm3AppDatasize())) {
        return 0;
    }
    if (!EVP_MD_meth_set_init(gSm3Md, SmSm3Init)) {
        return 0;
    }
    if (!EVP_MD_meth_set_update(gSm3Md, SmSm3Update)) {
        return 0;
    }
    if (!EVP_MD_meth_set_final(gSm3Md, SmSm3Final)) {
        return 0;
    }
    if (!EVP_MD_meth_set_copy(gSm3Md, SmSm3Copy)) {
        return 0;
    }
    if (!EVP_MD_meth_set_cleanup(gSm3Md, SmSm3Cleanup)) {
        return 0;
    }
    return 1;
}

/* Initialize SM4 CBC cipher method */
static int InitSm4Cbc(void) {
    gSm4Cbc =
        EVP_CIPHER_meth_new(NID_sm4_cbc, SmSm4BlockSizeCbc(), SmSm4KeyLength());
    if (!gSm4Cbc) {
        return 0;
    }
    if (!EVP_CIPHER_meth_set_iv_length(gSm4Cbc, SmSm4IvLengthCbc())) {
        return 0;
    }
    if (!EVP_CIPHER_meth_set_flags(gSm4Cbc, SmSm4FlagsCbc())) {
        return 0;
    }
    if (!EVP_CIPHER_meth_set_init(gSm4Cbc, SmSm4CbcInit)) {
        return 0;
    }
    if (!EVP_CIPHER_meth_set_do_cipher(gSm4Cbc, SmSm4CbcCipher)) {
        return 0;
    }
    if (!EVP_CIPHER_meth_set_cleanup(gSm4Cbc, SmSm4CbcCleanup)) {
        return 0;
    }
    if (!EVP_CIPHER_meth_set_impl_ctx_size(gSm4Cbc, SmSm4CbcImplCtxSize())) {
        return 0;
    }
    return 1;
}

/* Initialize SM4 ECB cipher method */
static int InitSm4Ecb(void) {
    gSm4Ecb =
        EVP_CIPHER_meth_new(NID_sm4_ecb, SmSm4BlockSizeEcb(), SmSm4KeyLength());
    if (!gSm4Ecb) {
        return 0;
    }
    if (!EVP_CIPHER_meth_set_iv_length(gSm4Ecb, SmSm4IvLengthEcb())) {
        return 0;
    }
    if (!EVP_CIPHER_meth_set_flags(gSm4Ecb, SmSm4FlagsEcb())) {
        return 0;
    }
    if (!EVP_CIPHER_meth_set_init(gSm4Ecb, SmSm4EcbInit)) {
        return 0;
    }
    if (!EVP_CIPHER_meth_set_do_cipher(gSm4Ecb, SmSm4EcbCipher)) {
        return 0;
    }
    if (!EVP_CIPHER_meth_set_cleanup(gSm4Ecb, SmSm4EcbCleanup)) {
        return 0;
    }
    if (!EVP_CIPHER_meth_set_impl_ctx_size(gSm4Ecb, SmSm4EcbImplCtxSize())) {
        return 0;
    }
    return 1;
}

/* Engine initialization */
static int SmInit(ENGINE *e) {
    (void)e;

    /* Initialize SM3 digest */
    if (!InitSm3Digest()) {
        return 0;
    }

    /* Initialize SM4 CBC cipher */
    if (!InitSm4Cbc()) {
        return 0;
    }

    /* Initialize SM4 ECB cipher */
    if (!InitSm4Ecb()) {
        return 0;
    }

    return 1;
}

/* Engine cleanup */
static int SmFinish(ENGINE *e) {
    (void)e;
    if (gSm3Md) {
        EVP_MD_meth_free(gSm3Md);
        gSm3Md = NULL;
    }
    if (gSm4Cbc) {
        EVP_CIPHER_meth_free(gSm4Cbc);
        gSm4Cbc = NULL;
    }
    if (gSm4Ecb) {
        EVP_CIPHER_meth_free(gSm4Ecb);
        gSm4Ecb = NULL;
    }
    return 1;
}

/* Engine destroy */
static int SmDestroy(ENGINE *e) {
    (void)e;
    return 1;
}

/* Engine control */
static int SmCtrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void)) {
    (void)e;
    (void)i;
    (void)p;
    (void)f;
    switch (cmd) {
        case ENGINE_CTRL_SET_LOG_LEVEL:
            return 1;
        default:
            return 0;
    }
}

/* Engine command definitions */
static const ENGINE_CMD_DEFN smCmdDefns[] = {{0, NULL, NULL, 0}};

/* Engine implementation */

/* Engine bind function */
static int SmBind(ENGINE *e, const char *id) {
    (void)id; /* Unused parameter */

    if (!ENGINE_set_id(e, engineSmId) || !ENGINE_set_name(e, engineSmName) ||
        !ENGINE_set_init_function(e, SmInit) ||
        !ENGINE_set_finish_function(e, SmFinish) ||
        !ENGINE_set_destroy_function(e, SmDestroy) ||
        !ENGINE_set_ctrl_function(e, SmCtrl) ||
        !ENGINE_set_cmd_defns(e, smCmdDefns) ||
        !ENGINE_set_digests(e, SmDigests) || !ENGINE_set_ciphers(e, SmCiphers)) {
        return 0;
    }
    return 1;
}

/* Register the engine */
IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(SmBind)
