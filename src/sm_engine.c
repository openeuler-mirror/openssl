#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/objects.h>
#include "sm3.h"
#include "sm4.h"

/* Engine control commands */
#define ENGINE_CTRL_SET_LOG_LEVEL 1000

/* Define NIDs for SM algorithms */


static const char *engine_sm_id = "sm_ce_engine";
static const char *engine_sm_name = "SM3/SM4 Engine (Static Library)";

/* Dynamic method objects (opaque in OpenSSL 1.1.1) */
static EVP_MD *g_sm3_md = NULL;
static EVP_CIPHER *g_sm4_cbc = NULL;
static EVP_CIPHER *g_sm4_ecb = NULL;

/* SM3 digest function */
static int sm_digests(ENGINE *e, const EVP_MD **digest, const int **nids, int nid)
{
    (void)e;
    static int sm3_nids[] = {NID_sm3, 0};
    if (digest == NULL) {
        *nids = sm3_nids;
        return 1;
    }
    switch (nid) {
        case NID_sm3:
            if (digest) {
                *digest = g_sm3_md;
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
static int sm_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid)
{
    (void)e;
    static int sm4_nids[] = {NID_sm4_cbc, NID_sm4_ecb, 0};
    if (cipher == NULL) {
        *nids = sm4_nids;
        return 2;
    }
    switch (nid) {
        case NID_sm4_cbc:
            if (cipher) {
                *cipher = g_sm4_cbc;
                if (*cipher == NULL) {
                    return 0;
                }
                return 1;
            }
            return 0;
        case NID_sm4_ecb:
            if (cipher) {
                *cipher = g_sm4_ecb;
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

/* Engine initialization */
static int sm_init(ENGINE *e)
{
    (void)e;
    /* Create SM3 method */
    g_sm3_md = EVP_MD_meth_new(NID_sm3, sm_sm3_pkey_type());
    if (!g_sm3_md) return 0;
    if (!EVP_MD_meth_set_result_size(g_sm3_md, sm_sm3_result_size())) return 0;
    if (!EVP_MD_meth_set_app_datasize(g_sm3_md, sm_sm3_app_datasize())) return 0;
    if (!EVP_MD_meth_set_init(g_sm3_md, sm_sm3_init)) return 0;
    if (!EVP_MD_meth_set_update(g_sm3_md, sm_sm3_update)) return 0;
    if (!EVP_MD_meth_set_final(g_sm3_md, sm_sm3_final)) return 0;
    if (!EVP_MD_meth_set_copy(g_sm3_md, sm_sm3_copy)) return 0;
    if (!EVP_MD_meth_set_cleanup(g_sm3_md, sm_sm3_cleanup)) return 0;

    /* Create SM4 CBC method (directly using sm_ helpers) */
    g_sm4_cbc = EVP_CIPHER_meth_new(NID_sm4_cbc, sm_sm4_block_size_cbc(), sm_sm4_key_length());
    if (!g_sm4_cbc) return 0;
    if (!EVP_CIPHER_meth_set_iv_length(g_sm4_cbc, sm_sm4_iv_length_cbc())) return 0;
    if (!EVP_CIPHER_meth_set_flags(g_sm4_cbc, sm_sm4_flags_cbc())) return 0;
    if (!EVP_CIPHER_meth_set_init(g_sm4_cbc, sm_sm4_cbc_init)) return 0;
    if (!EVP_CIPHER_meth_set_do_cipher(g_sm4_cbc, sm_sm4_cbc_cipher)) return 0;
    if (!EVP_CIPHER_meth_set_cleanup(g_sm4_cbc, sm_sm4_cbc_cleanup)) return 0;
    if (!EVP_CIPHER_meth_set_impl_ctx_size(g_sm4_cbc, sm_sm4_cbc_impl_ctx_size())) return 0;

    /* Create SM4 ECB method (directly using sm_ helpers) */
    g_sm4_ecb = EVP_CIPHER_meth_new(NID_sm4_ecb, sm_sm4_block_size_ecb(), sm_sm4_key_length());
    if (!g_sm4_ecb) return 0;
    if (!EVP_CIPHER_meth_set_iv_length(g_sm4_ecb, sm_sm4_iv_length_ecb())) return 0;
    if (!EVP_CIPHER_meth_set_flags(g_sm4_ecb, sm_sm4_flags_ecb())) return 0;
    if (!EVP_CIPHER_meth_set_init(g_sm4_ecb, sm_sm4_ecb_init)) return 0;
    if (!EVP_CIPHER_meth_set_do_cipher(g_sm4_ecb, sm_sm4_ecb_cipher)) return 0;
    if (!EVP_CIPHER_meth_set_cleanup(g_sm4_ecb, sm_sm4_ecb_cleanup)) return 0;
    if (!EVP_CIPHER_meth_set_impl_ctx_size(g_sm4_ecb, sm_sm4_ecb_impl_ctx_size())) return 0;

    return 1;
}

/* Engine cleanup */
static int sm_finish(ENGINE *e)
{
    (void)e;
    if (g_sm3_md) {
        EVP_MD_meth_free(g_sm3_md);
        g_sm3_md = NULL;
    }
    if (g_sm4_cbc) {
        EVP_CIPHER_meth_free(g_sm4_cbc);
        g_sm4_cbc = NULL;
    }
    if (g_sm4_ecb) {
        EVP_CIPHER_meth_free(g_sm4_ecb);
        g_sm4_ecb = NULL;
    }
    return 1;
}

/* Engine destroy */
static int sm_destroy(ENGINE *e)
{
    (void)e;
    return 1;
}

/* Engine control */
static int sm_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void))
{
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
static const ENGINE_CMD_DEFN sm_cmd_defns[] = {
    {0, NULL, NULL, 0}
};

/* Engine implementation */

/* Engine bind function */
static int sm_bind(ENGINE *e, const char *id)
{
    if (!ENGINE_set_id(e, engine_sm_id) ||
        !ENGINE_set_name(e, engine_sm_name) ||
        !ENGINE_set_init_function(e, sm_init) ||
        !ENGINE_set_finish_function(e, sm_finish) ||
        !ENGINE_set_destroy_function(e, sm_destroy) ||
        !ENGINE_set_ctrl_function(e, sm_ctrl) ||
        !ENGINE_set_cmd_defns(e, sm_cmd_defns) ||
        !ENGINE_set_digests(e, sm_digests) ||
        !ENGINE_set_ciphers(e, sm_ciphers)) {
        return 0;
    }
    return 1;
}

/* Register the engine */
IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(sm_bind)