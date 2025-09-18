#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

/* 简单的SM3和SM4使用示例（通过配置文件加载引擎） */

static void test_sm3(const char *data)
{
    EVP_MD_CTX *md_ctx;
    const EVP_MD *md;
    unsigned char hash[32];
    int len;

    printf("SM3哈希示例:\n");
    printf("原始数据: %s\n", data);

    md = EVP_get_digestbyname("sm3");
    if (!md) {
        printf("错误: 无法获取SM3摘要方法\n");
        return;
    }

    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        printf("错误: 无法创建摘要上下文\n");
        return;
    }

    if (EVP_DigestInit_ex(md_ctx, md, NULL) &&
        EVP_DigestUpdate(md_ctx, data, strlen(data)) &&
        EVP_DigestFinal_ex(md_ctx, hash, &len)) {
        printf("SM3哈希值: ");
        for (int i = 0; i < len; i++) {
            printf("%02x", hash[i]);
        }
        printf("\n");
    } else {
        printf("错误: SM3哈希计算失败\n");
    }

    EVP_MD_CTX_free(md_ctx);
}

static void test_sm4_ecb_single(const unsigned char *key, const char *data)
{
    EVP_CIPHER_CTX *cipher_ctx;
    const EVP_CIPHER *cipher;
    unsigned char ciphertext[256];
    unsigned char plaintext[256];
    int len, ciphertext_len, plaintext_len;

    printf("\nSM4-ECB 单块加密示例:\n");
    cipher = EVP_get_cipherbyname("sm4-ecb");
    if (!cipher) { printf("错误: 无法获取SM4-ECB\n"); return; }

    cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx) { printf("错误: 无法创建密码上下文\n"); return; }

    if (EVP_EncryptInit_ex(cipher_ctx, cipher, NULL, key, NULL) &&
        EVP_EncryptUpdate(cipher_ctx, ciphertext, &len, (const unsigned char*)data, (int)strlen(data))) {
        ciphertext_len = len;
        if (EVP_EncryptFinal_ex(cipher_ctx, ciphertext + len, &len)) {
            ciphertext_len += len;
            printf("原始数据: %s\n", data);
            printf("密文长度: %d 字节\n", ciphertext_len);
            printf("密文: ");
            for (int i = 0; i < ciphertext_len; i++) printf("%02x", ciphertext[i]);
            printf("\n");

            EVP_CIPHER_CTX_free(cipher_ctx);
            cipher_ctx = EVP_CIPHER_CTX_new();

            if (EVP_DecryptInit_ex(cipher_ctx, cipher, NULL, key, NULL) &&
                EVP_DecryptUpdate(cipher_ctx, plaintext, &len, ciphertext, ciphertext_len)) {
                plaintext_len = len;
                if (EVP_DecryptFinal_ex(cipher_ctx, plaintext + len, &len)) {
                    plaintext_len += len;
                    plaintext[plaintext_len] = '\0';
                    printf("解密数据: %s\n", plaintext);
                    printf("%s\n", strcmp((const char*)plaintext, data) == 0 ? "✓ SM4-ECB 单块通过" : "✗ SM4-ECB 单块失败");
                } else { printf("错误: SM4-ECB 解密失败\n"); }
            } else { printf("错误: SM4-ECB 解密初始化失败\n"); }
        } else { printf("错误: SM4-ECB 加密完成失败\n"); }
    } else { printf("错误: SM4-ECB 加密失败\n"); }

    EVP_CIPHER_CTX_free(cipher_ctx);
}

static void test_sm4_ecb_multi(const unsigned char *key, const char *data)
{
    EVP_CIPHER_CTX *cipher_ctx;
    const EVP_CIPHER *cipher = EVP_get_cipherbyname("sm4-ecb");
    unsigned char ciphertext[256];
    unsigned char plaintext[256];
    int len, ciphertext_len = 0, plaintext_len = 0;
    size_t total = strlen(data), half = total / 2;

    printf("\nSM4-ECB 多块加密示例:\n");
    if (!cipher) { printf("错误: 无法获取SM4-ECB\n"); return; }
    cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx) { printf("错误: 无法创建密码上下文\n"); return; }
    if (!EVP_EncryptInit_ex(cipher_ctx, cipher, NULL, key, NULL)) { printf("错误: ECB 加密初始化失败\n"); EVP_CIPHER_CTX_free(cipher_ctx); return; }
    if (!EVP_EncryptUpdate(cipher_ctx, ciphertext + ciphertext_len, &len, (const unsigned char*)data, (int)half)) { printf("错误: ECB Update1\n"); EVP_CIPHER_CTX_free(cipher_ctx); return; }
    ciphertext_len += len;
    if (!EVP_EncryptUpdate(cipher_ctx, ciphertext + ciphertext_len, &len, (const unsigned char*)data + half, (int)(total - half))) { printf("错误: ECB Update2\n"); EVP_CIPHER_CTX_free(cipher_ctx); return; }
    ciphertext_len += len;
    if (!EVP_EncryptFinal_ex(cipher_ctx, ciphertext + ciphertext_len, &len)) { printf("错误: ECB Final\n"); EVP_CIPHER_CTX_free(cipher_ctx); return; }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(cipher_ctx);
    cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx) { printf("错误: 无法创建密码上下文\n"); return; }
    if (!EVP_DecryptInit_ex(cipher_ctx, cipher, NULL, key, NULL)) { printf("错误: ECB 解密初始化失败\n"); EVP_CIPHER_CTX_free(cipher_ctx); return; }
    if (!EVP_DecryptUpdate(cipher_ctx, plaintext + plaintext_len, &len, ciphertext, ciphertext_len)) { printf("错误: ECB 解密 Update\n"); EVP_CIPHER_CTX_free(cipher_ctx); return; }
    plaintext_len += len;
    if (!EVP_DecryptFinal_ex(cipher_ctx, plaintext + plaintext_len, &len)) { printf("错误: ECB 解密 Final\n"); EVP_CIPHER_CTX_free(cipher_ctx); return; }
    plaintext_len += len;
    plaintext[plaintext_len] = '\0';
    printf("ECB 多块解密数据: %s\n", plaintext);
    printf("%s\n", strcmp((const char*)plaintext, data) == 0 ? "✓ SM4-ECB 多块通过" : "✗ SM4-ECB 多块失败");
    EVP_CIPHER_CTX_free(cipher_ctx);
}

static void test_sm4_cbc_single(const unsigned char *key, const unsigned char *iv, const char *data)
{
    EVP_CIPHER_CTX *cipher_ctx;
    const EVP_CIPHER *cipher;
    unsigned char ciphertext[256];
    unsigned char plaintext[256];
    int len, ciphertext_len, plaintext_len;

    printf("\nSM4-CBC 单块加密示例:\n");
    cipher = EVP_get_cipherbyname("sm4-cbc");
    if (!cipher) { printf("错误: 无法获取SM4-CBC\n"); return; }

    cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx) { printf("错误: 无法创建密码上下文\n"); return; }

    if (EVP_EncryptInit_ex(cipher_ctx, cipher, NULL, key, iv) &&
        EVP_EncryptUpdate(cipher_ctx, ciphertext, &len, (const unsigned char*)data, (int)strlen(data))) {
        ciphertext_len = len;
        if (EVP_EncryptFinal_ex(cipher_ctx, ciphertext + len, &len)) {
            ciphertext_len += len;
            printf("原始数据: %s\n", data);
            printf("密文长度: %d 字节\n", ciphertext_len);
            printf("密文: ");
            for (int i = 0; i < ciphertext_len; i++) printf("%02x", ciphertext[i]);
            printf("\n");

            EVP_CIPHER_CTX_free(cipher_ctx);
            cipher_ctx = EVP_CIPHER_CTX_new();

            if (EVP_DecryptInit_ex(cipher_ctx, cipher, NULL, key, iv) &&
                EVP_DecryptUpdate(cipher_ctx, plaintext, &len, ciphertext, ciphertext_len)) {
                plaintext_len = len;
                if (EVP_DecryptFinal_ex(cipher_ctx, plaintext + len, &len)) {
                    plaintext_len += len;
                    plaintext[plaintext_len] = '\0';
                    printf("解密数据: %s\n", plaintext);
                    printf("%s\n", strcmp((const char*)plaintext, data) == 0 ? "✓ SM4-CBC 单块通过" : "✗ SM4-CBC 单块失败");
                } else { printf("错误: SM4-CBC 解密失败\n"); }
            } else { printf("错误: SM4-CBC 解密初始化失败\n"); }
        } else { printf("错误: SM4-CBC 加密完成失败\n"); }
    } else { printf("错误: SM4-CBC 加密失败\n"); }

    EVP_CIPHER_CTX_free(cipher_ctx);
}

static void test_sm4_cbc_multi(const unsigned char *key, const unsigned char *iv, const char *data)
{
    EVP_CIPHER_CTX *cipher_ctx;
    const EVP_CIPHER *cipher = EVP_get_cipherbyname("sm4-cbc");
    unsigned char ciphertext[256];
    unsigned char plaintext[256];
    int len, ciphertext_len = 0, plaintext_len = 0;
    size_t total = strlen(data), half = total / 2;

    printf("\nSM4-CBC 多块加密示例:\n");
    if (!cipher) { printf("错误: 无法获取SM4-CBC\n"); return; }
    cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx) { printf("错误: 无法创建密码上下文\n"); return; }
    if (!EVP_EncryptInit_ex(cipher_ctx, cipher, NULL, key, iv)) { printf("错误: CBC 加密初始化失败\n"); EVP_CIPHER_CTX_free(cipher_ctx); return; }
    if (!EVP_EncryptUpdate(cipher_ctx, ciphertext + ciphertext_len, &len, (const unsigned char*)data, (int)half)) { printf("错误: CBC Update1\n"); EVP_CIPHER_CTX_free(cipher_ctx); return; }
    ciphertext_len += len;
    if (!EVP_EncryptUpdate(cipher_ctx, ciphertext + ciphertext_len, &len, (const unsigned char*)data + half, (int)(total - half))) { printf("错误: CBC Update2\n"); EVP_CIPHER_CTX_free(cipher_ctx); return; }
    ciphertext_len += len;
    if (!EVP_EncryptFinal_ex(cipher_ctx, ciphertext + ciphertext_len, &len)) { printf("错误: CBC Final\n"); EVP_CIPHER_CTX_free(cipher_ctx); return; }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(cipher_ctx);
    cipher_ctx = EVP_CIPHER_CTX_new();
    if (!cipher_ctx) { printf("错误: 无法创建密码上下文\n"); return; }
    if (!EVP_DecryptInit_ex(cipher_ctx, cipher, NULL, key, iv)) { printf("错误: CBC 解密初始化失败\n"); EVP_CIPHER_CTX_free(cipher_ctx); return; }
    if (!EVP_DecryptUpdate(cipher_ctx, plaintext + plaintext_len, &len, ciphertext, ciphertext_len)) { printf("错误: CBC 解密 Update\n"); EVP_CIPHER_CTX_free(cipher_ctx); return; }
    plaintext_len += len;
    if (!EVP_DecryptFinal_ex(cipher_ctx, plaintext + plaintext_len, &len)) { printf("错误: CBC 解密 Final\n"); EVP_CIPHER_CTX_free(cipher_ctx); return; }
    plaintext_len += len;
    plaintext[plaintext_len] = '\0';
    printf("CBC 多块解密数据: %s\n", plaintext);
    printf("%s\n", strcmp((const char*)plaintext, data) == 0 ? "✓ SM4-CBC 多块通过" : "✗ SM4-CBC 多块失败");
    EVP_CIPHER_CTX_free(cipher_ctx);
}

int main() {
    unsigned char key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    unsigned char iv[16] = {
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x0f, 0xed, 0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21
    };
    const char *test_data = "Hello, SM3 and SM4!";
    
    printf("SM Engine 使用示例 (通过配置加载)\n");
    printf("================================\n\n");
    
    /* 初始化OpenSSL并加载配置（包含引擎配置） */
    if (!OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL)) {
        printf("错误: OPENSSL_init_crypto 失败\n");
        return 1;
    }
    test_sm3(test_data);
    test_sm4_ecb_single(key, test_data);
    test_sm4_ecb_multi(key, test_data);
    test_sm4_cbc_single(key, iv, test_data);
    test_sm4_cbc_multi(key, iv, test_data);

    printf("\n示例程序执行完成\n");
    return 0;
}