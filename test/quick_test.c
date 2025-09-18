/*
 * SM引擎快速测试程序
 * 验证SM3和SM4算法功能和基本性能
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <signal.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/engine.h>
#include <openssl/crypto.h>

#define TEST_SIZE 1024
#define TEST_ITERATIONS 10000

/* 全局退出标志 */
static volatile int g_interrupted = 0;

/* 信号处理函数 */
static void signal_handler(int sig)
{
    if (sig == SIGINT) {
        printf("\n\n>>> 收到中断信号，正在退出...\n");
        g_interrupted = 1;
    }
}

/* 获取时间（秒） */
static double get_time(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec / 1000000.0;
}

/* 测试SM3 */
static void test_sm3(void)
{
    EVP_MD_CTX *ctx;
    const EVP_MD *md;
    unsigned char data[TEST_SIZE];
    unsigned char hash[32];
    unsigned int hash_len;
    double start, elapsed;
    int i;

    printf("\nSM3 测试:\n");
    printf("----------\n");

    md = EVP_get_digestbyname("sm3");
    if (!md) {
        printf("  状态: 不可用\n");
        return;
    }

    printf("  状态: 可用\n");

    /* 准备测试数据 */
    RAND_bytes(data, sizeof(data));

    /* 功能测试 */
    ctx = EVP_MD_CTX_new();
    if (!ctx) {
        printf("  错误: 无法创建上下文\n");
        return;
    }

    if (EVP_DigestInit_ex(ctx, md, NULL) &&
        EVP_DigestUpdate(ctx, data, sizeof(data)) &&
        EVP_DigestFinal_ex(ctx, hash, &hash_len)) {
        printf("  哈希长度: %u 字节\n", hash_len);
        printf("  示例哈希: ");
        for (i = 0; i < 8; i++) {
            printf("%02x", hash[i]);
        }
        printf("...\n");
    }

    /* 性能测试 */
    start = get_time();
    for (i = 0; i < TEST_ITERATIONS && !g_interrupted; i++) {
        EVP_DigestInit_ex(ctx, md, NULL);
        EVP_DigestUpdate(ctx, data, sizeof(data));
        EVP_DigestFinal_ex(ctx, hash, &hash_len);
    }
    elapsed = get_time() - start;

    if (g_interrupted) {
        printf("  测试被中断\n");
        EVP_MD_CTX_free(ctx);
        return;
    }

    printf("  性能: %d 次/秒 (1KB数据)\n", (int)(TEST_ITERATIONS / elapsed));
    printf("  速度: %.2f MB/s\n", (TEST_ITERATIONS * TEST_SIZE / elapsed) / (1024.0 * 1024.0));

    EVP_MD_CTX_free(ctx);
}

/* 测试SM4 */
static void test_sm4(const char *cipher_name)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher;
    unsigned char key[16];
    unsigned char iv[16];
    unsigned char plaintext[TEST_SIZE];
    unsigned char ciphertext[TEST_SIZE + 32];
    unsigned char decrypted[TEST_SIZE + 32];
    int outlen, tmplen;
    double start, elapsed;
    int i;

    printf("\n%s 测试:\n", cipher_name);
    printf("----------\n");

    cipher = EVP_get_cipherbyname(cipher_name);
    if (!cipher) {
        printf("  状态: 不可用\n");
        return;
    }

    printf("  状态: 可用\n");

    /* 初始化密钥和数据 */
    RAND_bytes(key, sizeof(key));
    RAND_bytes(iv, sizeof(iv));
    RAND_bytes(plaintext, sizeof(plaintext));

    /* 创建上下文 */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("  错误: 无法创建上下文\n");
        return;
    }

    /* 功能测试 - 加密 */
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) &&
        EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, sizeof(plaintext)) &&
        EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &tmplen)) {
        int ciphertext_len = outlen + tmplen;
        printf("  密文长度: %d 字节\n", ciphertext_len);

        /* 功能测试 - 解密 */
        if (EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv) &&
            EVP_DecryptUpdate(ctx, decrypted, &outlen, ciphertext, ciphertext_len) &&
            EVP_DecryptFinal_ex(ctx, decrypted + outlen, &tmplen)) {
            if (memcmp(plaintext, decrypted, sizeof(plaintext)) == 0) {
                printf("  加解密: 成功\n");
            } else {
                printf("  加解密: 失败（数据不匹配）\n");
            }
        }
    }

    /* 性能测试 */
    start = get_time();
    for (i = 0; i < TEST_ITERATIONS && !g_interrupted; i++) {
        EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);
        EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, sizeof(plaintext));
        EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &tmplen);
    }
    elapsed = get_time() - start;

    if (g_interrupted) {
        printf("  测试被中断\n");
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    printf("  性能: %d 次/秒 (1KB数据)\n", (int)(TEST_ITERATIONS / elapsed));
    printf("  速度: %.2f MB/s\n", (TEST_ITERATIONS * TEST_SIZE / elapsed) / (1024.0 * 1024.0));

    EVP_CIPHER_CTX_free(ctx);
}

int main(int argc, char *argv[])
{
    (void)argc;  /* 未使用参数 */
    (void)argv;  /* 未使用参数 */
    ENGINE *engine = NULL;

    /* 设置信号处理 */
    signal(SIGINT, signal_handler);

    printf("========================================\n");
    printf("        SM引擎快速测试程序\n");
    printf("========================================\n");
    printf("提示: 按 Ctrl+C 可以随时中断测试\n\n");

    /* 初始化OpenSSL */
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
    OpenSSL_add_all_algorithms();
    ENGINE_load_builtin_engines();
    ENGINE_register_all_complete();

    /* 尝试加载SM引擎 */
    printf("\n引擎状态:\n");
    printf("----------\n");
    engine = ENGINE_by_id("sm_ce_engine");
    if (engine) {
        if (ENGINE_init(engine)) {
            ENGINE_set_default_digests(engine);
            ENGINE_set_default_ciphers(engine);
            printf("  SM引擎: 已加载\n");
        } else {
            printf("  SM引擎: 初始化失败\n");
            ENGINE_free(engine);
            engine = NULL;
        }
    } else {
        printf("  SM引擎: 未找到（使用OpenSSL内置）\n");
    }

    /* 运行测试 */
    test_sm3();
    test_sm4("sm4-ecb");
    test_sm4("sm4-cbc");

    /* 清理 */
    if (engine) {
        ENGINE_finish(engine);
        ENGINE_free(engine);
    }
    EVP_cleanup();
    ENGINE_cleanup();

    printf("\n========================================\n");
    printf("           测试完成\n");
    printf("========================================\n");

    return 0;
}