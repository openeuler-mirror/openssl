/*
 * SM3/SM4 性能测试程序
 * 测试引擎的哈希和加密性能
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
#include <openssl/err.h>
#include <openssl/conf.h>

#define TEST_SECONDS 3      /* 每项测试运行秒数 */
#define WARMUP_ITERATIONS 1000  /* 预热迭代次数 */

/* 全局退出标志 */
static volatile int g_interrupted = 0;

/* 测试数据大小 */
static const int block_sizes[] = {16, 64, 256, 1024, 8192, 16384};
static const int num_sizes = 6;

/* 信号处理函数 */
static void signal_handler(int sig)
{
    if (sig == SIGINT) {
        printf("\n\n>>> 收到中断信号，正在退出...\n");
        g_interrupted = 1;
    }
}

/* 获取当前时间（微秒精度） */
static double get_time(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec / 1000000.0;
}

/* 格式化输出大小 */
static const char *format_size(long bytes)
{
    static char buf[32];
    if (bytes < 1024) {
        snprintf(buf, sizeof(buf), "%ld B", bytes);
    } else if (bytes < 1024 * 1024) {
        snprintf(buf, sizeof(buf), "%.2f KB", bytes / 1024.0);
    } else if (bytes < 1024 * 1024 * 1024) {
        snprintf(buf, sizeof(buf), "%.2f MB", bytes / 1024.0 / 1024.0);
    } else {
        snprintf(buf, sizeof(buf), "%.2f GB", bytes / 1024.0 / 1024.0 / 1024.0);
    }
    return buf;
}

/* 格式化输出速度 */
static const char *format_speed(double bytes_per_sec)
{
    static char buf[32];
    if (bytes_per_sec < 1024) {
        snprintf(buf, sizeof(buf), "%.2f B/s", bytes_per_sec);
    } else if (bytes_per_sec < 1024 * 1024) {
        snprintf(buf, sizeof(buf), "%.2f KB/s", bytes_per_sec / 1024.0);
    } else if (bytes_per_sec < 1024 * 1024 * 1024) {
        snprintf(buf, sizeof(buf), "%.2f MB/s", bytes_per_sec / 1024.0 / 1024.0);
    } else {
        snprintf(buf, sizeof(buf), "%.2f GB/s", bytes_per_sec / 1024.0 / 1024.0 / 1024.0);
    }
    return buf;
}

/* 测试SM3性能 */
static void benchmark_sm3(void)
{
    EVP_MD_CTX *ctx;
    const EVP_MD *md;
    unsigned char *buffer;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    int i, j;
    double start, elapsed;
    long iterations;
    double total_bytes;

    printf("\n┌────────────────────────────────────────────────────┐\n");
    printf("│                 SM3 哈希性能测试                    │\n");
    printf("└────────────────────────────────────────────────────┘\n\n");

    /* 获取SM3算法 */
    md = EVP_get_digestbyname("sm3");
    if (!md) {
        printf("错误: SM3算法不可用\n");
        return;
    }

    /* 创建上下文 */
    ctx = EVP_MD_CTX_new();
    if (!ctx) {
        printf("错误: 无法创建MD上下文\n");
        return;
    }

    printf("块大小          操作次数        总数据量        速度\n");
    printf("──────────────────────────────────────────────────────\n");

    /* 测试不同大小的数据块 */
    for (i = 0; i < num_sizes; i++) {
        if (g_interrupted) break;
        int size = block_sizes[i];

        /* 分配缓冲区 */
        buffer = malloc(size);
        if (!buffer) {
            printf("错误: 内存分配失败\n");
            continue;
        }
        RAND_bytes(buffer, size);

        /* 预热 */
        for (j = 0; j < WARMUP_ITERATIONS; j++) {
            EVP_DigestInit_ex(ctx, md, NULL);
            EVP_DigestUpdate(ctx, buffer, size);
            EVP_DigestFinal_ex(ctx, hash, &hash_len);
        }

        /* 正式测试 */
        iterations = 0;
        start = get_time();
        do {
            if (g_interrupted) break;
            EVP_DigestInit_ex(ctx, md, NULL);
            EVP_DigestUpdate(ctx, buffer, size);
            EVP_DigestFinal_ex(ctx, hash, &hash_len);
            iterations++;
            elapsed = get_time() - start;
        } while (elapsed < TEST_SECONDS && !g_interrupted);

        total_bytes = (double)iterations * size;
        printf("%-12d    %-10ld      %-12s    %s\n",
               size, iterations,
               format_size((long)total_bytes),
               format_speed(total_bytes / elapsed));

        free(buffer);
    }

    EVP_MD_CTX_free(ctx);
}

/* 测试SM4性能 */
static void benchmark_sm4(const char *cipher_name, const char *display_name)
{
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher;
    unsigned char key[16];
    unsigned char iv[16];
    unsigned char *plaintext;
    unsigned char *ciphertext;
    int outlen, tmplen;
    int i, j;
    double start, elapsed;
    long iterations;
    double total_bytes;

    printf("\n┌────────────────────────────────────────────────────┐\n");
    printf("│             %s 加密性能测试                 │\n", display_name);
    printf("└────────────────────────────────────────────────────┘\n\n");

    /* 获取算法 */
    cipher = EVP_get_cipherbyname(cipher_name);
    if (!cipher) {
        printf("错误: %s算法不可用\n", cipher_name);
        return;
    }

    /* 初始化密钥和IV */
    RAND_bytes(key, sizeof(key));
    RAND_bytes(iv, sizeof(iv));

    /* 创建上下文 */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        printf("错误: 无法创建CIPHER上下文\n");
        return;
    }

    printf("块大小          操作次数        总数据量        速度\n");
    printf("──────────────────────────────────────────────────────\n");

    /* 测试不同大小的数据块 */
    for (i = 0; i < num_sizes; i++) {
        if (g_interrupted) break;
        int size = block_sizes[i];

        /* 分配缓冲区 */
        plaintext = malloc(size);
        ciphertext = malloc(size + EVP_CIPHER_block_size(cipher));
        if (!plaintext || !ciphertext) {
            printf("错误: 内存分配失败\n");
            if (plaintext) free(plaintext);
            if (ciphertext) free(ciphertext);
            continue;
        }
        RAND_bytes(plaintext, size);

        /* 预热 */
        for (j = 0; j < WARMUP_ITERATIONS; j++) {
            EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);
            EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, size);
            EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &tmplen);
        }

        /* 正式测试 */
        iterations = 0;
        start = get_time();
        do {
            if (g_interrupted) break;
            EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);
            EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, size);
            EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &tmplen);
            iterations++;
            elapsed = get_time() - start;
        } while (elapsed < TEST_SECONDS && !g_interrupted);

        total_bytes = (double)iterations * size;
        printf("%-12d    %-10ld      %-12s    %s\n",
               size, iterations,
               format_size((long)total_bytes),
               format_speed(total_bytes / elapsed));

        free(plaintext);
        free(ciphertext);
    }

    EVP_CIPHER_CTX_free(ctx);
}



/* 加载SM引擎 */
static ENGINE *load_sm_engine(const char *engine_path)
{
    ENGINE *e = NULL;
    char error_buf[256];

    /* 如果提供了引擎路径，尝试动态加载 */
    if (engine_path) {
        printf("尝试从路径加载引擎: %s\n", engine_path);

        /* 检查文件是否存在 */
        FILE *fp = fopen(engine_path, "r");
        if (!fp) {
            printf("  ✗ 错误: 引擎文件不存在: %s\n", engine_path);
            return NULL;
        }
        fclose(fp);

        ENGINE_load_dynamic();
        e = ENGINE_by_id("dynamic");
        if (e) {
            if (!ENGINE_ctrl_cmd_string(e, "SO_PATH", engine_path, 0)) {
                ERR_error_string_n(ERR_get_error(), error_buf, sizeof(error_buf));
                printf("  ✗ 错误: 无法设置引擎路径: %s\n", error_buf);
                ENGINE_free(e);
                e = NULL;
            } else if (!ENGINE_ctrl_cmd_string(e, "ID", "sm_ce_engine", 0)) {
                ERR_error_string_n(ERR_get_error(), error_buf, sizeof(error_buf));
                printf("  ✗ 错误: 无法设置引擎ID: %s\n", error_buf);
                ENGINE_free(e);
                e = NULL;
            } else if (!ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0)) {
                ERR_error_string_n(ERR_get_error(), error_buf, sizeof(error_buf));
                printf("  ✗ 错误: 无法加载引擎: %s\n", error_buf);
                ENGINE_free(e);
                e = NULL;
            } else {
                printf("  ✓ 成功动态加载引擎\n");
            }
        } else {
            printf("  ✗ 错误: 无法获取动态引擎\n");
        }
    }

    /* 如果动态加载失败，尝试使用配置文件中的引擎 */
    if (!e) {
        printf("尝试通过配置文件加载引擎...\n");

        /* 先尝试使用环境变量设置配置文件 */
        const char *config_file = getenv("OPENSSL_CONF");
        if (config_file) {
            printf("  使用配置文件: %s\n", config_file);
        } else {
            /* 如果没有设置环境变量，尝试设置本地配置文件 */
            setenv("OPENSSL_CONF", "test/openssl.cnf", 1);
            printf("  设置配置文件: test/openssl.cnf\n");

            /* 重新初始化OpenSSL以加载新配置 */
            CONF_modules_unload(1);
            OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);
        }

        /* 通过配置文件加载引擎 */
        e = ENGINE_by_id("sm_ce_engine");
        if (!e) {
            printf("  ✗ SM引擎未找到（使用OpenSSL内置）\n");
            return NULL;
        }
        printf("  ✓ 成功通过配置文件获取引擎\n");
    }

    /* 初始化引擎 */
    if (!ENGINE_init(e)) {
        ERR_error_string_n(ERR_get_error(), error_buf, sizeof(error_buf));
        printf("  ✗ 错误: 引擎初始化失败: %s\n", error_buf);
        ENGINE_free(e);
        return NULL;
    }
    printf("  ✓ 引擎初始化成功\n");

    /* 设置为默认引擎 */
    if (!ENGINE_set_default_digests(e)) {
        printf("  ⚠ 警告: 无法设置为默认摘要引擎\n");
    } else {
        printf("  ✓ 已设置为默认摘要引擎\n");
    }

    if (!ENGINE_set_default_ciphers(e)) {
        printf("  ⚠ 警告: 无法设置为默认加密引擎\n");
    } else {
        printf("  ✓ 已设置为默认加密引擎\n");
    }

    /* 列出引擎支持的算法 */
    printf("\n引擎信息:\n");
    const char *engine_name = ENGINE_get_name(e);
    const char *engine_id = ENGINE_get_id(e);
    printf("  • 名称: %s\n", engine_name ? engine_name : "未知");
    printf("  • ID: %s\n", engine_id ? engine_id : "未知");

    return e;
}

/* 打印使用说明 */
static void print_usage(const char *program)
{
    printf("用法: %s [选项]\n", program);
    printf("选项:\n");
    printf("  -h, --help         显示帮助信息\n");
    printf("  -e, --engine PATH  指定引擎路径\n");
    printf("  -t <秒>            设置每项测试时长（默认: %d秒）\n", TEST_SECONDS);
    printf("\n");
    printf("示例:\n");
    printf("  %s                 # 使用配置文件中的引擎\n", program);
    printf("  %s -e build/lib/libsm_engine.dylib  # 指定引擎路径\n", program);
    printf("\n");
    printf("提示: 按 Ctrl+C 可以随时中断测试\n");
}

int main(int argc, char *argv[])
{
    const char *engine_path = NULL;
    ENGINE *engine = NULL;
    int i;

    /* 设置信号处理 */
    signal(SIGINT, signal_handler);

    /* 解析参数 */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if ((strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "--engine") == 0) && i + 1 < argc) {
            engine_path = argv[++i];
        }
    }

    printf("╔════════════════════════════════════════════════════╗\n");
    printf("║          SM Engine 性能测试程序 v1.0               ║\n");
    printf("╚════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("测试配置:\n");
    printf("  • OpenSSL版本: %s\n", SSLeay_version(SSLEAY_VERSION));
    printf("  • 测试时长: %d秒/项\n", TEST_SECONDS);
    printf("  • 预热次数: %d次\n", WARMUP_ITERATIONS);
    printf("  • 测试块大小: ");
    for (i = 0; i < num_sizes; i++) {
        printf("%d ", block_sizes[i]);
    }
    printf("bytes\n");

    /* 设置环境变量以使用本地配置文件 */
    if (!getenv("OPENSSL_CONF")) {
        setenv("OPENSSL_CONF", "test/openssl.cnf", 1);
        printf("  • 配置文件: test/openssl.cnf (自动设置)\n");
    } else {
        printf("  • 配置文件: %s\n", getenv("OPENSSL_CONF"));
    }

    /* 初始化OpenSSL */
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);

    /* 加载所有算法 */
    OpenSSL_add_all_algorithms();

    /* 加载引擎 */
    ENGINE_load_builtin_engines();
    ENGINE_register_all_complete();

    /* 尝试加载SM引擎 */
    printf("\n正在加载SM引擎...\n");
    engine = load_sm_engine(engine_path);
    if (engine) {
        printf("  • 引擎状态: 已加载\n");
    } else {
        printf("  • 引擎状态: 未加载（使用OpenSSL内置实现）\n");
    }
    printf("\n");

    /* 检查算法可用性 */
    const EVP_MD *sm3_md = EVP_get_digestbyname("sm3");
    const EVP_CIPHER *sm4_ecb = EVP_get_cipherbyname("sm4-ecb");
    const EVP_CIPHER *sm4_cbc = EVP_get_cipherbyname("sm4-cbc");

    printf("算法支持状态:\n");
    printf("  • SM3:     %s", sm3_md ? "可用" : "不可用");
    if (sm3_md && engine) {
        /* 检查算法提供者 */
        int from_engine = 0;
        ENGINE_DIGESTS_PTR fn = ENGINE_get_digests(engine);
        if (fn) {
            const int *nids;
            int n = fn(engine, NULL, &nids, 0);
            for (int j = 0; j < n; j++) {
                if (nids[j] == EVP_MD_type(sm3_md)) {
                    from_engine = 1;
                    break;
                }
            }
        }
        printf(" [来源: %s]", from_engine ? "SM引擎" : "OpenSSL内置");
    }
    printf("\n");

    printf("  • SM4-ECB: %s", sm4_ecb ? "可用" : "不可用");
    if (sm4_ecb && engine) {
        int from_engine = 0;
        ENGINE_CIPHERS_PTR fn = ENGINE_get_ciphers(engine);
        if (fn) {
            const int *nids;
            int n = fn(engine, NULL, &nids, 0);
            for (int j = 0; j < n; j++) {
                if (nids[j] == EVP_CIPHER_nid(sm4_ecb)) {
                    from_engine = 1;
                    break;
                }
            }
        }
        printf(" [来源: %s]", from_engine ? "SM引擎" : "OpenSSL内置");
    }
    printf("\n");

    printf("  • SM4-CBC: %s", sm4_cbc ? "可用" : "不可用");
    if (sm4_cbc && engine) {
        int from_engine = 0;
        ENGINE_CIPHERS_PTR fn = ENGINE_get_ciphers(engine);
        if (fn) {
            const int *nids;
            int n = fn(engine, NULL, &nids, 0);
            for (int j = 0; j < n; j++) {
                if (nids[j] == EVP_CIPHER_nid(sm4_cbc)) {
                    from_engine = 1;
                    break;
                }
            }
        }
        printf(" [来源: %s]", from_engine ? "SM引擎" : "OpenSSL内置");
    }
    printf("\n\n");

    /* 运行性能测试 */
    if (sm3_md) {
        benchmark_sm3();
    } else {
        printf("跳过 SM3 测试（算法不可用）\n");
    }

    if (sm4_ecb) {
        benchmark_sm4("sm4-ecb", "SM4-ECB");
    } else {
        printf("跳过 SM4-ECB 测试（算法不可用）\n");
    }

    if (sm4_cbc) {
        benchmark_sm4("sm4-cbc", "SM4-CBC");
    } else {
        printf("跳过 SM4-CBC 测试（算法不可用）\n");
    }

    /* 检查是否被中断 */
    if (g_interrupted) {
        printf("\n\n>>> 测试被用户中断\n");
    }

    printf("\n╔════════════════════════════════════════════════════╗\n");
    printf("║                    测试完成                        ║\n");
    printf("╚════════════════════════════════════════════════════╝\n");

    /* 清理引擎 */
    if (engine) {
        ENGINE_finish(engine);
        ENGINE_free(engine);
    }

    /* 清理 */
    EVP_cleanup();
    ENGINE_cleanup();

    return 0;
}