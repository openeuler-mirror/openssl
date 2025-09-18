# SM Engine - OpenSSL Engine for SM3 and SM4 Algorithms (Static Library)

这是一个基于OpenSSL 1.1.1的引擎实现，通过静态链接外部OpenSSL库来提供SM3哈希算法和SM4加密算法的支持。

## 功能特性

- **SM3哈希算法**: 通过静态链接的外部OpenSSL库的EVP接口实现SM3哈希算法
- **SM4加密算法**: 通过静态链接的外部OpenSSL库的EVP接口实现SM4加密算法，支持CBC、ECB模式（GCM 需外部库支持后再启用）
- **静态链接**: 外部OpenSSL库通过静态链接方式集成到engine中
- **符号隐藏**: 使用链接脚本隐藏除engine初始化之外的所有符号（macOS 使用 exported.symbols，Linux 使用 version script）
- **OpenSSL集成**: 完全集成到OpenSSL框架中，支持EVP接口
- **动态引擎加载**: 支持动态引擎加载，无需重新编译OpenSSL

## 架构设计

本引擎采用静态链接模式，通过以下方式工作：

1. **静态链接**: 外部OpenSSL库通过静态链接方式集成到engine中
2. **直接调用**: 直接调用外部库的EVP接口函数
3. **符号隐藏**: 使用链接脚本隐藏内部实现细节
4. **透明接口**: 用户调用engine接口时，实际调用外部库的实现

## 编译与使用

### 一键构建（推荐）

使用 `build.sh` 脚本统一构建引擎与示例。支持为“引擎编译/链接”和“示例编译/链接”分别指定 OpenSSL 的头文件与库路径。

常用参数：
- `-oi, --openssl-include DIR` 引擎编译头文件目录（可重复）
- `-ol, --openssl-lib-path FILE` 引擎链接使用的 OpenSSL 库路径（如 `libcrypto.a`）
- `-ai, --app-include DIR` 示例/测试编译头文件目录（可重复）
- `-al, --app-lib-path FILE` 示例/测试链接使用的 OpenSSL 库路径
- `--cc CC` 指定编译器；`--cflags '...'` 指定编译参数

构建引擎与示例：
```bash
./build.sh build \
  -oi ../../openssl-OpenSSL_1_1_1wc/include \
  -ol ../../openssl-OpenSSL_1_1_1wc/libcrypto.a \
  -ai ../../openssl-OpenSSL_1_1_1wc/include \
  -al ../../openssl-OpenSSL_1_1_1wc/libcrypto.a
```

运行示例：
```bash
./build.sh test
```

安装引擎（默认安装到 `/usr/local/lib/engines`）：
```bash
sudo ./build.sh install
```

卸载引擎：
```bash
sudo ./build.sh uninstall
```

清理构建：
```bash
./build.sh clean
```

输出产物：
- 引擎共享库：`build/libsm_engine.so`
- 示例可执行：`build/example`

说明：
- macOS 链接器不支持 GNU `--version-script`，脚本会自动使用 `-Wl,-exported_symbols_list,exported.symbols`；Linux 下则使用 `sm_engine.syms`。
- 若需自定义导出符号请编辑仓库根目录的 `exported.symbols`（macOS）或 `sm_engine.syms`（Linux）。

### OpenSSL 配置

`openssl.cnf` 示例（如使用）：
```ini
openssl_conf = openssl_init

[openssl_init]
engines = engine_section

[engine_section]
sm_ce_engine = sm_section

[sm_section]
engine_id = sm_ce_engine
# 请将 dynamic_path 改为你安装/构建的实际路径
# dynamic_path = /usr/local/lib/engines/libsm_engine.so
init = 1
default_algorithms = DIGESTS,CIPHERS
```

### 通过 EVP 标准接口使用

示例程序已放在 `test/example.c`，其工作流程：
1. 调用 `OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL)` 载入配置与引擎
2. 通过 `EVP_get_digestbyname("sm3")`、`EVP_get_cipherbyname("sm4-ecb")` 获取算法
3. 使用标准 EVP API 完成哈希/加密/解密

## 符号隐藏

本引擎使用链接脚本隐藏除engine初始化之外的所有符号：

### 可见符号
- `bind_engine`（动态引擎绑定入口）
- `v_check`（OpenSSL 动态引擎版本检查）

### 隐藏符号
- 所有SM3/SM4算法实现函数
- 所有内部辅助函数
- 所有外部库调用函数

## 依赖要求

- OpenSSL 1.1.1 或更高版本（示例使用 1.1.1 分支）
- GCC/Clang 编译器
- Make 工具（可选）

## 故障排除

- 链接报 `unknown option --version-script`：macOS 上请使用 `exported.symbols` 方案（脚本已自动处理）。
- 运行找不到引擎：检查 `openssl.cnf` 的 `dynamic_path` 是否正确、引擎是否安装到系统默认目录。
- `NID_sm4_gcm` 未定义：当前示例未启用 GCM，启用前需确保外部 OpenSSL 提供该算法及符号。

## 许可证

本项目基于Mulan PSL v2许可证开源。详见LICENSE文件。

## 贡献

build by openHiTLS community, not for commicial use


