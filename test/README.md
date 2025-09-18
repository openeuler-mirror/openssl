# SM Engine Test Suite

本目录包含 SM Engine 的完整测试套件，包括功能测试、性能测试、内存安全测试等。

## 目录结构

```
test/
├── example.c           # 基础功能示例和测试
├── quick_test.c        # 快速功能验证测试
├── performance.c       # 性能基准测试
├── test_asan.c         # AddressSanitizer 内存安全测试
├── run_asan.sh         # ASAN 测试运行脚本
├── run_valgrind.sh     # Valgrind 内存检查脚本
├── README_ASAN.md      # ASAN 测试详细文档
└── CMakeLists.txt      # CMake 构建配置
```

## 测试程序说明

### 1. example.c - 基础功能测试

**功能**: 演示和测试 SM3/SM4 算法的基本用法

**测试内容**:
- SM3 哈希计算
- SM4-ECB 加密/解密
- SM4-CBC 加密/解密
- 引擎加载和初始化

**运行方式**:
```bash
# 使用 CMake 构建后运行
cd build
./bin/example

# 或使用 build.sh
./build.sh test
```

### 2. quick_test.c - 快速验证测试

**功能**: 快速验证 SM Engine 的核心功能是否正常

**测试内容**:
- SM3 已知向量测试
- SM4 已知向量测试
- 基本加密/解密往返测试

**运行方式**:
```bash
cd build
./bin/quick_test
```

### 3. performance.c - 性能基准测试

**功能**: 测量 SM3/SM4 算法的性能指标

**测试内容**:
- SM3 吞吐量测试（MB/s）
- SM4 加密速度测试（MB/s）
- SM4 解密速度测试（MB/s）
- 不同数据块大小的性能对比

**运行方式**:
```bash
cd build
./bin/performance

# 输出示例：
# SM3 Performance Test:
#   1KB blocks: 245.32 MB/s
#   16KB blocks: 312.45 MB/s
#   1MB blocks: 325.67 MB/s
```

### 4. test_asan.c - 内存安全测试

**功能**: 使用 AddressSanitizer 检测内存安全问题

**测试内容**:
- 边界条件测试（空输入、单字节、大数据）
- 内存压力测试（快速创建/销毁上下文）
- 上下文重用测试
- 无效输入处理
- 内存泄漏检测

**运行方式**:
```bash
# 需要启用 ASAN 构建
mkdir build-asan && cd build-asan
cmake .. -DENABLE_ASAN=ON
make
./bin/test_asan

# 或使用脚本
./test/run_asan.sh
```

## 测试脚本说明

### run_asan.sh - ASAN 测试脚本

**功能**: 自动构建和运行 ASAN 测试

**使用方法**:
```bash
./test/run_asan.sh [选项]

选项：
  -oi, --openssl-include DIR   OpenSSL 头文件目录
  -ol, --openssl-lib PATH       OpenSSL 库文件路径
  -d, --debug                   启用调试输出
  -v, --verbose                 启用详细 ASAN 输出
  -h, --help                    显示帮助信息

示例：
  # 使用默认配置
  ./test/run_asan.sh

  # 指定 OpenSSL 路径
  ./test/run_asan.sh -oi 3rd/openssl/include -ol 3rd/openssl/libcrypto.a

  # 调试模式
  ./test/run_asan.sh -d -v
```


### run_valgrind.sh - Valgrind 内存检查脚本

**功能**: 使用 Valgrind 进行内存泄漏和错误检测

**使用方法**:
```bash
./test/run_valgrind.sh [选项]

选项：
  -oi, --openssl-include DIR   OpenSSL 头文件目录
  -ol, --openssl-lib PATH       OpenSSL 库文件路径
  -t, --test PROGRAM           要测试的程序（默认: example）
  -f, --full                    完整检查（包括文件描述符泄漏）
  -s, --suppressions FILE       Valgrind 抑制文件
  -h, --help                    显示帮助信息

示例：
  # 测试 example 程序
  ./test/run_valgrind.sh

  # 测试特定程序
  ./test/run_valgrind.sh -t performance

  # 完整内存检查
  ./test/run_valgrind.sh -f
```

**输出分析**:
- `definitely lost`: 确定的内存泄漏
- `indirectly lost`: 间接内存泄漏
- `possibly lost`: 可能的内存泄漏
- `still reachable`: 程序退出时仍可访问的内存
- `ERROR SUMMARY`: 错误总数

## 使用 CMake 运行测试

### 基本测试流程

```bash
# 1. 创建构建目录
mkdir build && cd build

# 2. 配置构建
cmake ..

# 3. 编译
make -j4

# 4. 运行所有测试
make test
# 或
ctest --verbose

# 5. 运行特定测试
ctest -R example_test
```

### ASAN 测试流程

```bash
# 1. 创建 ASAN 构建目录
mkdir build-asan && cd build-asan

# 2. 配置 ASAN 构建
cmake .. -DENABLE_ASAN=ON -DCMAKE_BUILD_TYPE=Debug

# 3. 编译
make -j4

# 4. 运行 ASAN 测试
make run_asan_tests

# 或运行特定 ASAN 测试
ctest -L asan --verbose
```

### Valgrind 测试流程

```bash
# 1. 常规构建（不能与 ASAN 同时启用）
mkdir build-valgrind && cd build-valgrind
cmake .. -DENABLE_VALGRIND=ON

# 2. 编译
make -j4

# 3. 运行 Valgrind 测试
ctest -L valgrind --verbose
```

## 测试环境变量

以下环境变量可用于控制测试行为：

```bash
# OpenSSL 引擎路径
export OPENSSL_ENGINES=/path/to/engines

# ASAN 选项
export ASAN_OPTIONS="detect_leaks=1:check_initialization_order=1:print_stats=1"

# ASAN 符号解析器路径
export ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer

# Valgrind 选项
export VALGRIND_OPTS="--leak-check=full --show-leak-kinds=all"
```

## 故障排查

### 常见问题

1. **引擎加载失败**
```bash
Failed to load engine 'sm_ce_engine'
```
解决方案:
- 检查 `OPENSSL_ENGINES` 环境变量
- 确认引擎库文件存在: `ls $OPENSSL_ENGINES/libsm_engine.so`
- 验证 OpenSSL 配置: `openssl engine -t sm_ce_engine`

2. **ASAN 不可用**
```bash
Compiler does not support AddressSanitizer
```
解决方案:
- 更新编译器: GCC 4.8+ 或 Clang 3.1+
- macOS 用户确保安装了 Xcode Command Line Tools

3. **Valgrind 错误**
```bash
Valgrind is not installed
```
解决方案:
```bash
# Ubuntu/Debian
sudo apt-get install valgrind

# RHEL/CentOS
sudo yum install valgrind

# macOS (可能不支持 ARM64)
brew install valgrind
```

4. **测试超时**
```bash
Test timeout exceeded
```
解决方案:
- 增加超时时间: `ctest --timeout 300`
- 检查是否有死循环或死锁
- 使用调试模式查看详细输出

### 调试技巧

1. **启用详细输出**
```bash
# CMake 测试
ctest --verbose --output-on-failure

# 直接运行带调试
SM_ENGINE_DEBUG=1 ./bin/example
```

2. **使用 GDB 调试**
```bash
gdb ./bin/example
(gdb) run
(gdb) bt  # 查看堆栈
```

3. **查看 ASAN 输出**
```bash
# 保存 ASAN 日志
ASAN_OPTIONS=log_path=asan.log ./bin/test_asan

# 符号化堆栈
asan_symbolize.py < asan.log.12345
```
