#!/bin/bash

# SM Engine 测试脚本

echo "========================================"
echo "       SM Engine 测试脚本"
echo "========================================"
echo ""

# 设置路径
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
TEST_DIR="${SCRIPT_DIR}/test"

# 检查编译
if [ ! -f "${BUILD_DIR}/lib/libsm_engine.dylib" ]; then
    echo "错误: 引擎未编译，请先运行："
    echo "  mkdir build && cd build && cmake .. && make"
    exit 1
fi

echo "1. 运行功能测试..."
echo "----------------------------------------"
cd "${BUILD_DIR}"
OPENSSL_CONF="${TEST_DIR}/openssl.cnf" ./bin/example
echo ""

echo "2. 运行性能测试（快速版）..."
echo "----------------------------------------"
cd "${BUILD_DIR}"
OPENSSL_CONF="${TEST_DIR}/openssl.cnf" ./bin/quick_test
echo ""

echo "注：完整性能测试可以通过以下命令运行："
echo "  cd build && OPENSSL_CONF=../test/openssl.cnf ./bin/performance -c"
echo ""

echo "========================================"
echo "           测试完成"
echo "========================================"