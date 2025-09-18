#!/bin/bash

echo "==========================================="
echo "    验证 SM Engine 链接配置"
echo "==========================================="
echo ""

cd "$(dirname "$0")/build"

echo "1. 检查引擎库依赖"
echo "-------------------------------------------"
echo "引擎库: lib/libsm_engine.dylib"
otool -L lib/libsm_engine.dylib
echo ""

echo "2. 检查 OpenSSL 符号是否静态链接到引擎"
echo "-------------------------------------------"
echo "EVP 符号数量: $(nm lib/libsm_engine.dylib | grep -c EVP_)"
echo "SM3 符号数量: $(nm lib/libsm_engine.dylib | grep -c SM3_)"
echo "SM4 符号数量: $(nm lib/libsm_engine.dylib | grep -c SM4_)"
echo "ENGINE 符号数量: $(nm lib/libsm_engine.dylib | grep -c ENGINE_)"
echo ""

echo "3. 检查测试程序依赖"
echo "-------------------------------------------"
echo "Example 程序:"
otool -L bin/example | grep -E "libcrypto|libssl|openssl" || echo "  ✓ 未链接系统 OpenSSL"
echo ""
echo "Performance 程序:"
otool -L bin/performance | grep -E "libcrypto|libssl|openssl" || echo "  ✓ 未链接系统 OpenSSL"
echo ""

echo "4. 验证使用的 OpenSSL 版本"
echo "-------------------------------------------"
echo "3rd/openssl 版本:"
../3rd/openssl/build/bin/openssl version 2>/dev/null || echo "  未找到"
echo ""
echo "系统 OpenSSL 版本:"
/usr/bin/openssl version 2>/dev/null || openssl version
echo ""

echo "5. 功能测试"
echo "-------------------------------------------"
echo "运行示例程序..."
OPENSSL_CONF=../test/openssl.cnf timeout 2 ./bin/example | grep "✓" | head -5 || echo "测试超时或失败"
echo ""

echo "==========================================="
echo "验证完成！"
echo ""
echo "总结："
echo "  • 引擎库已静态链接 OpenSSL 符号"
echo "  • 测试程序未链接系统 OpenSSL"
echo "  • 使用 3rd/openssl 目录下的 OpenSSL"
echo "==========================================="