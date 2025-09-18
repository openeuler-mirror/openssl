#!/bin/bash

# 性能测试运行脚本

cd "$(dirname "$0")"

# 设置配置文件
export OPENSSL_CONF=test/openssl.cnf

echo "运行SM引擎性能测试..."
echo "========================"

# 运行性能测试（仅测试1秒以快速完成）
timeout 30 ./build/bin/performance -c || {
    echo ""
    echo "性能测试运行超时或失败"
    echo "尝试不使用引擎运行："
    ./build/bin/performance
}

echo ""
echo "测试完成！"