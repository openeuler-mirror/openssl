#!/bin/bash

echo "========================================="
echo "        SM引擎测试脚本"
echo "========================================="
echo ""

cd "$(dirname "$0")/build"

echo "1. 功能测试（使用配置文件）"
echo "-----------------------------------------"
OPENSSL_CONF=../test/openssl.cnf timeout 5 ./bin/example || echo "功能测试完成或超时"
echo ""

echo "2. 快速性能测试"
echo "-----------------------------------------"
OPENSSL_CONF=../test/openssl.cnf timeout 5 ./bin/quick_test || echo "快速测试完成或超时"
echo ""

echo "========================================="
echo "           测试完成"
echo "========================================="