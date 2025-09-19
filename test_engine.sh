#!/bin/bash
# Test script for SM Engine with automatic path configuration

# Detect OS and set library extension
if [[ "$OSTYPE" == "darwin"* ]]; then
    LIB_EXT="dylib"
else
    LIB_EXT="so"
fi

# Check if we're in build directory or source directory
if [ -f "./lib/libsm_engine.$LIB_EXT" ]; then
    # We're in build directory
    ENGINE_PATH="$(pwd)/lib/libsm_engine.$LIB_EXT"
elif [ -f "./build/lib/libsm_engine.$LIB_EXT" ]; then
    # We're in source directory
    ENGINE_PATH="$(pwd)/build/lib/libsm_engine.$LIB_EXT"
else
    echo "Error: Cannot find libsm_engine.$LIB_EXT"
    echo "Please run from build directory or source root"
    exit 1
fi

# Set up OpenSSL config for engine loading
if [ -f "./build/lib/libsm_engine.$LIB_EXT" ]; then
    # We're in source directory - set up config in build directory
    mkdir -p build/openssl-install/ssl

    # Copy platform-specific config
    if [[ "$OSTYPE" == "darwin"* ]]; then
        cp test/openssl_macos.cnf build/openssl-install/ssl/openssl.cnf
    else
        cp test/openssl_linux.cnf build/openssl-install/ssl/openssl.cnf
    fi

    # Update config with absolute path
    sed -i.bak "s|dynamic_path = ./lib/libsm_engine.$LIB_EXT|dynamic_path = $ENGINE_PATH|" build/openssl-install/ssl/openssl.cnf
    rm -f build/openssl-install/ssl/openssl.cnf.bak

    echo "✅ Engine config updated: build/openssl-install/ssl/openssl.cnf"
fi

echo "Using engine: $ENGINE_PATH"
echo ""

# Find and run test binary
if [ -f "./bin/quick_test" ]; then
    ./bin/quick_test
elif [ -f "./build/bin/quick_test" ]; then
    ./build/bin/quick_test
else
    echo "Error: Cannot find quick_test binary"
    echo "Please build the project first: mkdir build && cd build && cmake .. && make"
    exit 1
fi
