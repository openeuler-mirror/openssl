#!/bin/bash
# OpenSSL speed test script for SM engine
# Usage: ./openssl_speed_test.sh

set -e

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Detect OS for library extension
if [[ "$OSTYPE" == "darwin"* ]]; then
    LIB_EXT="dylib"
else
    LIB_EXT="so"
fi

# Find OpenSSL binary - prefer locally built one
OPENSSL_BIN=""
if [ -f "$SCRIPT_DIR/build/openssl-install/bin/openssl" ]; then
    OPENSSL_BIN="$SCRIPT_DIR/build/openssl-install/bin/openssl"
    echo "Using locally built OpenSSL"
else
    OPENSSL_BIN="openssl"
    echo "Using system OpenSSL"
fi

# Check library exists
if [ ! -f "$SCRIPT_DIR/build/lib/libsm_engine.$LIB_EXT" ]; then
    echo "Error: SM engine library not found at $SCRIPT_DIR/build/lib/libsm_engine.$LIB_EXT"
    echo "Please build the engine first: mkdir build && cd build && cmake .. && make"
    exit 1
fi

# Display configuration
echo "=========================================="
echo " SM Engine OpenSSL Speed Test"
echo "=========================================="
echo "OpenSSL binary: $OPENSSL_BIN"
echo "Engine library: $SCRIPT_DIR/build/lib/libsm_engine.$LIB_EXT"
echo "=========================================="
echo ""

# Set up configuration and environment
if [ -d "$SCRIPT_DIR/build/openssl-install" ]; then
    # We have locally built OpenSSL - use it with relative paths

    # Create config directory if needed
    mkdir -p "$SCRIPT_DIR/build/openssl-install/ssl"

    # Generate configuration file with relative paths
    cat > "$SCRIPT_DIR/build/openssl-install/ssl/openssl.cnf" <<EOF
# Auto-generated OpenSSL Engine Configuration
openssl_conf = openssl_init

[openssl_init]
engines = engine_section

[engine_section]
sm_ce_engine = sm_section

[sm_section]
engine_id = sm_ce_engine
# Relative path from ssl directory to lib directory
dynamic_path = ../../lib/libsm_engine.$LIB_EXT
init = 1
default_algorithms = DIGESTS,CIPHERS
EOF

    # Set environment
    export OPENSSL_CONF="$SCRIPT_DIR/build/openssl-install/ssl/openssl.cnf"
    export OPENSSL_ENGINES="$SCRIPT_DIR/build/lib"

    # Set library paths
    export LD_LIBRARY_PATH="$SCRIPT_DIR/build/lib:$SCRIPT_DIR/build/openssl-install/lib:$LD_LIBRARY_PATH"
    export DYLD_LIBRARY_PATH="$SCRIPT_DIR/build/lib:$SCRIPT_DIR/build/openssl-install/lib:$DYLD_LIBRARY_PATH"

    # Change to ssl directory for relative paths to work
    cd "$SCRIPT_DIR/build/openssl-install/ssl"
else
    # No local OpenSSL build - use absolute paths
    echo "Warning: No local OpenSSL build found, using system OpenSSL"

    # Create temporary config with absolute paths
    TEMP_CONF="/tmp/sm_engine_$$.cnf"
    cat > "$TEMP_CONF" <<EOF
# Temporary OpenSSL Engine Configuration
openssl_conf = openssl_init

[openssl_init]
engines = engine_section

[engine_section]
sm_ce_engine = sm_section

[sm_section]
engine_id = sm_ce_engine
dynamic_path = $SCRIPT_DIR/build/lib/libsm_engine.$LIB_EXT
init = 1
default_algorithms = DIGESTS,CIPHERS
EOF

    export OPENSSL_CONF="$TEMP_CONF"
    export OPENSSL_ENGINES="$SCRIPT_DIR/build/lib"

    # Cleanup function
    trap "rm -f $TEMP_CONF" EXIT
fi

# Check if engine is available
echo "Checking engine availability..."
$OPENSSL_BIN engine -t sm_ce_engine
if [ $? -ne 0 ]; then
    echo "Error: SM engine not available"
    exit 1
fi
echo ""

# Run SM3 speed test
echo "=========================================="
echo " SM3 Hash Performance Test"
echo "=========================================="
$OPENSSL_BIN speed -engine sm_ce_engine -evp sm3
echo ""

# Run SM4-ECB speed test
echo "=========================================="
echo " SM4-ECB Encryption Performance Test"
echo "=========================================="
$OPENSSL_BIN speed -engine sm_ce_engine -evp sm4-ecb
echo ""

# Run SM4-CBC speed test
echo "=========================================="
echo " SM4-CBC Encryption Performance Test"
echo "=========================================="
$OPENSSL_BIN speed -engine sm_ce_engine -evp sm4-cbc
echo ""

echo "=========================================="
echo " Test Complete"
echo "=========================================="