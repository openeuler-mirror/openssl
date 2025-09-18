#!/bin/bash

# Run AddressSanitizer tests for SM Engine
# This script compiles and runs tests with ASAN enabled

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}SM Engine AddressSanitizer Test Runner${NC}"
echo "========================================"
echo ""

# Check if we're in the right directory
if [ ! -f "src/sm_engine.c" ]; then
    echo -e "${RED}Error: Must run from sm-engine root directory${NC}"
    exit 1
fi

# Parse command line arguments
OPENSSL_INCLUDE=""
OPENSSL_LIB=""
DEBUG=0
VERBOSE=0

while [[ $# -gt 0 ]]; do
    case $1 in
        -oi|--openssl-include)
            OPENSSL_INCLUDE="$2"
            shift 2
            ;;
        -ol|--openssl-lib)
            OPENSSL_LIB="$2"
            shift 2
            ;;
        -d|--debug)
            DEBUG=1
            shift
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  -oi, --openssl-include DIR   OpenSSL include directory"
            echo "  -ol, --openssl-lib PATH       OpenSSL library path (libcrypto.a)"
            echo "  -d, --debug                   Enable debug output"
            echo "  -v, --verbose                 Enable verbose ASAN output"
            echo "  -h, --help                    Show this help message"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Set default paths if not provided
if [ -z "$OPENSSL_INCLUDE" ]; then
    if [ -d "3rd/openssl/include" ]; then
        OPENSSL_INCLUDE="3rd/openssl/include"
    else
        OPENSSL_INCLUDE="/usr/local/include"
    fi
fi

if [ -z "$OPENSSL_LIB" ]; then
    if [ -f "3rd/openssl/libcrypto.a" ]; then
        OPENSSL_LIB="3rd/openssl/libcrypto.a"
    else
        OPENSSL_LIB="-lcrypto"
    fi
fi

echo "Configuration:"
echo "  OpenSSL Include: $OPENSSL_INCLUDE"
echo "  OpenSSL Library: $OPENSSL_LIB"
echo ""

# Determine platform
PLATFORM=$(uname -s)
echo "Platform: $PLATFORM"
echo ""

# Check for compiler with ASAN support
CC=${CC:-gcc}
if ! command -v $CC &> /dev/null; then
    CC=clang
fi

if ! command -v $CC &> /dev/null; then
    echo -e "${RED}Error: No suitable compiler found (tried gcc and clang)${NC}"
    exit 1
fi

echo "Compiler: $CC"

# Check if compiler supports ASAN
echo -n "Checking ASAN support... "
if echo "int main(){return 0;}" | $CC -fsanitize=address -x c - -o /dev/null 2>/dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
    echo -e "${RED}Error: Compiler does not support AddressSanitizer${NC}"
    echo "Try installing clang or a newer version of gcc"
    exit 1
fi
echo ""

# Build the engine with ASAN if not already built
ENGINE_LIB="build/libsm_engine.so"
if [ ! -f "$ENGINE_LIB" ]; then
    echo -e "${YELLOW}Engine not found, building with ASAN...${NC}"

    # Create build directory
    mkdir -p build

    # Compile flags for ASAN
    CFLAGS="-fPIC -Wall -Wextra -g -O0 -fsanitize=address -fno-omit-frame-pointer"
    if [ $DEBUG -eq 1 ]; then
        CFLAGS="$CFLAGS -DSM_ENGINE_DEBUG"
    fi

    # Platform-specific linking
    if [ "$PLATFORM" = "Darwin" ]; then
        LDFLAGS="-dynamiclib -Wl,-exported_symbols_list,exported.symbols"
        ENGINE_EXT="dylib"
    else
        LDFLAGS="-shared -Wl,--version-script=sm_engine.syms"
        ENGINE_EXT="so"
    fi

    LDFLAGS="$LDFLAGS -fsanitize=address"

    # Build command
    BUILD_CMD="$CC $CFLAGS -I$OPENSSL_INCLUDE \
        src/sm_engine.c src/sm3.c src/sm4.c \
        -o build/libsm_engine.$ENGINE_EXT \
        $LDFLAGS $OPENSSL_LIB -ldl"

    echo "Build command:"
    echo "$BUILD_CMD"
    echo ""

    if $BUILD_CMD; then
        echo -e "${GREEN}Engine built successfully with ASAN${NC}"
    else
        echo -e "${RED}Failed to build engine${NC}"
        exit 1
    fi

    ENGINE_LIB="build/libsm_engine.$ENGINE_EXT"
else
    echo -e "${GREEN}Using existing engine: $ENGINE_LIB${NC}"
fi
echo ""

# Compile the ASAN test program
echo "Building ASAN test program..."
TEST_CFLAGS="-g -O0 -fsanitize=address -fno-omit-frame-pointer"
if [ $DEBUG -eq 1 ]; then
    TEST_CFLAGS="$TEST_CFLAGS -DDEBUG"
fi

TEST_BUILD_CMD="$CC $TEST_CFLAGS -I$OPENSSL_INCLUDE \
    test/test_asan.c \
    -o build/test_asan \
    -fsanitize=address $OPENSSL_LIB -ldl"

echo "Test build command:"
echo "$TEST_BUILD_CMD"
echo ""

if $TEST_BUILD_CMD; then
    echo -e "${GREEN}Test program built successfully${NC}"
else
    echo -e "${RED}Failed to build test program${NC}"
    exit 1
fi
echo ""

# Set up environment for running tests
export OPENSSL_ENGINES=$(pwd)/build
export ASAN_OPTIONS="detect_leaks=1:check_initialization_order=1:strict_string_checks=1:print_stats=1"

if [ $VERBOSE -eq 1 ]; then
    export ASAN_OPTIONS="$ASAN_OPTIONS:verbosity=1"
fi

# Additional ASAN options for better debugging
export ASAN_SYMBOLIZER_PATH=$(which llvm-symbolizer 2>/dev/null || which addr2line 2>/dev/null)

echo "Environment:"
echo "  OPENSSL_ENGINES=$OPENSSL_ENGINES"
echo "  ASAN_OPTIONS=$ASAN_OPTIONS"
if [ -n "$ASAN_SYMBOLIZER_PATH" ]; then
    echo "  ASAN_SYMBOLIZER_PATH=$ASAN_SYMBOLIZER_PATH"
fi
echo ""

# Run the tests
echo -e "${YELLOW}Running ASAN tests...${NC}"
echo "========================================"
echo ""

if ./build/test_asan; then
    EXIT_CODE=$?
    echo ""
    echo -e "${GREEN}========================================"
    echo -e "ASAN tests completed successfully"
    echo -e "========================================${NC}"
else
    EXIT_CODE=$?
    echo ""
    echo -e "${RED}========================================"
    echo -e "ASAN tests failed with exit code: $EXIT_CODE"
    echo -e "========================================${NC}"
fi

# Check for ASAN output
if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo -e "${YELLOW}Note: Check above for AddressSanitizer reports${NC}"
    echo "Common issues detected by ASAN:"
    echo "  - Heap buffer overflow"
    echo "  - Stack buffer overflow"
    echo "  - Use after free"
    echo "  - Memory leaks"
    echo "  - Double free"
fi

exit $EXIT_CODE