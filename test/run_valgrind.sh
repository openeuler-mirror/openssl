#!/bin/bash

# Run Valgrind memory checks for SM Engine
# This script runs the test program under Valgrind to detect memory issues

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}SM Engine Valgrind Memory Check${NC}"
echo "================================"
echo ""

# Check if we're in the right directory
if [ ! -f "src/sm_engine.c" ]; then
    echo -e "${RED}Error: Must run from sm-engine root directory${NC}"
    exit 1
fi

# Check if Valgrind is installed
if ! command -v valgrind &> /dev/null; then
    echo -e "${RED}Error: Valgrind is not installed${NC}"
    echo "Install with:"
    echo "  Ubuntu/Debian: sudo apt-get install valgrind"
    echo "  RHEL/CentOS: sudo yum install valgrind"
    echo "  macOS: brew install valgrind (Note: may not work on Apple Silicon)"
    exit 1
fi

echo "Valgrind version:"
valgrind --version
echo ""

# Parse command line arguments
OPENSSL_INCLUDE=""
OPENSSL_LIB=""
TEST_PROGRAM="example"
FULL_CHECK=0
SUPPRESSIONS=""

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
        -t|--test)
            TEST_PROGRAM="$2"
            shift 2
            ;;
        -f|--full)
            FULL_CHECK=1
            shift
            ;;
        -s|--suppressions)
            SUPPRESSIONS="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  -oi, --openssl-include DIR   OpenSSL include directory"
            echo "  -ol, --openssl-lib PATH       OpenSSL library path"
            echo "  -t, --test PROGRAM           Test program to run (default: example)"
            echo "  -f, --full                    Run full leak check (slower)"
            echo "  -s, --suppressions FILE       Valgrind suppressions file"
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
echo "  Test Program: $TEST_PROGRAM"
echo ""

# Determine platform
PLATFORM=$(uname -s)

# Build the engine without ASAN (Valgrind and ASAN don't mix well)
if [ ! -f "build/libsm_engine.so" ] && [ ! -f "build/libsm_engine.dylib" ]; then
    echo -e "${YELLOW}Building engine for Valgrind testing...${NC}"
    ./build.sh build \
        -oi "$OPENSSL_INCLUDE" \
        -ol "$OPENSSL_LIB" \
        -ai "$OPENSSL_INCLUDE" \
        -al "$OPENSSL_LIB" \
        -d  # Debug build for better Valgrind output
fi

# Build test program if needed
TEST_BINARY="build/$TEST_PROGRAM"
if [ ! -f "$TEST_BINARY" ]; then
    if [ "$TEST_PROGRAM" = "example" ] && [ -f "test/example.c" ]; then
        echo -e "${YELLOW}Building example program...${NC}"
        ./build.sh test
    elif [ "$TEST_PROGRAM" = "test_asan" ] && [ -f "test/test_asan.c" ]; then
        echo -e "${YELLOW}Building test_asan program (without ASAN for Valgrind)...${NC}"
        gcc -g -O0 -I"$OPENSSL_INCLUDE" \
            test/test_asan.c \
            -o build/test_asan \
            $OPENSSL_LIB -ldl
    else
        echo -e "${RED}Error: Test program '$TEST_BINARY' not found${NC}"
        exit 1
    fi
fi

# Set up environment
export OPENSSL_ENGINES=$(pwd)/build

# Prepare Valgrind options
VALGRIND_OPTS="--leak-check=full"
VALGRIND_OPTS="$VALGRIND_OPTS --show-leak-kinds=all"
VALGRIND_OPTS="$VALGRIND_OPTS --track-origins=yes"
VALGRIND_OPTS="$VALGRIND_OPTS --verbose"
VALGRIND_OPTS="$VALGRIND_OPTS --log-file=valgrind.log"

if [ $FULL_CHECK -eq 1 ]; then
    VALGRIND_OPTS="$VALGRIND_OPTS --leak-check=full"
    VALGRIND_OPTS="$VALGRIND_OPTS --show-reachable=yes"
    VALGRIND_OPTS="$VALGRIND_OPTS --track-fds=yes"
fi

if [ -n "$SUPPRESSIONS" ] && [ -f "$SUPPRESSIONS" ]; then
    VALGRIND_OPTS="$VALGRIND_OPTS --suppressions=$SUPPRESSIONS"
fi

echo "Valgrind options:"
echo "  $VALGRIND_OPTS"
echo ""

# Run Valgrind
echo -e "${YELLOW}Running Valgrind memory check...${NC}"
echo "================================"
echo ""

valgrind $VALGRIND_OPTS "$TEST_BINARY"

EXIT_CODE=$?

# Analyze the results
echo ""
echo -e "${YELLOW}Analyzing Valgrind results...${NC}"
echo "================================"

if [ -f "valgrind.log" ]; then
    # Check for definitely lost memory
    DEFINITELY_LOST=$(grep "definitely lost:" valgrind.log | tail -1 | awk '{print $4}')
    INDIRECTLY_LOST=$(grep "indirectly lost:" valgrind.log | tail -1 | awk '{print $4}')
    POSSIBLY_LOST=$(grep "possibly lost:" valgrind.log | tail -1 | awk '{print $4}')
    REACHABLE=$(grep "still reachable:" valgrind.log | tail -1 | awk '{print $4}')

    echo "Memory leak summary:"
    echo "  Definitely lost: ${DEFINITELY_LOST:-0} bytes"
    echo "  Indirectly lost: ${INDIRECTLY_LOST:-0} bytes"
    echo "  Possibly lost: ${POSSIBLY_LOST:-0} bytes"
    echo "  Still reachable: ${REACHABLE:-0} bytes"
    echo ""

    # Check for errors
    ERROR_COUNT=$(grep "ERROR SUMMARY:" valgrind.log | tail -1 | awk '{print $4}')
    echo "Error count: ${ERROR_COUNT:-0}"
    echo ""

    # Display any error details
    if [ "${ERROR_COUNT:-0}" -gt 0 ]; then
        echo -e "${RED}Errors detected! Check valgrind.log for details${NC}"
        echo ""
        echo "First few errors:"
        grep -A 5 "Invalid" valgrind.log | head -20 || true
    else
        echo -e "${GREEN}No errors detected${NC}"
    fi

    # Check for leaks
    if [ "${DEFINITELY_LOST:-0}" = "0" ] && [ "${INDIRECTLY_LOST:-0}" = "0" ]; then
        echo -e "${GREEN}No definite memory leaks detected${NC}"
    else
        echo -e "${RED}Memory leaks detected! Check valgrind.log for details${NC}"
    fi

    echo ""
    echo "Full log saved to: valgrind.log"
else
    echo -e "${RED}Valgrind log file not found${NC}"
fi

exit $EXIT_CODE