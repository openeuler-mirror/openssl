#!/bin/bash

# Build script for SM Engine
# This script provides an alternative to Makefile for building the engine

set -e

# Configuration (can be overridden by CLI flags)
CC="gcc"
CFLAGS="-Wall -Wextra -O2 -fPIC -std=c99"
# Debug flag
DEBUG=0
# Engine OpenSSL include/lib options
ENGINE_INCLUDE_DIRS=()
ENGINE_LIB_PATH=""
# App (test/example) OpenSSL
APP_INCLUDE_DIRS=()
APP_SO_DIR=""
# Optional env: OPENSSL_INCLUDE (space-separated), OPENSSL_LIB_PATH (file)

# Directories
SRC_DIR="src"
BUILD_DIR="build"
INSTALL_DIR="/usr/local/lib/engines"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Functions
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Parse CLI options
parse_args() {
    POSITIONAL=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            build|install|uninstall|clean|test|all|help|-h|--help)
                POSITIONAL+=("$1")
                shift
                ;;
            -oi|--openssl-include)
                ENGINE_INCLUDE_DIRS+=("$2"); shift 2 ;;
            -ol|--openssl-lib-path)
                ENGINE_LIB_PATH="$2"; shift 2 ;;
            -ei|--engine-include)
                ENGINE_INCLUDE_DIRS+=("$2"); shift 2 ;;
            -el|--engine-lib-path)
                ENGINE_LIB_PATH="$2"; shift 2 ;;
            -ai|--app-include)
                APP_INCLUDE_DIRS+=("$2"); shift 2 ;;
            -sd|--so-dir)
                APP_SO_DIR="$2"; shift 2 ;;
            --cc)
                CC="$2"; shift 2 ;;
            --cflags)
                CFLAGS="$2"; shift 2 ;;
            -d|--debug)
                DEBUG=1; shift ;;
            *)
                print_warning "Unknown option: $1"; POSITIONAL+=("$1"); shift ;;
        esac
    done
    set -- "${POSITIONAL[@]}"
    CMD="${1:-build}"
}

# Compute include/link flags from arrays
compute_flags() {
    ENGINE_INCLUDES=""
    for d in "${ENGINE_INCLUDE_DIRS[@]}"; do ENGINE_INCLUDES+=" -I$d"; done
    APP_INCLUDES=""
    for d in "${APP_INCLUDE_DIRS[@]}"; do APP_INCLUDES+=" -I$d"; done
    # Apply debug flags if requested
    if [[ "$DEBUG" -eq 1 ]]; then
        # Remove any existing -O* and add -g -O0
        CFLAGS="$(echo "$CFLAGS" | sed -E 's/ -O[0-9s]?//g') -g -O0"
    fi
    # LDFLAGS for engine: platform specific symbol control
    if [[ "$(uname)" == "Darwin" ]]; then
        if [[ -f exported.symbols ]]; then
            LDFLAGS_ENGINE="-shared -fPIC -Wl,-exported_symbols_list,exported.symbols"
        else
            LDFLAGS_ENGINE="-shared -fPIC"
        fi
    else
        if [[ -f sm_engine.syms ]]; then
            LDFLAGS_ENGINE="-shared -fPIC -Wl,--version-script=sm_engine.syms"
        else
            LDFLAGS_ENGINE="-shared -fPIC"
        fi
    fi
}

# Create build directory
create_build_dir() {
    if [ ! -d "$BUILD_DIR" ]; then
        print_info "Creating build directory..."
        mkdir -p "$BUILD_DIR"
    fi
}

# Compile source files (engine)
compile_sources() {
    print_info "Compiling source files..."
    
    for src_file in "$SRC_DIR"/*.c; do
        if [ -f "$src_file" ]; then
            obj_file="$BUILD_DIR/$(basename "${src_file%.c}.o")"
            print_info "Compiling $src_file -> $obj_file"
            $CC $CFLAGS $ENGINE_INCLUDES -c "$src_file" -o "$obj_file"
        fi
    done
}

# Link the engine
link_engine() {
    print_info "Linking engine..."
    
    OBJECTS="$BUILD_DIR"/*.o
    TARGET="$BUILD_DIR/libsm_engine.so"
    CMDLINE="$CC $LDFLAGS_ENGINE -o \"$TARGET\" $OBJECTS"
    # Prefer static lib path if provided, else rely on -l flags
    if [[ -n "$ENGINE_LIB_PATH" ]]; then
        CMDLINE+=" $ENGINE_LIB_PATH"
    fi
    # No global fallback; rely only on explicit -ol/--openssl-lib-path
    eval "$CMDLINE"
    print_info "Engine built: $TARGET"
}

# Install the engine
install_engine() {
    if [ ! -f "$BUILD_DIR/libsm_engine.so" ]; then
        print_error "Engine not built. Run build first."
        exit 1
    fi
    
    print_info "Installing engine to $INSTALL_DIR..."
    
    if [ ! -d "$INSTALL_DIR" ]; then
        print_info "Creating engine directory..."
        sudo mkdir -p "$INSTALL_DIR"
    fi
    
    sudo cp "$BUILD_DIR/libsm_engine.so" "$INSTALL_DIR/"
    sudo chmod 755 "$INSTALL_DIR/libsm_engine.so"
    print_info "Engine installed successfully"
}

# Uninstall the engine
uninstall_engine() {
    print_info "Uninstalling engine..."
    
    if [ -f "$INSTALL_DIR/libsm_engine.so" ]; then
        sudo rm -f "$INSTALL_DIR/libsm_engine.so"
        print_info "Engine uninstalled"
    else
        print_warning "Engine not found in $INSTALL_DIR"
    fi
}

# Clean build artifacts
clean_build() {
    print_info "Cleaning build artifacts..."
    rm -rf "$BUILD_DIR"
    :
    print_info "Build artifacts cleaned"
}

# Test the engine
test_engine() {
    if [ ! -f "$BUILD_DIR/libsm_engine.so" ]; then
        print_error "Engine not built. Run build first."
        exit 1
    fi
    
    print_info "Testing engine..."
    
    # Create test directory if it doesn't exist
    if [ ! -d "test" ]; then
        mkdir -p test
    fi
    
    # Run example if present
    if [ -f "$BUILD_DIR/example" ]; then
        print_info "Running example..."
        "$BUILD_DIR/example"
    else
        print_warning "Example executable not found. Run 'build' first to generate it."
    fi
}

# Build example program (optional)
build_example() {
    if [ -f "test/example.c" ]; then
        print_info "Building test/example..."
        local OUT="$BUILD_DIR/example"
        CMDLINE="$CC $CFLAGS $APP_INCLUDES -o $OUT test/example.c -L$BUILD_DIR -lsm_engine"
        if [[ -n "$APP_SO_DIR" ]]; then
            CMDLINE+=" -L$APP_SO_DIR -lcrypto"
        fi
        eval "$CMDLINE"
        print_info "Example built: $OUT"
    fi
}

# Show usage
show_usage() {
    echo "Usage: $0 [COMMAND] [options]"
    echo ""
    echo "Commands:"
    echo "  build      - Build the engine"
    echo "  install    - Install the engine"
    echo "  uninstall  - Uninstall the engine"
    echo "  clean      - Clean build artifacts"
    echo "  test       - Test the engine"
    echo "  all        - Build, install, and test"
    echo "  help       - Show this help"
    echo ""
    echo "Options:"
    echo "  -oi, --openssl-include DIR    Include dir(s) for engine compile (repeatable)"
    echo "  -ol, --openssl-lib-path FILE  OpenSSL lib path for engine link (e.g., libcrypto.a)"
    echo "  -ei, --engine-include DIR     (deprecated) same as --openssl-include"
    echo "  -el, --engine-lib-path FILE   (deprecated) same as --openssl-lib-path"
    echo "  -ai, --app-include DIR        Add include dir for app compile (repeatable)"
    echo "  -sd, --so-dir DIR             Directory containing libcrypto.so for app link"
    echo "      --cc CC                   Override compiler"
    echo "      --cflags '...'           Override CFLAGS"
}

# Main script
main() {
    parse_args "$@"
    compute_flags
    case "$CMD" in
        "build")
            create_build_dir
            compile_sources
            link_engine
            build_example
            ;;
        "install")
            install_engine
            ;;
        "uninstall")
            uninstall_engine
            ;;
        "clean")
            clean_build
            ;;
        "test")
            test_engine
            ;;
        "all")
            create_build_dir
            compile_sources
            link_engine
            build_example
            install_engine
            test_engine
            ;;
        "help"|"-h"|"--help")
            show_usage
            ;;
        *)
            print_error "Unknown command: $1"
            show_usage
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"