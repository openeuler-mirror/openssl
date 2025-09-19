cmake_minimum_required(VERSION 3.11)  # 3.11 required for FetchContent
project(sm_engine VERSION 1.0.0 LANGUAGES C)

# Set C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Include required modules
include(ExternalProject)
include(ProcessorCount)

# Options
option(BUILD_SHARED_LIBS "Build shared libraries" ON)
option(BUILD_TESTS "Build test programs" ON)
option(BUILD_EXAMPLES "Build example programs" ON)
option(ENABLE_DEBUG "Enable debug build" OFF)
option(ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(ENABLE_VALGRIND "Enable Valgrind memory checks" OFF)
option(AUTO_BUILD_OPENSSL "Automatically build OpenSSL if not found" ON)

# Set default build type if not specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose the type of build." FORCE)
endif()

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -fPIC")
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")

# AddressSanitizer configuration
if(ENABLE_ASAN)
    # Simply check if we can compile with ASAN flags
    # Modern compilers (GCC 4.8+, Clang 3.1+, AppleClang) support ASAN
    if(CMAKE_C_COMPILER_ID MATCHES "GNU")
        if(CMAKE_C_COMPILER_VERSION VERSION_LESS "4.8")
            message(FATAL_ERROR "GCC ${CMAKE_C_COMPILER_VERSION} does not support AddressSanitizer. Requires GCC 4.8+")
        endif()
    elseif(CMAKE_C_COMPILER_ID MATCHES "Clang")
        if(CMAKE_C_COMPILER_VERSION VERSION_LESS "3.1")
            message(FATAL_ERROR "Clang ${CMAKE_C_COMPILER_VERSION} does not support AddressSanitizer. Requires Clang 3.1+")
        endif()
    elseif(NOT CMAKE_C_COMPILER_ID MATCHES "AppleClang")
        message(WARNING "Unknown compiler ${CMAKE_C_COMPILER_ID}. ASAN support may not work.")
    endif()

    # ASAN flags
    set(ASAN_FLAGS "-fsanitize=address -fno-omit-frame-pointer -g -O1")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${ASAN_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${ASAN_FLAGS}")

    # Linker flags for ASAN
    if(APPLE)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
        set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fsanitize=address")
    else()
        # On Linux, use static ASAN for better compatibility
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address -static-libasan")
        set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fsanitize=address")
    endif()

    # Mutual exclusivity with Valgrind
    if(ENABLE_VALGRIND)
        message(FATAL_ERROR "Cannot enable both ASAN and Valgrind")
    endif()

    message(STATUS "AddressSanitizer enabled")
endif()

# Set output directories for out-of-source build
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Determine number of cores for parallel build
ProcessorCount(NPROC)
if(NPROC EQUAL 0)
    set(NPROC 4)
endif()

# Git submodule auto-initialization
find_package(Git QUIET)
if(GIT_FOUND)
    message(STATUS "Checking git submodules...")
    execute_process(
        COMMAND ${GIT_EXECUTABLE} submodule status 3rd/openssl
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_SUBMODULE_STATUS
        RESULT_VARIABLE GIT_SUBMOD_RESULT
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    # Check if submodule needs initialization (status starts with -)
    if(GIT_SUBMOD_RESULT OR "${GIT_SUBMODULE_STATUS}" MATCHES "^-")
        message(STATUS "Initializing git submodule 3rd/openssl...")
        execute_process(
            COMMAND ${GIT_EXECUTABLE} submodule update --init 3rd/openssl
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            RESULT_VARIABLE GIT_SUBMOD_RESULT
        )
        if(GIT_SUBMOD_RESULT)
            message(WARNING "Failed to initialize git submodule. Will attempt to continue anyway.")
        endif()
    endif()
endif()

# OpenSSL configuration - use the one from 3rd/openssl
# IMPORTANT: We explicitly use the OpenSSL from 3rd/openssl, NOT the system OpenSSL
set(OPENSSL_ROOT_DIR "${CMAKE_SOURCE_DIR}/3rd/openssl" CACHE PATH "Path to OpenSSL root directory")
set(OPENSSL_BUILD_DIR "${CMAKE_BINARY_DIR}/openssl-build" CACHE PATH "OpenSSL build directory")
set(OPENSSL_INSTALL_DIR "${CMAKE_BINARY_DIR}/openssl-install" CACHE PATH "OpenSSL install directory")

# Prevent CMake from finding system OpenSSL
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE NEVER)
unset(OPENSSL_INCLUDE_DIR CACHE)
unset(OPENSSL_SSL_LIBRARY CACHE)
unset(OPENSSL_CRYPTO_LIBRARY CACHE)

# Function to check if OpenSSL is built
function(check_openssl_built)
    if(EXISTS "${OPENSSL_INSTALL_DIR}/lib/libcrypto.a")
        set(OPENSSL_FOUND TRUE PARENT_SCOPE)
        set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_INSTALL_DIR}/lib/libcrypto.a" CACHE FILEPATH "Path to OpenSSL crypto library" FORCE)
        set(OPENSSL_INCLUDE_DIR "${OPENSSL_INSTALL_DIR}/include" CACHE PATH "Path to OpenSSL include directory" FORCE)
    elseif(EXISTS "${OPENSSL_ROOT_DIR}/build/lib/libcrypto.a")
        set(OPENSSL_FOUND TRUE PARENT_SCOPE)
        set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_ROOT_DIR}/build/lib/libcrypto.a" CACHE FILEPATH "Path to OpenSSL crypto library" FORCE)
        set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/build/include" CACHE PATH "Path to OpenSSL include directory" FORCE)
    elseif(EXISTS "${OPENSSL_ROOT_DIR}/libcrypto.a")
        set(OPENSSL_FOUND TRUE PARENT_SCOPE)
        set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_ROOT_DIR}/libcrypto.a" CACHE FILEPATH "Path to OpenSSL crypto library" FORCE)
        set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include" CACHE PATH "Path to OpenSSL include directory" FORCE)
    else()
        set(OPENSSL_FOUND FALSE PARENT_SCOPE)
    endif()
endfunction()

# Check if OpenSSL is already built
check_openssl_built()

if(NOT OPENSSL_FOUND AND AUTO_BUILD_OPENSSL)
    message(STATUS "OpenSSL not found. Building OpenSSL as external project...")

    # Check if OpenSSL source exists
    if(NOT EXISTS "${OPENSSL_ROOT_DIR}/Configure")
        message(FATAL_ERROR "OpenSSL source not found at ${OPENSSL_ROOT_DIR}. "
                           "Please ensure git submodule is initialized:\n"
                           "  git submodule update --init 3rd/openssl")
    endif()

    # Configure OpenSSL build command based on platform
    if(APPLE)
        # Detect architecture on macOS
        execute_process(
            COMMAND uname -m
            OUTPUT_VARIABLE APPLE_ARCH
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        if(APPLE_ARCH STREQUAL "arm64")
            set(OPENSSL_CONFIGURE_COMMAND ./Configure darwin64-arm64-cc)
        else()
            set(OPENSSL_CONFIGURE_COMMAND ./Configure darwin64-x86_64-cc)
        endif()
        message(STATUS "Detected macOS architecture: ${APPLE_ARCH}")
    else()
        set(OPENSSL_CONFIGURE_COMMAND ./config)
    endif()

    # Add OpenSSL as external project (OpenSSL requires in-source build)
    ExternalProject_Add(
        openssl_external
        SOURCE_DIR ${OPENSSL_ROOT_DIR}
        INSTALL_DIR ${OPENSSL_INSTALL_DIR}
        CONFIGURE_COMMAND ${CMAKE_COMMAND} -E chdir ${OPENSSL_ROOT_DIR}
            ${OPENSSL_CONFIGURE_COMMAND}
            --prefix=${OPENSSL_INSTALL_DIR}
            no-shared
            no-tests
        BUILD_COMMAND ${CMAKE_COMMAND} -E chdir ${OPENSSL_ROOT_DIR}
            make -j${NPROC}
        BUILD_IN_SOURCE 1
        INSTALL_COMMAND ${CMAKE_COMMAND} -E chdir ${OPENSSL_ROOT_DIR}
            make install_sw
        BUILD_BYPRODUCTS
            ${OPENSSL_INSTALL_DIR}/lib/libcrypto.a
            ${OPENSSL_INSTALL_DIR}/include/openssl/engine.h
    )

    # Set OpenSSL paths after build
    set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_INSTALL_DIR}/lib/libcrypto.a" CACHE FILEPATH "Path to OpenSSL crypto library" FORCE)
    set(OPENSSL_INCLUDE_DIR "${OPENSSL_INSTALL_DIR}/include" CACHE PATH "Path to OpenSSL include directory" FORCE)
    set(OPENSSL_BUILD_REQUIRED TRUE)

    message(STATUS "OpenSSL will be built to: ${OPENSSL_INSTALL_DIR}")
    message(STATUS "Using ${NPROC} parallel jobs for OpenSSL build")
elseif(NOT OPENSSL_FOUND)
    message(FATAL_ERROR "OpenSSL libcrypto.a not found and AUTO_BUILD_OPENSSL is disabled.\n"
                        "Either enable AUTO_BUILD_OPENSSL or build OpenSSL manually:\n"
                        "  cd ${OPENSSL_ROOT_DIR}\n"
                        "  ./config --prefix=\${PWD}/build\n"
                        "  make -j4\n"
                        "  make install_sw")
else()
    message(STATUS "Found existing OpenSSL:")
    message(STATUS "  Include: ${OPENSSL_INCLUDE_DIR}")
    message(STATUS "  Library: ${OPENSSL_CRYPTO_LIBRARY}")
    set(OPENSSL_BUILD_REQUIRED FALSE)
endif()

# Platform-specific symbol export settings
if(APPLE)
    set(SYMBOL_EXPORT_FILE "${CMAKE_SOURCE_DIR}/exported.symbols")
    if(NOT EXISTS ${SYMBOL_EXPORT_FILE})
        # Create exported.symbols file if it doesn't exist
        file(WRITE ${SYMBOL_EXPORT_FILE} "_bind_engine\n_v_check\n")
    endif()
    set(SYMBOL_EXPORT_FLAGS "-Wl,-exported_symbols_list,${SYMBOL_EXPORT_FILE}")
else()
    set(SYMBOL_EXPORT_FILE "${CMAKE_SOURCE_DIR}/sm_engine.syms")
    if(EXISTS ${SYMBOL_EXPORT_FILE})
        set(SYMBOL_EXPORT_FLAGS "-Wl,--version-script=${SYMBOL_EXPORT_FILE}")
    endif()
endif()

# Installation directories
include(GNUInstallDirs)
set(ENGINE_INSTALL_DIR "${CMAKE_INSTALL_LIBDIR}/engines" CACHE PATH "Installation directory for OpenSSL engines")

# Enable testing
if(BUILD_TESTS)
    enable_testing()
endif()

# Add subdirectories
add_subdirectory(src)

if(BUILD_TESTS)
    add_subdirectory(test)
endif()

# Create uninstall target
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)

add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)

# Print configuration summary
message(STATUS "")
message(STATUS "=====================================")
message(STATUS "SM Engine Configuration:")
message(STATUS "=====================================")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  Compiler: ${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}")
message(STATUS "  Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "  Engine install dir: ${CMAKE_INSTALL_PREFIX}/${ENGINE_INSTALL_DIR}")
message(STATUS "  Build tests: ${BUILD_TESTS}")
message(STATUS "  Build examples: ${BUILD_EXAMPLES}")
message(STATUS "  Build shared libs: ${BUILD_SHARED_LIBS}")
message(STATUS "  Symbol export: ${SYMBOL_EXPORT_FILE}")
message(STATUS "")
message(STATUS "Sanitizers:")
message(STATUS "  AddressSanitizer: ${ENABLE_ASAN}")
message(STATUS "  Valgrind support: ${ENABLE_VALGRIND}")
message(STATUS "")
message(STATUS "Build Commands:")
message(STATUS "  Regular build:")
message(STATUS "    mkdir build && cd build")
message(STATUS "    cmake ..")
message(STATUS "    make")
message(STATUS "")
message(STATUS "  ASAN build:")
message(STATUS "    mkdir build-asan && cd build-asan")
message(STATUS "    cmake .. -DENABLE_ASAN=ON")
message(STATUS "    make")
message(STATUS "    make run_asan_tests")
message(STATUS "")
message(STATUS "  Install:")
message(STATUS "    sudo make install")
message(STATUS "=====================================")
