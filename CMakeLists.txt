cmake_minimum_required(VERSION 3.10)
project(sm_engine VERSION 1.0.0 LANGUAGES C)

# Set C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Options
option(BUILD_SHARED_LIBS "Build shared libraries" ON)
option(BUILD_TESTS "Build test programs" ON)
option(BUILD_EXAMPLES "Build example programs" ON)
option(ENABLE_DEBUG "Enable debug build" OFF)

# Set default build type if not specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose the type of build." FORCE)
endif()

# Compiler flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -fPIC")
set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG")

# Set output directories for out-of-source build
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# OpenSSL configuration - use the one from 3rd/openssl
# IMPORTANT: We explicitly use the OpenSSL from 3rd/openssl, NOT the system OpenSSL
set(OPENSSL_ROOT_DIR "${CMAKE_SOURCE_DIR}/3rd/openssl" CACHE PATH "Path to OpenSSL root directory")

# Prevent CMake from finding system OpenSSL
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE NEVER)
unset(OPENSSL_INCLUDE_DIR CACHE)
unset(OPENSSL_SSL_LIBRARY CACHE)
unset(OPENSSL_CRYPTO_LIBRARY CACHE)

# Check if OpenSSL is built
if(EXISTS "${OPENSSL_ROOT_DIR}/build/lib/libcrypto.a")
    set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_ROOT_DIR}/build/lib/libcrypto.a" CACHE FILEPATH "Path to OpenSSL crypto library" FORCE)
    set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/build/include" CACHE PATH "Path to OpenSSL include directory" FORCE)
elseif(EXISTS "${OPENSSL_ROOT_DIR}/libcrypto.a")
    set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_ROOT_DIR}/libcrypto.a" CACHE FILEPATH "Path to OpenSSL crypto library" FORCE)
    set(OPENSSL_INCLUDE_DIR "${OPENSSL_ROOT_DIR}/include" CACHE PATH "Path to OpenSSL include directory" FORCE)
else()
    message(FATAL_ERROR "OpenSSL libcrypto.a not found. Please build OpenSSL first:\n"
                        "  cd ${OPENSSL_ROOT_DIR}\n"
                        "  ./config --prefix=\${PWD}/build\n"
                        "  make -j4\n"
                        "  make install_sw")
endif()

# Check for OpenSSL headers
if(NOT EXISTS "${OPENSSL_INCLUDE_DIR}/openssl/engine.h")
    message(FATAL_ERROR "OpenSSL headers not found at ${OPENSSL_INCLUDE_DIR}")
endif()

message(STATUS "OpenSSL include: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL crypto library: ${OPENSSL_CRYPTO_LIBRARY}")

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
message(STATUS "SM Engine Configuration:")
message(STATUS "  Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  Install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "  Engine install dir: ${CMAKE_INSTALL_PREFIX}/${ENGINE_INSTALL_DIR}")
message(STATUS "  Build tests: ${BUILD_TESTS}")
message(STATUS "  Build examples: ${BUILD_EXAMPLES}")
message(STATUS "  Symbol export: ${SYMBOL_EXPORT_FILE}")
message(STATUS "")
message(STATUS "Build with:")
message(STATUS "  mkdir build && cd build")
message(STATUS "  cmake ..")
message(STATUS "  make")
message(STATUS "  sudo make install")