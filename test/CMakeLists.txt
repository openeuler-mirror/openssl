# Test programs for SM Engine

# Include directories for tests
include_directories(
    ${CMAKE_SOURCE_DIR}/src
    ${OPENSSL_INCLUDE_DIR}
)

# Example program
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/example.c)
    add_executable(example example.c)

    # Link with the engine and OpenSSL
    target_link_libraries(example
        sm_engine
        ${OPENSSL_CRYPTO_LIBRARY}
    )

    # Platform-specific libraries
    if(UNIX AND NOT APPLE)
        target_link_libraries(example dl pthread)
    endif()

    # Set runtime path for finding the engine library
    set_target_properties(example PROPERTIES
        INSTALL_RPATH_USE_LINK_PATH TRUE
        BUILD_RPATH "${CMAKE_BINARY_DIR}/lib"
    )

    # Add as a test
    add_test(NAME example_test
        COMMAND example
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )

    # Set environment for test to find the engine
    set_tests_properties(example_test PROPERTIES
        ENVIRONMENT "LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}/lib:$ENV{LD_LIBRARY_PATH}"
    )
endif()

# Performance test program
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/performance.c)
    add_executable(performance performance.c)

    target_link_libraries(performance
        sm_engine
        ${OPENSSL_CRYPTO_LIBRARY}
    )

    if(UNIX AND NOT APPLE)
        target_link_libraries(performance dl pthread)
    endif()

    set_target_properties(performance PROPERTIES
        INSTALL_RPATH_USE_LINK_PATH TRUE
        BUILD_RPATH "${CMAKE_BINARY_DIR}/lib"
    )

    add_test(NAME performance_test
        COMMAND performance
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )

    set_tests_properties(performance_test PROPERTIES
        ENVIRONMENT "LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}/lib:$ENV{LD_LIBRARY_PATH}"
    )
endif()

# Quick test program
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/quick_test.c)
    add_executable(quick_test quick_test.c)

    target_link_libraries(quick_test
        sm_engine
        ${OPENSSL_CRYPTO_LIBRARY}
    )

    if(UNIX AND NOT APPLE)
        target_link_libraries(quick_test dl pthread)
    endif()

    set_target_properties(quick_test PROPERTIES
        INSTALL_RPATH_USE_LINK_PATH TRUE
        BUILD_RPATH "${CMAKE_BINARY_DIR}/lib"
    )
endif()

# AddressSanitizer test program
if(ENABLE_ASAN AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/test_asan.c)
    add_executable(test_asan test_asan.c)

    # Include directories
    target_include_directories(test_asan PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${OPENSSL_INCLUDE_DIR}
    )

    # Link with the engine and OpenSSL
    target_link_libraries(test_asan
        sm_engine
        ${OPENSSL_CRYPTO_LIBRARY}
    )

    # Platform-specific libraries
    if(UNIX AND NOT APPLE)
        target_link_libraries(test_asan dl pthread)
    endif()

    # ASAN runtime already linked via CMAKE_EXE_LINKER_FLAGS

    # Set runtime path for finding the engine library
    set_target_properties(test_asan PROPERTIES
        INSTALL_RPATH_USE_LINK_PATH TRUE
        BUILD_RPATH "${CMAKE_BINARY_DIR}/lib"
    )

    # Add ASAN tests
    add_test(NAME asan_boundary_test
        COMMAND test_asan
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )

    # Configure ASAN environment for the test
    if(APPLE)
        set(ASAN_OPTIONS "detect_leaks=0:check_initialization_order=1:strict_string_checks=1:print_stats=1")
    else()
        set(ASAN_OPTIONS "detect_leaks=1:check_initialization_order=1:strict_string_checks=1:print_stats=1")
    endif()

    set_tests_properties(asan_boundary_test PROPERTIES
        ENVIRONMENT "OPENSSL_ENGINES=${CMAKE_BINARY_DIR}/lib:ASAN_OPTIONS=${ASAN_OPTIONS}"
        LABELS "sanitizer;asan"
        TIMEOUT 60
    )

    # Find symbolizer for better ASAN output
    if(NOT APPLE)
        find_program(LLVM_SYMBOLIZER llvm-symbolizer)
        if(LLVM_SYMBOLIZER)
            set_tests_properties(asan_boundary_test PROPERTIES
                ENVIRONMENT "ASAN_SYMBOLIZER_PATH=${LLVM_SYMBOLIZER}:OPENSSL_ENGINES=${CMAKE_BINARY_DIR}/lib:ASAN_OPTIONS=${ASAN_OPTIONS}"
            )
        endif()
    endif()

    message(STATUS "ASAN test program enabled")
endif()

# Valgrind memory check (only if not using ASAN)
if(ENABLE_VALGRIND AND NOT ENABLE_ASAN)
    find_program(VALGRIND valgrind)
    if(VALGRIND)
        add_test(NAME valgrind_test
            COMMAND ${VALGRIND} --leak-check=full --show-leak-kinds=all
                    --track-origins=yes --quiet --error-exitcode=1
                    ${CMAKE_BINARY_DIR}/bin/example
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        )

        set_tests_properties(valgrind_test PROPERTIES
            ENVIRONMENT "OPENSSL_ENGINES=${CMAKE_BINARY_DIR}/lib"
            LABELS "memory;valgrind"
            TIMEOUT 120
        )

        message(STATUS "Valgrind memory check enabled")
    else()
        message(WARNING "Valgrind requested but not found")
    endif()
endif()

# Custom test target to run all tests
add_custom_target(run_tests
    COMMAND ${CMAKE_CTEST_COMMAND} --verbose
    DEPENDS example
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running SM Engine tests..."
)

# Custom target for ASAN tests only
if(ENABLE_ASAN)
    add_custom_target(run_asan_tests
        COMMAND ${CMAKE_CTEST_COMMAND} --verbose -L asan
        DEPENDS test_asan
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        COMMENT "Running ASAN tests..."
    )
endif()

# Installation of test programs (optional)
if(BUILD_EXAMPLES)
    install(TARGETS example
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
endif()