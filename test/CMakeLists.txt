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

# Custom test target to run all tests
add_custom_target(run_tests
    COMMAND ${CMAKE_CTEST_COMMAND} --verbose
    DEPENDS example
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running SM Engine tests..."
)

# Installation of test programs (optional)
if(BUILD_EXAMPLES)
    install(TARGETS example
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    )
endif()