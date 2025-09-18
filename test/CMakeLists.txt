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

# Test engine program (if exists)
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/test_engine.c)
    add_executable(test_engine test_engine.c)

    target_link_libraries(test_engine
        sm_engine
        ${OPENSSL_CRYPTO_LIBRARY}
    )

    if(UNIX AND NOT APPLE)
        target_link_libraries(test_engine dl pthread)
    endif()

    set_target_properties(test_engine PROPERTIES
        INSTALL_RPATH_USE_LINK_PATH TRUE
        BUILD_RPATH "${CMAKE_BINARY_DIR}/lib"
    )

    add_test(NAME engine_test
        COMMAND test_engine
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )

    set_tests_properties(engine_test PROPERTIES
        ENVIRONMENT "LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}/lib:$ENV{LD_LIBRARY_PATH}"
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