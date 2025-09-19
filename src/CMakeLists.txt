# SM Engine library

# Source files
set(ENGINE_SOURCES
    sm3.c
    sm4.c
    sm_engine.c
)

# Header files
set(ENGINE_HEADERS
    sm3.h
    sm4.h
)

# Create the engine library
add_library(sm_engine ${ENGINE_SOURCES})

# If OpenSSL needs to be built first, add dependency
if(OPENSSL_BUILD_REQUIRED)
    add_dependencies(sm_engine openssl_external)
endif()

# Set library properties
set_target_properties(sm_engine PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    OUTPUT_NAME "sm_engine"
    PREFIX "lib"
    C_VISIBILITY_PRESET hidden
)

# Include directories - ONLY use our custom OpenSSL
target_include_directories(sm_engine
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${OPENSSL_INCLUDE_DIR}
)

# Ensure we don't accidentally include system headers
target_compile_options(sm_engine PRIVATE
    -I${OPENSSL_INCLUDE_DIR}
)

# Link OpenSSL statically - MUST use our custom OpenSSL
if(OPENSSL_CRYPTO_LIBRARY)
    # Use absolute path for OpenSSL library
    get_filename_component(OPENSSL_LIB_ABS "${OPENSSL_CRYPTO_LIBRARY}" ABSOLUTE)
    target_link_libraries(sm_engine PRIVATE ${OPENSSL_LIB_ABS})

    # Add library directory to link path
    get_filename_component(OPENSSL_LIB_DIR "${OPENSSL_LIB_ABS}" DIRECTORY)
    target_link_directories(sm_engine PRIVATE ${OPENSSL_LIB_DIR})
else()
    message(FATAL_ERROR "OpenSSL crypto library not found")
endif()

# Platform-specific linking flags for symbol export
if(SYMBOL_EXPORT_FLAGS)
    set_target_properties(sm_engine PROPERTIES
        LINK_FLAGS "${SYMBOL_EXPORT_FLAGS}"
    )
endif()

# Additional link libraries for different platforms
if(UNIX AND NOT APPLE)
    target_link_libraries(sm_engine PRIVATE dl pthread)
elseif(APPLE)
    # macOS specific libraries if needed
endif()

# Installation
install(TARGETS sm_engine
    LIBRARY DESTINATION ${ENGINE_INSTALL_DIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Install headers (optional, usually engines don't install headers)
# install(FILES ${ENGINE_HEADERS}
#     DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/sm_engine
# )

# Export compile commands for development tools
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
