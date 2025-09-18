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

# Set library properties
set_target_properties(sm_engine PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    OUTPUT_NAME "sm_engine"
    PREFIX "lib"
    C_VISIBILITY_PRESET hidden
)

# Include directories
target_include_directories(sm_engine
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${OPENSSL_INCLUDE_DIR}
)

# Link OpenSSL statically
if(OPENSSL_CRYPTO_LIBRARY)
    target_link_libraries(sm_engine PRIVATE ${OPENSSL_CRYPTO_LIBRARY})
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