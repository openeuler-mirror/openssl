# Makefile for SM Engine
# OpenSSL Engine implementation for SM3 and SM4 algorithms using static library

CC = gcc
CFLAGS = -Wall -Wextra -O2 -fPIC -std=c99 -fvisibility=hidden

# OpenSSL paths - can be overridden by environment variables or make parameters
OPENSSL_INCLUDE ?= /usr/include/openssl /usr/local/include/openssl
OPENSSL_LIB_PATH ?= /usr/local/lib/libsm_openssl.a
OPENSSL_LIBS ?= 

# Convert space-separated include paths to -I flags
INCLUDES = $(foreach dir,$(OPENSSL_INCLUDE),-I$(dir))
ifeq ($(shell uname),Darwin)
  LDFLAGS = -shared -fPIC -Wl,-exported_symbols_list,exported.symbols
else
  LDFLAGS = -shared -fPIC -Wl,--version-script=sm_engine.syms
endif
LIBS = $(OPENSSL_LIBS)

# Source files
SOURCES = src/sm3.c src/sm4.c src/sm_engine.c
OBJECTS = $(SOURCES:.c=.o)
TARGET = libsm_engine.so

# Installation directories
PREFIX = /usr/local
ENGINE_DIR = $(PREFIX)/lib/engines

# Default target
all: check_paths $(TARGET)

# Check if required paths exist
check_paths:
	@echo "Checking OpenSSL paths..."
	@for dir in $(OPENSSL_INCLUDE); do \
		if [ ! -d "$$dir" ]; then \
			echo "Warning: OpenSSL include directory '$$dir' does not exist"; \
		fi; \
	done
	@if [ ! -f "$(OPENSSL_LIB_PATH)" ]; then \
		echo "Warning: OpenSSL library '$(OPENSSL_LIB_PATH)' does not exist"; \
	fi
	@echo "OpenSSL include paths: $(OPENSSL_INCLUDE)"
	@echo "OpenSSL library path: $(OPENSSL_LIB_PATH)"
	@echo "OpenSSL libraries: $(OPENSSL_LIBS)"

# Build the shared library with static linking
$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^ $(OPENSSL_LIB_PATH) $(LIBS)

# Compile source files
%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Install the engine
install: $(TARGET)
	install -d $(ENGINE_DIR)
	install -m 755 $(TARGET) $(ENGINE_DIR)/
	@echo "SM Engine installed to $(ENGINE_DIR)/$(TARGET)"

# Uninstall the engine
uninstall:
	rm -f $(ENGINE_DIR)/$(TARGET)
	@echo "SM Engine uninstalled"

# Clean build artifacts
clean:
	rm -f $(OBJECTS) $(TARGET)
	@echo "Build artifacts cleaned"

# Test the engine
test: $(TARGET)
	@echo "Running engine tests..."
	@if [ -f test/test_engine ]; then \
		./test/test_engine; \
	else \
		echo "Test executable not found. Run 'make test-build' first."; \
	fi

# Build test executable
test-build: $(TARGET)
	$(CC) $(CFLAGS) $(INCLUDES) -o test/test_engine test/test_engine.c -L. -lsm_engine $(LIBS)

# Build example executable
example-build: $(TARGET)
	$(CC) $(CFLAGS) $(INCLUDES) -o examples/simple_example examples/simple_example.c -L. -lsm_engine $(LIBS)

# Run example
example: example-build
	@echo "Running simple example..."
	@if [ -f examples/simple_example ]; then \
		LD_LIBRARY_PATH=. ./examples/simple_example; \
	else \
		echo "Example executable not found. Run 'make example-build' first."; \
	fi

# Debug build
debug: CFLAGS += -g -DDEBUG
debug: $(TARGET)

# Release build
release: CFLAGS += -DNDEBUG
release: $(TARGET)

# AddressSanitizer build
asan: CC = clang
asan: CFLAGS = -Wall -Wextra -g -O0 -fPIC -std=c99 -fsanitize=address -fno-omit-frame-pointer
asan: LDFLAGS += -fsanitize=address
asan: $(TARGET)
	@echo "Built with AddressSanitizer enabled"

# Build and run ASAN tests
test-asan: asan
	@echo "Building ASAN test program..."
	$(CC) -g -O0 -fsanitize=address -fno-omit-frame-pointer $(INCLUDES) \
		test/test_asan.c -o build/test_asan \
		-fsanitize=address $(OPENSSL_LIB_PATH) $(LIBS) -ldl
	@echo "Running ASAN tests..."
	OPENSSL_ENGINES=$(PWD)/build ASAN_OPTIONS=detect_leaks=1:check_initialization_order=1 ./build/test_asan

# Run Valgrind memory check
test-valgrind: $(TARGET)
	@if command -v valgrind >/dev/null 2>&1; then \
		echo "Running Valgrind memory check..."; \
		OPENSSL_ENGINES=$(PWD)/build valgrind --leak-check=full --show-leak-kinds=all \
			--track-origins=yes --log-file=valgrind.log ./build/example; \
		echo "Valgrind log saved to valgrind.log"; \
	else \
		echo "Valgrind not installed. Install with: sudo apt-get install valgrind"; \
	fi

# Show help
help:
	@echo "Available targets:"
	@echo "  all        - Build the engine (default)"
	@echo "  install    - Install the engine to system"
	@echo "  uninstall  - Remove the engine from system"
	@echo "  clean      - Remove build artifacts"
	@echo "  test       - Run engine tests"
	@echo "  test-build - Build test executable"
	@echo "  test-asan  - Run AddressSanitizer tests"
	@echo "  test-valgrind - Run Valgrind memory check"
	@echo "  example    - Run simple example"
	@echo "  example-build - Build example executable"
	@echo "  asan       - Build with AddressSanitizer"
	@echo "  debug      - Build with debug symbols"
	@echo "  release    - Build optimized release version"
	@echo "  help       - Show this help"
	@echo ""
	@echo "Environment variables and make parameters:"
	@echo "  OPENSSL_INCLUDE  - OpenSSL header file paths (space-separated)"
	@echo "  OPENSSL_LIB_PATH - OpenSSL static library path"
	@echo "  OPENSSL_LIBS     - OpenSSL libraries to link"
	@echo ""
	@echo "Examples:"
	@echo "  make OPENSSL_INCLUDE='/opt/openssl/include' OPENSSL_LIB_PATH='/opt/openssl/lib/libssl.a'"
	@echo "  make OPENSSL_INCLUDE='/usr/include/openssl /usr/local/include' OPENSSL_LIB_PATH='/usr/lib/libssl.a'"
	@echo "  make OPENSSL_LIBS='-lcrypto -lssl -ldl'"

.PHONY: all check_paths install uninstall clean test test-build test-asan test-valgrind example example-build asan debug release help