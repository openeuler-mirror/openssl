# AddressSanitizer Testing for SM Engine

This document describes how to build and run the SM Engine with AddressSanitizer (ASAN) for memory safety testing.

## Prerequisites

- Compiler with ASAN support (GCC 4.8+ or Clang 3.1+)
- CMake 3.10 or higher
- OpenSSL built from 3rd/openssl

## Building with ASAN

### Using CMake (Recommended)

1. Create a separate build directory for ASAN builds:
```bash
mkdir build-asan
cd build-asan
```

2. Configure with ASAN enabled:
```bash
cmake .. -DENABLE_ASAN=ON -DCMAKE_BUILD_TYPE=Debug
```

3. Build:
```bash
make -j4
```

4. Run ASAN tests:
```bash
# Run all ASAN tests
make run_asan_tests

# Or use CTest directly
ctest -L asan --verbose

# Or run the test binary directly
./bin/test_asan
```

### Using the Shell Script

For quick testing without CMake:

```bash
# From the project root
./test/run_asan.sh \
    -oi 3rd/openssl/include \
    -ol 3rd/openssl/libcrypto.a \
    -v  # Verbose output
```

## ASAN Test Coverage

The `test_asan.c` program tests:

1. **SM3 Hash Algorithm**:
   - Empty input handling
   - Single byte processing
   - Large data (1MB) hashing
   - Multiple small updates
   - Context reuse

2. **SM4 Cipher Algorithm**:
   - Empty input encryption
   - Single block (16 bytes)
   - Unaligned data (requires padding)
   - Large data (1MB) encryption
   - ECB and CBC modes
   - Context reuse

3. **Memory Stress Testing**:
   - Rapid context creation/destruction (1000 iterations)
   - Memory leak detection
   - Buffer overflow detection

4. **Invalid Input Handling**:
   - NULL pointer handling
   - Invalid algorithm IDs
   - Edge cases and boundary conditions

## ASAN Options

The tests run with the following ASAN options:

- `detect_leaks=1` - Enable memory leak detection (Linux only)
- `check_initialization_order=1` - Check static initialization order
- `strict_string_checks=1` - Enable strict string function checks
- `print_stats=1` - Print ASAN statistics at exit

### Custom ASAN Options

Set custom options via environment variable:

```bash
export ASAN_OPTIONS="detect_leaks=1:halt_on_error=0:print_stats=1"
make run_asan_tests
```

## Interpreting ASAN Output

### Clean Output
```
=================================
All ASAN tests PASSED
=================================
```

### Memory Leak
```
=================================================================
==12345==ERROR: LeakSanitizer: detected memory leaks

Direct leak of 32 byte(s) in 1 object(s) allocated from:
    #0 0x... in malloc
    #1 0x... in function_name
```

### Buffer Overflow
```
=================================================================
==12345==ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 4 at 0x... thread T0
```

### Use After Free
```
=================================================================
==12345==ERROR: AddressSanitizer: heap-use-after-free
READ of size 4 at 0x... thread T0
```

## Platform-Specific Notes

### macOS
- Leak detection is disabled by default (ASAN limitation)
- May require disabling SIP for full functionality
- Uses `atos` for symbolization

### Linux
- Full leak detection support
- Uses `llvm-symbolizer` for better stack traces
- Install: `sudo apt-get install llvm`

## Troubleshooting

### ASAN Not Available
```
Error: Compiler does not support AddressSanitizer
```
**Solution**: Update compiler or use clang

### Missing Symbolizer
```
WARNING: Can't find symbolizer
```
**Solution**:
- Linux: `sudo apt-get install llvm`
- macOS: Xcode Command Line Tools should provide `atos`

### False Positives with OpenSSL
If seeing leaks in OpenSSL itself:
1. These may be one-time allocations (not real leaks)
2. OpenSSL may use custom memory management
3. Consider using suppressions file

## Building OpenSSL with ASAN (Optional)

For complete ASAN coverage including OpenSSL:

```bash
cd 3rd/openssl
./config --prefix=$PWD/build -g -O1 -fsanitize=address -fno-omit-frame-pointer
make clean
make -j4
make install_sw
```

Then rebuild the SM engine with this ASAN-enabled OpenSSL.

## Integration with CI/CD

Example GitHub Actions workflow:

```yaml
asan-test:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v2
    - name: Build OpenSSL
      run: |
        cd 3rd/openssl
        ./config --prefix=$PWD/build
        make -j4
        make install_sw
    - name: Build with ASAN
      run: |
        mkdir build-asan
        cd build-asan
        cmake .. -DENABLE_ASAN=ON
        make
    - name: Run ASAN Tests
      run: |
        cd build-asan
        make run_asan_tests
```

## Performance Impact

When running with ASAN:
- **Memory overhead**: 2-3x
- **CPU overhead**: 2-5x
- **Binary size**: Larger due to instrumentation

This is normal and expected for ASAN builds.

## See Also

- [AddressSanitizer Documentation](https://github.com/google/sanitizers/wiki/AddressSanitizer)
- [test_asan.c](test_asan.c) - ASAN test source code
- [run_asan.sh](run_asan.sh) - Standalone ASAN test script
- [run_valgrind.sh](run_valgrind.sh) - Alternative memory checking with Valgrind