# anon_cert_c
A C language implementation of an anonymous certificate system based on BLS12-381 elliptic curve cryptography. This system provides privacy-preserving credential issuance, verification, selective disclosure, and revocation capabilities.
## Overview

This implementation provides a complete anonymous credential system that allows:
- **Selective attribute disclosure**: Users can selectively reveal certain attributes while keeping others private
- **Revocation support**: Certificates can be revoked efficiently using cryptographic accumulators
- **Zero-knowledge proofs**: All operations are backed by zero-knowledge proofs to ensure privacy and correctness

## Features

### Core Functionality

1. **System Initialization** (`setup`)
   - Generate system parameters and cryptographic keys
   - Initialize attribute bases
   - Set up cryptographic accumulator for revocation

2. **Certificate Issuance** (`issuer_verify_and_generate`)
   - Verify user requests and issue certificates
   - Automatically assign unique IDs and expiration times
   - Support for multiple user attributes

3. **Certificate Verification** (`user_verify_certificate`)
   - User-side verification of certificate validity
   - Verify cryptographic signatures

4. **Full Attribute Disclosure** (`full_show_prove/verify`)
   - Zero-knowledge proof for revealing all attributes
   - Complete certificate presentation

5. **Selective Attribute Disclosure** (`selective_show_prove/verify`)
   - Zero-knowledge proof for selectively revealing specific attributes
   - Includes revocation verification
   - Privacy-preserving attribute presentation

6. **Revocation** (`revoke`)
   - Efficient certificate revocation using cryptographic accumulators
   - Batch revocation support
   - Non-membership witness generation

7. **Non-Membership Witness** (`non_membership_witness`)
   - Generate proofs that a certificate ID is not in the revocation list
   - Supports multithreaded witness generation for performance

## Project Structure

```
anon_cert_c/
├── include/
│   └── anon_cert.h          # Main header file with all data structures and function prototypes
├── src/
│   ├── groups.c             # Basic group operations (G1/G2 point operations, pairings)
│   ├── accumulator.c        # Accumulator functionality (revocation list management)
│   ├── zk.c                 # Schnorr zero-knowledge proofs
│   ├── core.c               # Core functions (system setup, certificate issuance, verification)
│   ├── full_show.c          # Full attribute disclosure zero-knowledge proof
│   └── selective_show.c     # Selective attribute disclosure zero-knowledge proof
├── test/
│   ├── test_main.c          # Functional test program (test_func)
│   └── test_init_perf.c     # Performance test program (test_perf)
├── Makefile                 # Build configuration
├── libanon_cert.a           # Static library (generated)
├── test_func                # Functional test executable (generated)
├── test_perf                # Performance test executable (generated)
└── README.md                # This file
```

## Dependencies

### Required Libraries

1. **blst Library**
   - BLS12-381 elliptic curve operations library
   - Provides G1, G2 group operations, pairings, and scalar arithmetic
   - Version: 0.3.11 or compatible

2. **System Libraries**
   - Standard C library (`libc`)
   - Math library (`libm`)
   - POSIX threads library (`libpthread`)

### Compiler Requirements

- **GCC** compiler with C11 support
- Recommended: GCC 7.0 or later
- Compiler flags: `-Wall -Wextra -O3 -march=native -std=c11`

## Environment Setup

### Installing blst Library

The blst library can be obtained and built in several ways:

#### Option 1: Build from Source (Recommended)

```bash
# Clone the blst repository
git clone https://github.com/supranational/blst.git
cd blst

# Build the library
./build.sh

# The library will be in the blst directory
# Copy or symlink to a standard location (e.g., /tmp/blst or any directory of your choice)
cp -r . /tmp/blst
# Or use a custom location:
# cp -r . /path/to/your/blst
```

#### Option 2: Use Rust Cargo (if available)

If you have Rust installed, blst can be installed via Cargo:

```bash
# Install via cargo (blst will be in cargo registry)
cargo build --release

# The library path will typically be:
# ~/.cargo/registry/src/index.crates.io-*/blst-*/blst
```

#### Option 3: Use Pre-built Library

If you have a pre-built `libblst.a` file:

```bash
# Choose a directory for blst (e.g., /tmp/blst or any directory of your choice)
BLST_INSTALL_DIR=/tmp/blst  # Or use your preferred path

# Create directory structure
mkdir -p $BLST_INSTALL_DIR/lib
mkdir -p $BLST_INSTALL_DIR/bindings

# Copy library file
cp libblst.a $BLST_INSTALL_DIR/lib/

# Copy header files
cp bindings/*.h $BLST_INSTALL_DIR/bindings/
```

### Setting BLST_DIR Environment Variable

If blst is installed in a non-standard location, set the `BLST_DIR` environment variable:

```bash
export BLST_DIR=/path/to/blst
```

The Makefile will automatically detect blst in the following locations (in order):
1. `/tmp/blst` (default location)
2. `$BLST_DIR` (if set via environment variable)
3. Cargo registry path (if Rust/Cargo is installed)

**Note**: You can install blst in any directory. Just set the `BLST_DIR` environment variable to point to the directory containing `libblst.a` and the `bindings/` subdirectory.

## Building the Project

### Prerequisites

Before building, ensure you have:
1. Installed the blst library (see [Environment Setup](#environment-setup))
2. Set `BLST_DIR` environment variable if blst is not in `/tmp/blst`:
   ```bash
   export BLST_DIR=/path/to/your/blst
   ```

### Build All Targets

Navigate to the project root directory (where `Makefile` is located):

```bash
cd anon_cert_c  # Or wherever you cloned/extracted the project
make
```

This will:

This will:
- Compile all source files into object files
- Create the static library `libanon_cert.a`
- Build test executables `test_func` and `test_perf`

### Build Only the Library

```bash
make libanon_cert.a
```

### Build Only Test Programs

```bash
make test
```

### Clean Build Artifacts

```bash
make clean
```

This removes:
- All object files (`.o`)
- The static library (`libanon_cert.a`)
- Test executables (`test_func`, `test_perf`)

### Check blst Library Location

```bash
make check-blst
```

This will verify that the blst library is found and display its location.

## Running the Programs

### Functional Test (`test_func`)

The functional test demonstrates the complete workflow of the anonymous certificate system:

```bash
./test_func
```

**What it tests:**
1. System initialization
2. User request generation
3. Certificate issuance
4. Certificate verification
5. Selective attribute disclosure
6. Certificate revocation
7. Non-membership witness generation

**Expected output:**
- Timing information for each phase
- Verification results (Pass/Fail)
- Certificate details (ID, attributes)

### Performance Test (`test_perf`)

The performance test measures the system's performance under various conditions:

```bash
./test_perf
```

**What it tests:**
1. Initialization performance with different attribute counts
2. Certificate issuance and verification performance
3. Selective disclosure performance
4. Witness generation performance
5. Performance scaling with different numbers of revoked certificates

**Output:**
- Performance metrics in milliseconds
- CSV-formatted results
- Optional log file (if specified)

**Example output:**
```
========================================
Initialization Performance Test
========================================

Testing with max_attrs=5, q=200, iterations=10
Average initialization time: 45.23 ms

Certificate Issuance Performance:
  - User Attrs: 10, Phase1: 2.1 ms, Phase2: 15.3 ms, Phase3: 1.8 ms
  ...
```

## API Usage Example

Here's a basic example of how to use the library:

```c
#include "anon_cert.h"

int main() {
    // 1. Initialize system
    system_params_t params;
    issuer_keys_t issuer_keys;
    setup(&params, &issuer_keys, 5, 200);  // max_attrs=5, q=200
    
    // 2. User generates request
    scalar_t sk_u;
    g1_point_t M1;
    schnorr_proof_t pi_sk;
    user_generate_request(sk_u, &M1, &pi_sk, &params);
    
    // 3. Issuer issues certificate
    certificate_t cert;
    scalar_t user_attrs[] = { /* user attributes */ };
    bool success = issuer_verify_and_generate(&cert, &params, &issuer_keys,
                                             &M1, &pi_sk, user_attrs, 3, 86400);
    
    // 4. User verifies certificate
    bool valid = user_verify_certificate(&params, &cert, sk_u);
    
    // 5. Selective disclosure
    int disclosed_indices[] = {2, 3};
    selective_show_view_t view;
    selective_show_prove(&view, &params, &cert, sk_u, disclosed_indices, 2);
    
    scalar_t disclosed_attrs[2];
    memcpy(disclosed_attrs[0], cert.m[2], 32);
    memcpy(disclosed_attrs[1], cert.m[3], 32);
    bool verified = selective_show_verify(&params, &view, disclosed_attrs, 2);
    
    // 6. Cleanup
    cleanup_accumulator(&params);
    // ... cleanup issuer_keys resources ...
    
    return 0;
}
```

## Technical Details

### Cryptographic Primitives

- **Curve**: BLS12-381
- **Groups**: G1, G2 (elliptic curve groups), GT (target group for pairings)
- **Pairing**: Optimal Ate pairing
- **Hash Functions**: FNV-1a based hashing (for attribute bases), SHA-256 compatible

### Zero-Knowledge Proofs

- **Schnorr Proofs**: Used for proving knowledge of discrete logarithms
- **Batch Schnorr Proofs**: Efficient batch verification of multiple proofs
- **Selective Disclosure Proofs**: Zero-knowledge proofs for selective attribute revelation

### Accumulator

- **Type**: Cryptographic accumulator for revocation
- **Batch Processing**: Fixed-size batch revocation for efficiency
- **Polynomial Representation**: Revocation state represented as polynomial coefficients
- **Non-Membership Witness**: Efficient proofs of non-revocation

## Performance Considerations

- **Initialization**: Typically 20-50 ms depending on attribute count and accumulator capacity
- **Certificate Issuance**: ~15-20 ms for typical configurations
- **Selective Disclosure**: ~5-10 ms for proof generation, ~2-5 ms for verification
- **Witness Generation**: Scales with number of revoked certificates; multithreaded support available

## Troubleshooting

### Error: blst library not found

**Solution**: Ensure blst is installed and `BLST_DIR` is set correctly:
```bash
# Set BLST_DIR to the directory containing libblst.a
export BLST_DIR=/path/to/blst  # Replace with your actual blst installation path
make clean
make
```

**Note**: The path should point to the directory that contains:
- `libblst.a` (or in a `lib/` subdirectory)
- `bindings/blst.h` (header files)

### Error: Cannot find blst.h

**Solution**: Check that the blst bindings directory contains the header files:
```bash
ls $BLST_DIR/bindings/blst.h
```

### Compilation errors

**Solution**: Ensure you have a compatible GCC version:
```bash
gcc --version  # Should be 7.0 or later
```

### Runtime errors

**Solution**: Check that all required libraries are linked:
```bash
ldd test_func  # Should show libblst.a, libm, libpthread
```

## License

This implementation follows the same license as the original project.

## References

- BLS12-381 curve specification
- blst library: https://github.com/supranational/blst
- Anonymous credential system paper (referenced in implementation)

## Contributing

When contributing to this project:
1. Follow the existing code style
2. Ensure all tests pass
3. Update documentation as needed
4. Use English for all comments and documentation

## Contact

For questions or issues, please refer to the project repository.
