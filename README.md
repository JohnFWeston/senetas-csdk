# libcsdk

libcsdk is the Senetas Cryptographic Software Development Kit (CSDK), version 0.0.4. It is a reference OpenSSL engine that supplies symmetric ciphers for the Senetas CV1000 and CN7000 DPDK encryption platform.

The engine is a dynamically loadable OpenSSL ENGINE with id `libcsdk`. Applications keep using the OpenSSL EVP cipher API. When the engine is loaded, it answers those calls with the cipher selected at build time.

It is built against the OpenSSL 1.1.1n tree that sits beside this directory.

## What the engine provides

`csdk.c` binds the engine: id, name, init, finish, destroy, and the cipher callback. `csdk_ciphers.c` implements the EVP methods and the mode layer. Each build compiles in exactly one cipher, chosen with `CSDK_CIPHER_TARGET`.

For every block-cipher target the engine registers the standard AES EVP names:

| EVP name | Mode |
| --- | --- |
| `aes-128-cfb`, `aes-256-cfb` | CFB-128 |
| `aes-128-ctr`, `aes-256-ctr` | CTR |
| `aes-128-gcm`, `aes-256-gcm` | GCM (AEAD) |

The names stay stable so existing callers do not change. The algorithm behind those names is the one selected for the build. The `aes` target really is AES and delegates to OpenSSL. The other block-cipher targets use the same names and key sizes while running their own algorithm.

`chacha20_poly1305` is the exception. That build registers only `NID_chacha20_poly1305`.

The mode code (CFB, CTR, GCM) lives in the engine. The selected cipher supplies the block encrypt and key schedule. The GCM context follows the OpenSSL layout so the bundled GHASH assembly can be used. On each cipher query the engine records the host CPU features through OpenSSL's `OPENSSL_ia32_cpuid` helper.

## Cipher targets

`./build.sh` selects the target, configures CMake, builds with Ninja, runs a self-test on the default architecture, and writes a deployable package.

| Target | Implementation |
| --- | --- |
| `aes` | OpenSSL built-in AES. Baseline for comparison. |
| `aesni` | AES using AES-NI assembly. |
| `aessbox` | AES with a custom S-box, in assembly. |
| `camellia` | Camellia, with x86_64 assembly. |
| `camellia_ossl` | Camellia taken from the OpenSSL sources. |
| `twofish` | Twofish, with assembly. |
| `xor` | XOR of the keystream. A minimal example of the cipher hook. |
| `chacha20_poly1305` | ChaCha20-Poly1305 AEAD, with Senetas x86_64 assembly. |
| `custom` | Empty template in `cipher/custom.c` for a new cipher. It does not build until an implementation is filled in. |

`cipher/twofish_intrinsics.c` is an alternate Twofish body. It is compiled when `CSDK_CIPHER_TARGET=twofish_intrinsics`, and it is not one of the `build.sh` presets.

Block-cipher sources follow a common hook: a `csdk_key_st` for key size, block size, and private state, plus set-key and encrypt entry points that the mode layer calls. `cipher/custom.c` is the place to start a new algorithm. `cipher/xor.c` is the smallest working example.

## Layout

```
libcsdk/
  CMakeLists.txt          project, OpenSSL discovery, -march selection
  build.sh                configure, build, self-test, package
  test.sh                 openssl speed against the built-in baseline
  vt.sh                   Intel VTune launch for the speed test
  src/csdk/
    csdk.c                engine bind
    csdk_ciphers.c        EVP methods and CFB / CTR / GCM
    csdk_err.c            engine error strings
    cipher/               one implementation per target, plus assembly
  tests/                  known-answer tests, one driver per target
```

Assembly is x86_64. CMake sets `-march` from `ENGARCH` (default `corei7`). Other values, such as `skylake`, are passed through to the compiler. An unrecognised `-march` name makes the compiler list the names it accepts.

## Build

Dependencies: CMake 3.6 or later, Ninja, and a C compiler. The engine uses the OpenSSL 1.1 ENGINE API and links the `libcrypto.so` from the sibling `openssl-1.1.1n` tree. Build that library first, from `openssl-1.1.1n`:

```
./snts_build.sh
```

That script configures a Debian amd64 shared build and runs `make`. It does not install OpenSSL onto the system.

From this directory, `./build.sh` with no arguments lists the cipher targets. A build is one target and an optional `-march` name:

```
./build.sh aes
./build.sh twofish skylake
```

`build.sh` points the test binary at `tests/csdk_test_<target>.c`, configures with `-DOPENSSL_ROOT_DIR` set to `../openssl-1.1.1n`, and runs Ninja. A third argument other than `no` writes a package whose library checksum does not match, so the appliance version check fails.

The build produces:

- `build/lib/libcsdk.so.0.0.4`, the engine shared library
- `build/tests/csdk_test`, the known-answer self-test

The self-test runs only for the default `corei7` architecture, because a binary built for a newer `-march` may not execute on the build machine. Set `OPENSSL_ENGINES` to `build/lib` before loading the engine by hand:

```
export LD_LIBRARY_PATH=$PWD/../openssl-1.1.1n
export OPENSSL_ENGINES=$PWD/build/lib
./build/tests/csdk_test
```

`test.sh` compares `openssl speed` for the engine with the OpenSSL baseline (AES-256 CFB, CTR, and GCM, or ChaCha20-Poly1305 for that target). `vt.sh` opens the same style of run under Intel VTune, which must already be installed.

## Packages

A successful `build.sh` writes `packages/libcsdk_<target>_<arch>_<timestamp>.csdk`. The archive holds the library, `csdk_test`, a `csdk_info` manifest (version, target, architecture, OpenSSL version, SHA-256 sums), and `csdk_check.sh`. On an appliance the check script verifies those sums under `/var/persistent/config/csdk`.

## Using the engine

Load it by id `libcsdk` (`ENGINE_by_id`, or `openssl` with `-engine libcsdk`). `OPENSSL_ENGINES` must contain the directory of `libcsdk.so`. After the engine is set as the default, or passed into `EVP_EncryptInit_ex`, the usual EVP encrypt and decrypt calls use the cipher compiled into that build.

## License

The engine adopts the OpenSSL license. See `LICENSE` in the bundled `openssl-1.1.1n` tree. Individual ciphers keep their own copyright notices: Camellia from NTT and the OpenSSL project, Twofish from Niels Ferguson.
