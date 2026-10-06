#!/bin/bash
#
# Build one libcsdk OpenSSL engine, run the corei7 self-test, and write a
# .csdk package for the appliance.
#
# Usage:
#   ./build.sh <target> [arch] [corrupt]
#
# target    Cipher compiled into this engine. Run ./build.sh with no
#           arguments to list them. Each build contains one cipher.
# arch      Value passed to the compiler as -march, via CMake ENGARCH.
#           Default is corei7. An unrecognised name makes the compiler
#           print the names it accepts.
# corrupt   Any value other than "no" rewrites the library checksum in
#           csdk_info so the appliance version check fails. Default is no.
#           That package is for exercising the check, not for production.
#
# The self-test runs only for corei7. A binary built for a newer -march
# may not execute on this machine. Speed comparisons are a separate step:
# ./test.sh <target>. They are not part of this build.
#
# OpenSSL must already be built with ../openssl-1.1.1n/snts_build.sh.
# This script switches to its own directory, so it can be started from
# anywhere.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

TARGET="${1:-help}"
ARCH="${2:-corei7}"
CORRUPT="${3:-no}"
BASE_DIR="$(cd "$ROOT/.." && pwd)"
OPENSSL_ROOT="$BASE_DIR/openssl-1.1.1n"

# Must match CSDK_VERSION_TEXT in CMakeLists.txt. The shared library is
# installed as libcsdk.so.${CSDK_VERSION}.
CSDK_VERSION="0.0.4"
CSDK_LIB="libcsdk.so.${CSDK_VERSION}"

usage() {
    cat <<EOF
Senetas CSDK build

Usage:
  ./build.sh <target> [arch] [corrupt]

Targets:
  aes                  OpenSSL built-in AES
  aesni                AES-NI assembly
  aessbox              AES with a custom S-box
  xor                  XOR example of the cipher hook
  camellia             Camellia
  camellia_ossl        Camellia from the OpenSSL sources
  twofish              Twofish
  chacha20_poly1305    ChaCha20-Poly1305
  custom               Empty cipher template. Does not compile until filled in.

arch defaults to corei7. Example:
  ./build.sh twofish skylake

The third argument, when it is not "no", corrupts the library checksum in
the package so the appliance version check fails.

The self-test runs only for the corei7 arch.
EOF
}

if [[ "$TARGET" == "help" || "$TARGET" == "-h" || "$TARGET" == "--help" ]]; then
    usage
    exit 0
fi

if [[ ! -e "$OPENSSL_ROOT/libcrypto.so.1.1" || ! -x "$OPENSSL_ROOT/apps/openssl" ]]; then
    echo "OpenSSL is not built in $OPENSSL_ROOT. Run snts_build.sh first." >&2
    exit 1
fi

if [[ ! -f "tests/csdk_test_${TARGET}.c" ]]; then
    echo "No test driver tests/csdk_test_${TARGET}.c for target '$TARGET'." >&2
    usage >&2
    exit 1
fi

echo "Building engine ... $TARGET ($ARCH)"

# The test binary is always tests/csdk_test.c. Point that name at the
# driver for this cipher. The link is relative, so it resolves inside tests/.
rm -f tests/csdk_test.c
ln -s "csdk_test_${TARGET}.c" tests/csdk_test.c

rm -rf build
mkdir -p build

# BUILD_SHARED_LIBS
#   Engine is a shared library.
# CSDK_CIPHER_TARGET
#   Selects which cipher/*.c body is compiled in.
# ENGARCH
#   Becomes -march=${ARCH}.
# OPENSSL_ROOT_DIR
#   The in-tree OpenSSL that snts_build.sh produced.
if ! (
    cd build
    cmake \
        -DBUILD_SHARED_LIBS=ON \
        -DCSDK_CIPHER_TARGET="$TARGET" \
        -DENGARCH="$ARCH" \
        -DOPENSSL_ROOT_DIR="$OPENSSL_ROOT" \
        -GNinja \
        ..
    ninja
); then
    echo "BUILD FAILED!!!! - aborting" >&2
    exit 1
fi

export LD_LIBRARY_PATH="$OPENSSL_ROOT"
export OPENSSL_ENGINES="$ROOT/build/lib"

if [[ "$ARCH" == "corei7" ]]; then
    echo ""
    echo "EXECUTING selftest for basic (corei7) arch"
    echo ""
    # A failing self-test is reported and the package is still written.
    "$ROOT/build/tests/csdk_test" || echo "Self-test failed." >&2
else
    echo ""
    echo "SKIPPING selftest for non-default arch ($ARCH)"
    echo ""
fi

# Package layout, consumed on the appliance under /var/persistent/config/csdk:
#   libcsdk.so.0.0.4, csdk_test, csdk_info, csdk_check.sh
mkdir -p packages
rm -f packages/libcsdk_"${TARGET}"*.csdk

pkg_dir="$ROOT/build/lib"
cp "$ROOT/build/tests/csdk_test" "$pkg_dir/"

# Sums are taken inside the package directory so the recorded names are
# ./csdk_test and ./libcsdk.so.<version>. The appliance check runs from
# /var/persistent/config/csdk and looks those names up there.
T256="$(cd "$pkg_dir" && /usr/bin/sha256sum ./csdk_test)"
L256="$(cd "$pkg_dir" && /usr/bin/sha256sum "./$CSDK_LIB")"

DATE="$(/usr/bin/date '+%Y%m%d-%H%M%S')"
OSSLV="$("$OPENSSL_ROOT/apps/openssl" version -v)"
FILE="$ROOT/packages/libcsdk_${TARGET}_${ARCH}_${DATE}.csdk"

# Flip the first character of the library sum. sha256sum --check then fails.
if [[ "$CORRUPT" != "no" ]]; then
    L256="X${L256:1}"
fi

{
    echo "CSDK version ${CSDK_VERSION}"
    echo "... Model: $TARGET (1.4)"
    echo "...  Arch: $ARCH"
    echo "...  Ossl: $OSSLV"
    echo "... Built: $DATE"
    echo "           $T256"
    echo "           $L256"
} > "$pkg_dir/csdk_info"

# Runs on the appliance. The sums above are the lines sha256sum --check reads.
cat > "$pkg_dir/csdk_check.sh" <<EOF
#!/bin/bash
pushd /var/persistent/config/csdk 1>/dev/null 2>&1
cat ./csdk_info
grep csdk_test ./csdk_info | /usr/bin/sha256sum --check --status
if [ \$? -gt 0 ] ; then
    # bad checksum or file missing
    echo "Warning checksum failed!"
    exit 1
fi
grep ${CSDK_LIB} ./csdk_info | /usr/bin/sha256sum --check --status
if [ \$? -gt 0 ] ; then
    # bad checksum or file missing
    echo "Warning checksum failed!"
    exit 1
fi
popd 1>/dev/null 2>&1
echo "Checksums verified!"
exit 0
EOF
chmod 744 "$pkg_dir/csdk_check.sh"

# ./* matches the previous package contents and skips hidden files.
(
    cd "$pkg_dir"
    tar -zcpf "$FILE" ./*
)

echo ""
echo "$FILE package ready"
echo ""
echo "Package details..."
echo ""
cat "$pkg_dir/csdk_info"
echo ""
if [[ "$CORRUPT" != "no" ]]; then
    echo "WARNING - CORRUPTED checksum creation - not for production use!"
fi

echo "SKIPPING speedtest arch ($ARCH)"
