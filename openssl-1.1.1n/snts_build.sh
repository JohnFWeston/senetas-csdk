#!/bin/bash
#
# Clean, configure, and build the bundled OpenSSL 1.1.1n reference library.
#
# libcsdk links against the libcrypto produced here. The options follow
# the Debian amd64 shared build in debian/rules (CONFARGS plus the
# debian-amd64 target). The build stays in this tree; nothing is installed
# onto the system.
#
# Usage, from this directory or elsewhere:
#   ./snts_build.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

# Remove objects, generated sources, configdata.pm, and the Makefile from
# an earlier Configure. A fresh tree has no Makefile, so there is nothing
# to clean.
if [ -f Makefile ]; then
    make distclean
fi

# shared
#   Build libcrypto.so and libssl.so. libcsdk loads this libcrypto.
# --prefix / --openssldir / --libdir
#   Debian multiarch install layout. Used if the tree is later installed;
#   this script does not run "make install".
# no-idea no-mdc2 no-rc5
#   Leave out the patent-encumbered ciphers Debian also disables.
# no-zlib
#   Do not link compression into libcrypto.
# no-ssl3 no-ssl3-method
#   Drop SSLv3 and the method that would re-enable it.
# no-capieng
#   Windows CAPI engine. Not used on this Linux build.
# enable-unit-test enable-rfc3779 enable-cms
#   Debian enables the unit-test support, RFC 3779 certificate extensions,
#   and CMS.
# enable-ec_nistp_64_gcc_128
#   64-bit GCC implementation of the NIST P-224/P-256/P-521 curves.
#   Debian turns this on for amd64 only.
# debian-amd64
#   linux-x86_64 target plus the Debian warning and noexecstack flags
#   from Configurations/20-debian.conf.
# -Wno-incompatible-pointer-types
#   GCC 14 treats this diagnostic as an error. crypto/dh/dh_local.h still
#   stores the reference count as a plain int, while CRYPTO_UP_REF and
#   CRYPTO_DOWN_REF take _Atomic int * when C11 atomics are available.
# -Wno-implicit-int
#   GCC 14 also rejects old declarations with no return type. test/dhtest.c
#   declares dh_test that way.
./Configure shared \
    --prefix=/usr \
    --openssldir=/usr/lib/ssl \
    --libdir=lib/x86_64-linux-gnu \
    no-idea \
    no-mdc2 \
    no-rc5 \
    no-zlib \
    no-ssl3 \
    no-ssl3-method \
    no-capieng \
    enable-unit-test \
    enable-rfc3779 \
    enable-cms \
    enable-ec_nistp_64_gcc_128 \
    debian-amd64 \
    -Wno-incompatible-pointer-types \
    -Wno-implicit-int

# Print the configuration Configure just wrote. debian/rules does the same.
perl configdata.pm -d

make -j"$(nproc)"
