#!/bin/sh
# Build and run the WebTransport C99 crypto/TLS tests on the host.
#
# These are host tests, not target tests. The target is XAIOS, which has no way
# to print a hex digest and compare it to an RFC; the values they check are
# arithmetic over byte strings, so the host is where they can actually be
# verified. The code under test is the same code the target builds, compiled
# from the same sources with the same BearSSL.
#
# BearSSL is compiled here rather than linked from a system library, for the
# same reason: the point is to test the vendored BearSSL binding the target
# uses, not whatever OpenSSL the host happens to have.
#
# Usage: scripts/test-wt-host.sh [test-name ...]
#        (no arguments runs every test; a name runs only that one)
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
BEARSSL="$ROOT/third_party/bearssl"
BUILD="$ROOT/build/wt-host"
CC=${CC:-clang}
# WT_SANITIZE=1 builds and runs everything under ASan and UBSan. It is off by
# default because the whole BearSSL object set has to be rebuilt with the same
# flags, which roughly doubles the build, and on because it has already found a
# test bug that the plain run passed.
SANITIZE=${WT_SANITIZE:-0}
case "$SANITIZE" in
  0) SAN_FLAGS="" ;;
  1) SAN_FLAGS="-fsanitize=address,undefined -fno-sanitize=function" ;;
  *) printf '%s\n' "error: WT_SANITIZE must be 0 or 1" >&2; exit 2 ;;
esac
# -fno-sanitize=function is not optional: clang's `undefined` includes it, and
# it flags BearSSL's own vtable type-punning in hmac.c, which is not a defect in
# the code under test. The Darwin symbolizer also hangs on that report, so the
# environment below disables symbolization. This is a toolchain workaround and
# it belongs in a comment rather than in a run that looks clean by accident.
if [ -n "$SAN_FLAGS" ]; then
  BUILD="$BUILD-san"
  ASAN_OPTIONS=symbolize=0
  UBSAN_OPTIONS=symbolize=0
  export ASAN_OPTIONS UBSAN_OPTIONS
fi

mkdir -p "$BUILD/bearssl" "$BUILD/objects"

# The BearSSL sources the WebTransport module binds to: SHA-256, HMAC, GCM,
# AES, and the small codec helpers they call. Compiling the whole tree would
# work but would link a TLS 1.2 state machine into a test that must not use
# one.
BEARSSL_SOURCES="
  hash/sha2small
  hash/sha2big
  hash/ghash_ctmul64
  mac/hmac
  aead/gcm
  symcipher/aes_common
  symcipher/aes_ct
  symcipher/aes_ct64
  symcipher/aes_ct64_ctr
  symcipher/aes_ct64_enc
  symcipher/aes_ct64_dec
  ec/ec_c25519_m15
  codec/ccopy
  int/i15_add
  int/i15_sub
  int/i15_montmul
  int/i15_mulacc
  int/i15_moddiv
  int/i15_encode
  int/i15_decode
  int/i15_decmod
  int/i15_muladd
  int/i15_bitlen
  int/i15_reduce
  int/i15_ninv15
  int/i15_tmont
  rsa/rsa_i31_pss_vrfy
  rsa/rsa_i31_pub
  rsa/rsa_pss_sig_unpad
  rsa/rsa_i31_modulus
  hash/mgf1
  int/i31_add
  int/i31_sub
  int/i31_mulacc
  int/i31_montmul
  int/i31_encode
  int/i31_decode
  int/i31_bitlen
  int/i31_ninv31
  int/i31_reduce
  int/i31_decmod
  int/i31_modpow
  int/i31_modpow2
  int/i31_muladd
  int/i31_tmont
  int/i31_fmont
  int/i31_rshift
  int/i31_iszero
  int/i32_div32
  ec/ecdsa_atr
  ec/ec_prime_i31
  ec/ec_secp256r1
  ec/ec_secp384r1
  ec/ec_secp521r1
  ec/ec_curve25519
  ec/ec_pubkey
  ec/ecdsa_i31_vrfy_asn1
  ec/ecdsa_i31_vrfy_raw
  ec/ecdsa_i31_bits
  x509/x509_decoder
  x509/x509_knownkey
  codec/dec32be
  codec/dec32le
  codec/dec64be
  codec/enc32be
  codec/enc32le
  codec/enc64be
"

bearssl_object() {
  printf '%s/bearssl/%s.o' "$BUILD" "$(printf '%s' "$1" | tr '/' '_')"
}

needs_build=0
for source in $BEARSSL_SOURCES; do
  object=$(bearssl_object "$source")
  if [ ! -f "$object" ] || [ "$BEARSSL/src/$source.c" -nt "$object" ]; then
    needs_build=1
  fi
done

if [ "$needs_build" -eq 1 ]; then
  for source in $BEARSSL_SOURCES; do
    object=$(bearssl_object "$source")
    [ -f "$object" ] && [ "$BEARSSL/src/$source.c" -ot "$object" ] && continue
    # -Werror only for this repository's own sources. The vendored BearSSL is
    # compiled by the target build with its own flags; making it fail this
    # script on a warning a different clang version grows would turn a
    # third-party warning into a red CI job about XAIOS's code. Its warnings
    # are still printed.
    "$CC" -std=c99 -O1 -g -Wall -Wextra $SAN_FLAGS \
      -I"$BEARSSL/inc" -I"$BEARSSL/src" \
      -c "$BEARSSL/src/$source.c" -o "$object"
  done
fi

# One object per source that is not a test, so a test can be rebuilt alone.
#
# A module is rebuilt when its own source is newer than its object OR when any
# header in userspace/wt/include is. The first version checked only the source,
# so editing a header left every object stale and a run could pass against code
# that no longer existed -- which happened, and cost a debugging session
# chasing a defect that had already been fixed.
newest_header() {
  newest=""
  for header in "$ROOT"/userspace/wt/include/*.h; do
    if [ -z "$newest" ] || [ "$header" -nt "$newest" ]; then
      newest=$header
    fi
  done
  printf '%s' "$newest"
}

HEADER_STAMP=$(newest_header)

build_module() {
  source=$1
  object="$BUILD/objects/$(printf '%s' "$source" | tr '/' '_').o"
  if [ ! -f "$object" ] || [ "$ROOT/$source" -nt "$object" ] ||
     { [ -n "$HEADER_STAMP" ] && [ "$HEADER_STAMP" -nt "$object" ]; }; then
    "$CC" -std=c99 -O1 -g -Wall -Wextra -Werror $SAN_FLAGS \
      -I"$BEARSSL/inc" -I"$BEARSSL/src" \
      -I"$ROOT/userspace/wt/include" \
      -c "$ROOT/$source" -o "$object"
  fi
  printf '%s' "$object"
}

MODULE_OBJECTS=""
for source in userspace/wt/src/wt_crypto_bearssl.c userspace/wt/src/wt_aes128.c \
              userspace/wt/src/wt_tls.c \
              userspace/wt/src/wt_quic_pkt.c \
              userspace/wt/src/wt_tls_handshake.c \
              userspace/wt/src/wt_tls_cert.c \
              userspace/wt/src/wt_tls_pin.c \
              userspace/wt/src/wt_tls_client.c; do
  MODULE_OBJECTS="$MODULE_OBJECTS $(build_module "$source")"
done

# The tests. Each is tests/security/test_wt_<name>.c.
if [ "$#" -eq 0 ]; then
  set -- crypto tls quic_pkt tls_handshake tls_cert tls_pin tls_client
fi

failed=0
for name in "$@"; do
  test_source="tests/security/test_wt_$name.c"
  if [ ! -f "$ROOT/$test_source" ]; then
    printf 'error: no such test: %s\n' "$test_source" >&2
    exit 2
  fi
  binary="$BUILD/test_wt_$name"
  # Rebuild the test when its source or any header changed, for the same reason.
  if [ -f "$binary" ] && [ -n "$HEADER_STAMP" ] &&
     [ "$HEADER_STAMP" -nt "$binary" ]; then
    rm -f "$binary"
  fi
  "$CC" -std=c99 -O1 -g -Wall -Wextra -Werror $SAN_FLAGS \
    -I"$BEARSSL/inc" -I"$BEARSSL/src" \
    -I"$ROOT/userspace/wt/include" \
    "$ROOT/$test_source" $MODULE_OBJECTS "$BUILD"/bearssl/*.o \
    -o "$binary"
  if ! "$binary"; then
    failed=$((failed + 1))
  fi
done

if [ "$failed" -ne 0 ]; then
  printf 'wt-host: %d test(s) failed\n' "$failed" >&2
  exit 1
fi
