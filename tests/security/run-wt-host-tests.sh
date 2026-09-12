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
    "$CC" -std=c99 -O1 -g -Wall -Wextra -Werror \
      -I"$BEARSSL/inc" -I"$BEARSSL/src" \
      -c "$BEARSSL/src/$source.c" -o "$object"
  done
fi

# One object per source that is not a test, so a test can be rebuilt alone.
build_module() {
  source=$1
  object="$BUILD/objects/$(printf '%s' "$source" | tr '/' '_').o"
  if [ ! -f "$object" ] || [ "$ROOT/$source" -nt "$object" ]; then
    "$CC" -std=c99 -O1 -g -Wall -Wextra -Werror \
      -I"$BEARSSL/inc" -I"$BEARSSL/src" \
      -I"$ROOT/userspace/wt/include" \
      -c "$ROOT/$source" -o "$object"
  fi
  printf '%s' "$object"
}

MODULE_OBJECTS=""
for source in userspace/wt/src/wt_crypto_bearssl.c userspace/wt/src/wt_aes128.c; do
  MODULE_OBJECTS="$MODULE_OBJECTS $(build_module "$source")"
done

# The tests. Each is tests/security/test_wt_<name>.c.
if [ "$#" -eq 0 ]; then
  set -- crypto
fi

failed=0
for name in "$@"; do
  test_source="tests/security/test_wt_$name.c"
  if [ ! -f "$ROOT/$test_source" ]; then
    printf 'error: no such test: %s\n' "$test_source" >&2
    exit 2
  fi
  binary="$BUILD/test_wt_$name"
  "$CC" -std=c99 -O1 -g -Wall -Wextra -Werror \
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
