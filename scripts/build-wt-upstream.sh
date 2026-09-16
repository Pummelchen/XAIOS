#!/bin/sh
#
# Compile the vendored WebTransport C99 library for XAIOS (B-131).
#
# This is the integration's compile step, written before the handshake gate so
# that "it compiles" is a command rather than a claim. It builds the upstream
# sources that need no backend at all, plus the XAIOS platform seam and clock
# that stand in for the POSIX ones, against the hosted libc sysroot the other
# C99 applications use.
#
# What it does NOT yet build is recorded rather than hidden: four upstream
# files call OpenSSL directly -- `src/crypto/crypto_openssl.c` and
# `src/tls/{keyshare,trust,self_signed}.c` -- and the plan is a BearSSL
# backend beside the tree. Until those exist the library cannot link, so this
# script stops at objects and says so. `docs/WEBTRANSPORT-C99-INTEGRATION.md`
# is the evidence for why those four are the whole list.
#
# Usage: build-wt-upstream.sh [--arch aarch64|x86_64|riscv64] [--out DIR]

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ARCH=aarch64
OUT=""

usage() {
  printf '%s\n' \
    'usage: build-wt-upstream.sh [--arch aarch64|x86_64|riscv64] [--out DIR]' >&2
  exit 2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --arch) [ "$#" -ge 2 ] || usage; ARCH=$2; shift 2 ;;
    --out) [ "$#" -ge 2 ] || usage; OUT=$2; shift 2 ;;
    *) usage ;;
  esac
done

case "$ARCH" in
  aarch64) TARGET=aarch64-none-elf; ARCH_FLAGS="" ;;
  x86_64)
    TARGET=x86_64-none-elf
    ARCH_FLAGS="-mcmodel=large -mno-red-zone -march=core2 -mfpmath=sse -msse2"
    ;;
  riscv64)
    TARGET=riscv64-unknown-elf
    ARCH_FLAGS="-march=rv64gc -mabi=lp64d -mcmodel=medany"
    ;;
  *) usage ;;
esac

SYSROOT="$ROOT/build/libc/$ARCH/sysroot"
[ -f "$SYSROOT/lib/libc.a" ] || {
  printf '%s\n' \
    "error: the $ARCH libc is not built; run make libc" >&2
  exit 1
}
RESOURCE=$(clang -print-resource-dir)
[ -n "$RESOURCE" ] || {
  printf '%s\n' 'error: clang did not report its resource directory' >&2
  exit 1
}

VENDOR="$ROOT/third_party/webtransport-c99"
SEAM="$ROOT/userspace/wt/xaios"
[ -d "$VENDOR/src" ] || {
  printf '%s\n' 'error: the vendored WebTransport tree is missing' >&2
  exit 1
}

OUT="${OUT:-$ROOT/build/wt-upstream/$ARCH}"
rm -rf "$OUT"
mkdir -p "$OUT"

# The feature macros are not optional: this libc hides the POSIX section of
# `time.h` -- which is where `clock_gettime` and `CLOCK_MONOTONIC` live --
# behind them, and `src/core/time.c` is the library's one clock source.
COMMON="-std=c99 -fhosted -D_POSIX_C_SOURCE=200809L -D_POSIX_MONOTONIC_CLOCK=200809L \
-fno-pic -fno-pie -fno-stack-protector -nostdinc \
-isystem $SYSROOT/include -isystem $RESOURCE/include \
-I$VENDOR/include -I$VENDOR/src -I$SEAM \
-I$ROOT/third_party/bearssl/inc -I$ROOT/third_party/bearssl/src \
-I$ROOT/userspace/wt/include -I$ROOT/userspace/include"

# The vendored sources are third-party and are compiled with the warnings but
# without `-Werror`: a warning in code this repository does not own is not a
# gate. The seam is ours and is held to the same standard as the rest.
VENDOR_WARN="-Wall -Wextra"
SEAM_WARN="-Wall -Wextra -Werror"

# The socket seam replaces the vendored POSIX platform header in the one
# translation unit that includes it. `udp_platform.h`'s include guard is
# defined on the command line, so its body is skipped and the header below
# supplies the same operations over XAIOS's UDP syscalls.
SEAM_FLAGS="-DWEBTRANSPORT_RUNTIME_UDP_PLATFORM_H -include $SEAM/wt_xaios_platform.h"

built=0

compile_one() {
  # shellcheck disable=SC2086
  clang --target="$TARGET" $ARCH_FLAGS $COMMON $1 -c "$2" -o "$OUT/$3.o"
  built=$((built + 1))
}

for source in "$VENDOR"/src/core/*.c "$VENDOR"/src/quic/*.c \
              "$VENDOR"/src/runtime/server_retry.c \
              "$VENDOR"/src/tls/extension.c "$VENDOR"/src/tls/handshake.c \
              "$VENDOR"/src/tls/keyschedule.c "$VENDOR"/src/tls/session.c; do
  compile_one "$VENDOR_WARN" "$source" "$(basename "$source" .c)"
done

# The one upstream file that needs the platform seam.
compile_one "$VENDOR_WARN $SEAM_FLAGS" "$VENDOR/src/runtime/udp.c" "udp"

# The XAIOS side of the port. The crypto backend implements upstream's
# `webtransport/crypto/crypto.h` over BearSSL; the keyshare backend replaces
# upstream's OpenSSL X25519 with the ladder this repository already checks
# against RFC 7748, and the AES block file is the same one the in-tree module
# uses.
for source in "$SEAM"/wt_xaios_platform.c "$SEAM"/wt_xaios_clock.c \
              "$SEAM"/wt_crypto_bearssl_upstream.c \
              "$SEAM"/wt_keyshare_xaios.c \
              "$ROOT"/userspace/wt/src/wt_x25519.c \
              "$ROOT"/userspace/wt/src/wt_aes128.c; do
  compile_one "$SEAM_WARN" "$source" "$(basename "$source" .c)"
done

# Said rather than left as a link error two steps later.
# Three of the four upstream OpenSSL files are now replaced rather than
# missing: `src/crypto/crypto_openssl.c` by the BearSSL backend,
# `src/tls/keyshare.c` by the XAIOS X25519 binding, and
# `src/tls/self_signed.c` by not being needed -- it is a server and test
# helper no compiled translation unit references.
printf '%s\n' \
  "wt-upstream: $built sources compiled for $ARCH into ${OUT#"$ROOT"/}"
printf '%s\n' \
  "wt-upstream: 1 upstream source still calls OpenSSL and is not built:" \
  "  src/tls/trust.c (pin-only verify); crypto_openssl.c, tls/keyshare.c and" \
  "  tls/self_signed.c are replaced or unneeded"
