#!/bin/sh
# Build a hosted XAIOS application against the vendored WebTransport port (B-131).
#
# This is `build-c99-app.sh` plus the port: the same hosted libc runtime and
# linker script, with the vendored library's runtime (socket, QUIC connection,
# TLS handshake), the XAIOS platform seam, this repository's BearSSL backend,
# and the BearSSL archive. The seam is force-included into `udp.c` exactly as
# the compile check does it, so the vendored POSIX branch is inert and upstream
# is unmodified.
#
# `userspace/lib/xaios_user.c` is linked in because the port reaches XAIOS
# through it -- the UDP syscalls, the monotonic clock and the entropy the key
# share draws from -- and the hosted libc does not carry those.
#
# Usage: build-wt-app.sh --arch aarch64|x86_64|riscv64 SOURCE OUTPUT
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
ARCH=""
usage() {
  printf '%s\n' \
    'usage: build-wt-app.sh --arch aarch64|x86_64|riscv64 SOURCE OUTPUT' >&2
  exit 2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --arch) [ "$#" -ge 2 ] || usage; ARCH=$2; shift 2 ;;
    --) shift; break ;;
    -*) usage ;;
    *) break ;;
  esac
done
[ "$#" -eq 2 ] || usage
SOURCE=$1
OUTPUT=$2
[ -f "$SOURCE" ] || { printf 'error: source not found: %s\n' "$SOURCE" >&2; exit 1; }

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
RUNTIME="$ROOT/build/libc/$ARCH/runtime-test"
BEARSSL_ARCHIVE="$ROOT/build/bearssl/$ARCH/libbearssl-xapt.a"
[ -f "$SYSROOT/lib/libc.a" ] && [ -f "$RUNTIME/crt0.o" ] || {
  printf '%s\n' 'error: libc is not built; run make libc first' >&2
  exit 1
}
[ -f "$BEARSSL_ARCHIVE" ] || {
  printf 'error: the BearSSL archive is not built; run scripts/build-bearssl.sh %s\n' \
    "$ARCH" >&2
  exit 1
}

VENDOR="$ROOT/third_party/webtransport-c99"
SEAM="$ROOT/userspace/wt/xaios"
OUT="$ROOT/build/wt-app/$ARCH"
mkdir -p "$OUT/objects"

CC=${CC:-clang}
RESOURCE=$($CC -print-resource-dir)

# ARCH_FLAGS, COMMON and APP_FLAGS are fixed lists selected above.
# shellcheck disable=SC2086
COMMON="--target=$TARGET $ARCH_FLAGS -std=c99 -fhosted \
-D_POSIX_C_SOURCE=200809L -D_POSIX_MONOTONIC_CLOCK=200809L \
-fno-pic -fno-pie -fno-stack-protector -ffunction-sections -fdata-sections \
-nostdinc -isystem $SYSROOT/include -isystem $RESOURCE/include \
-I$VENDOR/include -I$VENDOR/src -I$SEAM \
-I$ROOT/third_party/bearssl/inc -I$ROOT/third_party/bearssl/src \
-I$ROOT/userspace/wt/include -I$ROOT/userspace/include"

# `udp_platform.h`'s include guard is defined on the command line so its body is
# skipped and the seam supplies the same operations over XAIOS's UDP syscalls.
SEAM_FLAGS="-DWEBTRANSPORT_RUNTIME_UDP_PLATFORM_H -include $SEAM/wt_xaios_platform.h"

objects=""
compile() {
  source=$1
  name=$2
  flags=$3
  object="$OUT/objects/$name.o"
  if [ ! -f "$object" ] || [ "$source" -nt "$object" ]; then
    # shellcheck disable=SC2086
    $CC $COMMON $flags -Wall -Wextra -Werror -c "$source" -o "$object"
  fi
  objects="$objects $object"
}

# The vendored runtime: core, the QUIC connection and the TLS handshake. The
# names come from the path because session.c and handshake.c each exist twice.
for source in "$VENDOR"/src/core/*.c "$VENDOR"/src/quic/*.c \
              "$VENDOR"/src/runtime/server_retry.c \
              "$VENDOR"/src/runtime/session.c \
              "$VENDOR"/src/tls/extension.c "$VENDOR"/src/tls/handshake.c \
              "$VENDOR"/src/tls/keyschedule.c "$VENDOR"/src/tls/session.c; do
  relative=${source#"$VENDOR"/src/}
  compile "$source" "vendor-$(printf '%s' "${relative%.c}" | tr '/' '_')" ""
done
compile "$VENDOR/src/runtime/udp.c" "vendor-runtime_udp" "$SEAM_FLAGS"

# The XAIOS side of the port.
for source in "$SEAM"/wt_xaios_platform.c "$SEAM"/wt_xaios_clock.c \
              "$SEAM"/wt_crypto_bearssl_upstream.c \
              "$SEAM"/wt_keyshare_xaios.c "$SEAM"/wt_trust_xaios.c \
              "$SEAM"/wt_xaios_x509.c \
              "$ROOT"/userspace/wt/src/wt_x25519.c \
              "$ROOT"/userspace/wt/src/wt_x509_spki.c \
              "$ROOT"/userspace/wt/src/wt_sigverify.c \
              "$ROOT"/userspace/wt/src/wt_aes128.c; do
  compile "$source" "seam-$(basename "$source" .c)" ""
done

# The syscall wrappers the port reaches XAIOS through, built the way every other
# XAIOS userspace object is: freestanding, against the userspace headers.
user_object="$OUT/objects/xaios_user.o"
if [ ! -f "$user_object" ] || [ "$ROOT/userspace/lib/xaios_user.c" -nt "$user_object" ]; then
  # shellcheck disable=SC2086
  $CC --target=$TARGET $ARCH_FLAGS -std=c99 -ffreestanding -fno-stack-protector \
    -fno-builtin -fno-pic -fno-pie -Wall -Wextra -Werror \
    -I"$ROOT/userspace/include" \
    -c "$ROOT/userspace/lib/xaios_user.c" -o "$user_object"
fi

app_object="$OUT/objects/$(basename "$SOURCE" .c).o"
# shellcheck disable=SC2086
$CC $COMMON -Wall -Wextra -Werror -c "$SOURCE" -o "$app_object"

mkdir -p "$(dirname "$OUTPUT")"
# shellcheck disable=SC2086
# The libc's `thread_api.o` is deliberately absent: it and
# `userspace/lib/xaios_user.c` implement the same `xaios_thread_*` entry
# points, so linking both is a duplicate symbol -- and this application uses no
# threads, while `xaios_user.o` is what carries the socket, clock and entropy
# calls the port cannot come up without.
ld.lld -nostdlib --gc-sections -T "$ROOT/userspace/libc/linker.ld" \
  -o "$OUTPUT" "$RUNTIME/crt0.o" "$RUNTIME/runtime.o" \
  "$RUNTIME/os_adapter.o" "$RUNTIME/thread_context.o" \
  "$RUNTIME/locking.o" \
  "$app_object" "$user_object" $objects --start-group \
  "$SYSROOT/lib/libc.a" "$SYSROOT/lib/libm.a" \
  "$SYSROOT/lib/libcompiler_rt_xaios.a" "$BEARSSL_ARCHIVE" --end-group

if llvm-nm -u "$OUTPUT" | awk '$1 == "U" { found = 1 } END { exit !found }'; then
  llvm-nm -u "$OUTPUT" >&2
  printf '%s\n' 'error: application has strong unresolved symbols' >&2
  exit 1
fi
printf 'wt-app: built %s (%s)\n' "$OUTPUT" "$ARCH"
