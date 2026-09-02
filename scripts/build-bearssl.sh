#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
ARCH=${1:?usage: build-bearssl.sh aarch64|x86_64}
SOURCE="$ROOT/third_party/bearssl"
case "$ARCH" in
  aarch64) TARGET=aarch64-none-elf ;;
  x86_64) TARGET=x86_64-none-elf; ARCH_CFLAGS="-mcmodel=large -march=core2" ;;
  riscv64) TARGET=riscv64-unknown-elf; ARCH_CFLAGS="-march=rv64gc -mabi=lp64d -mcmodel=medany -mno-relax" ;;
  *) printf 'error: unsupported BearSSL architecture: %s\n' "$ARCH" >&2; exit 2 ;;
esac
ARCH_CFLAGS=${ARCH_CFLAGS:-}

SYSROOT="$ROOT/build/libc/$ARCH/sysroot"
BUILD="$ROOT/build/bearssl/$ARCH"
ARCHIVE="$BUILD/libbearssl-xapt.a"
[ -f "$SYSROOT/include/string.h" ] ||
  XAIOS_LIBC_ARCHES="$ARCH" "$ROOT/scripts/build-libc.sh"
mkdir -p "$BUILD/objects"

set --
for relative in $(CDPATH= cd -- "$SOURCE" && find src -name '*.c' | LC_ALL=C sort); do
  source="$SOURCE/$relative"
  object="$BUILD/objects/$(printf '%s' "$relative" | tr '/' '_').o"
  clang --target="$TARGET" $ARCH_CFLAGS -std=c99 -ffreestanding -fno-builtin -fno-pic \
    -fno-pie -Os -Wall -Wextra -Werror \
    -isystem "$SYSROOT/include" -I"$SOURCE/inc" -I"$SOURCE/src" \
    -c "$source" -o "$object"
  set -- "$@" "$object"
done
llvm-ar rcs "$ARCHIVE" "$@"
printf 'Built BearSSL xapt archive: %s\n' "$ARCHIVE"
