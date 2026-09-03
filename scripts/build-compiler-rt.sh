#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
ARCH=${1:-}
case "$ARCH" in
  aarch64) TARGET=aarch64-none-elf ;;
  x86_64) TARGET=x86_64-none-elf ;;
  riscv64) TARGET=riscv64-unknown-elf ;;
  *) printf '%s\n' 'usage: build-compiler-rt.sh aarch64|x86_64|riscv64' >&2; exit 2 ;;
esac

OUT="$ROOT/build/libc/$ARCH/compiler-rt"
ARCHIVE="$ROOT/build/libc/$ARCH/sysroot/lib/libcompiler_rt_xaios.a"
SOURCE="$ROOT/third_party/compiler-rt-builtins"
mkdir -p "$OUT"

ARCH_FLAGS=""
if [ "$ARCH" = riscv64 ]; then
  ARCH_FLAGS="-march=rv64gc -mabi=lp64d -mcmodel=medany"
fi

set --
COMMON="mulsc3 muldc3 clzti2"
# riscv64 lp64d has a 128-bit long double, the same as aarch64, so it needs
# the same quad-precision soft-float builtins. x86-64's 80-bit x87 format
# needs a different set entirely.
if [ "$ARCH" = aarch64 ] || [ "$ARCH" = riscv64 ]; then
  SOURCES="addtf3 multf3 comparetf2 fixtfsi floatsitf subtf3 divtf3 multc3 fixtfdi floatditf trunctfdf2 extenddftf2 extendsftf2 trunctfsf2 floatunsitf floatuntitf $COMMON"
else
  SOURCES="floatuntixf floattixf mulxc3 $COMMON"
fi

for name in $SOURCES; do
  object="$OUT/$name.o"
  # shellcheck disable=SC2086
  clang --target="$TARGET" $ARCH_FLAGS -std=c99 -ffreestanding \
    -fno-stack-protector -fno-pic -fno-pie -Wall -Wextra -Werror -I"$SOURCE" \
    -c "$SOURCE/$name.c" -o "$object"
  set -- "$@" "$object"
done
# The floating-point mode adapter, which is per-architecture because the
# rounding mode and the inexact flag live in a different register on each.
# x86-64 does not need one: its quad-precision path is not built here.
FP_MODE_SOURCE=""
case "$ARCH" in
  aarch64) FP_MODE_SOURCE="$SOURCE/aarch64/fp_mode.c" ;;
  riscv64) FP_MODE_SOURCE="$SOURCE/riscv/fp_mode.c" ;;
esac
if [ "$FP_MODE_SOURCE" != "" ]; then
  object="$OUT/fp_mode.o"
  # shellcheck disable=SC2086
  clang --target="$TARGET" $ARCH_FLAGS -std=c99 -ffreestanding \
    -fno-stack-protector -fno-pic -fno-pie -Wall -Wextra -Werror \
    -I"$SOURCE" -c "$FP_MODE_SOURCE" -o "$object"
  set -- "$@" "$object"
fi
llvm-ar rcs "$ARCHIVE" "$@"
