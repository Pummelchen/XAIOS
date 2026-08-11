#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
ARCH=${1:-}
case "$ARCH" in
  aarch64) TARGET=aarch64-none-elf ;;
  x86_64) TARGET=x86_64-none-elf ;;
  *) printf '%s\n' 'usage: build-compiler-rt.sh aarch64|x86_64' >&2; exit 2 ;;
esac

OUT="$ROOT/build/libc/$ARCH/compiler-rt"
ARCHIVE="$ROOT/build/libc/$ARCH/sysroot/lib/libcompiler_rt_xaios.a"
SOURCE="$ROOT/third_party/compiler-rt-builtins"
mkdir -p "$OUT"

set --
COMMON="mulsc3 muldc3 clzti2"
if [ "$ARCH" = aarch64 ]; then
  SOURCES="addtf3 multf3 comparetf2 fixtfsi floatsitf subtf3 divtf3 multc3 fixtfdi floatditf trunctfdf2 extenddftf2 extendsftf2 trunctfsf2 floatunsitf floatuntitf $COMMON"
else
  SOURCES="floatuntixf floattixf mulxc3 $COMMON"
fi

for name in $SOURCES; do
  object="$OUT/$name.o"
  clang --target="$TARGET" -std=c99 -ffreestanding -fno-stack-protector \
    -fno-pic -fno-pie -Wall -Wextra -Werror -I"$SOURCE" \
    -c "$SOURCE/$name.c" -o "$object"
  set -- "$@" "$object"
done
if [ "$ARCH" = aarch64 ]; then
  object="$OUT/fp_mode.o"
  clang --target="$TARGET" -std=c99 -ffreestanding -fno-stack-protector \
    -fno-pic -fno-pie -Wall -Wextra -Werror -I"$SOURCE" \
    -c "$SOURCE/aarch64/fp_mode.c" -o "$object"
  set -- "$@" "$object"
fi
llvm-ar rcs "$ARCHIVE" "$@"
