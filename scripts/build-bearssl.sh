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
# Everything upstream ships, except the algorithms and profiles this project
# does not use and cannot reach.
#
# DES and 3DES are the whole of `src/symcipher/des_*.c`, and nothing here calls
# them. The client configures its suites explicitly through `set_suites`, and
# the DES-CBC branch of the handshake is reached only through the engine's
# `ides_cbcenc`/`ides_cbcdec` hooks, which nothing ever sets -- `ssl_hs_client.c`
# names them as struct members, not as calls. Compiling them in puts a broken
# cipher in every shipped image and keeps ten code-scanning alerts open about
# code that cannot be negotiated (B-96).
#
# The profiles go for the same reason. `ssl_client_full.c` registers every
# suite upstream knows, the DES ones among them; the two `ssl_server_full_*`
# files are a server this project never is. XAIOS builds its client from
# `ssl_client_reset` and the individual `set_default_*` calls instead.
#
# This is an exclusion rather than a list of the files to keep on purpose: the
# crypto and the TLS engine are upstream's to get right, and a project that
# names them one at a time will be wrong the first time upstream adds a module.
for relative in $(CDPATH= cd -- "$SOURCE" && find src -name '*.c' \
    ! -path 'src/symcipher/des_*' \
    ! -path 'src/ssl/ssl_client_full.c' \
    ! -path 'src/ssl/ssl_engine_default_descbc.c' \
    ! -path 'src/ssl/ssl_server_full_*' | LC_ALL=C sort); do
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
