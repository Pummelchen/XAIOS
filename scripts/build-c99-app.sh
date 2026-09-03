#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
ARCH=""
MAIN_FORM=args

usage() {
  printf '%s\n' \
    'usage: build-c99-app.sh --arch aarch64|x86_64|riscv64 [--main args|void] SOURCE OUTPUT' >&2
  exit 2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --arch) [ "$#" -ge 2 ] || usage; ARCH=$2; shift 2 ;;
    --main) [ "$#" -ge 2 ] || usage; MAIN_FORM=$2; shift 2 ;;
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
    # medany because hosted applications link where every other XAIOS
    # userspace image does, past what the default code model can address
    # through lui.
    ARCH_FLAGS="-march=rv64gc -mabi=lp64d -mcmodel=medany"
    ;;
  *) usage ;;
esac
case "$MAIN_FORM" in args|void) ;; *) usage ;; esac

SYSROOT="$ROOT/build/libc/$ARCH/sysroot"
RUNTIME="$ROOT/build/libc/$ARCH/runtime-test"
[ -f "$SYSROOT/lib/libc.a" ] && [ -f "$RUNTIME/crt0.o" ] || {
  printf '%s\n' 'error: libc is not built; run make libc first' >&2
  exit 1
}

RESOURCE=$(clang -print-resource-dir)
TEMP=$(mktemp -d "${TMPDIR:-/tmp}/xaios-c99-app.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM
OBJECT="$TEMP/app.o"
RUNTIME_OBJECT="$RUNTIME/runtime.o"
if [ "$MAIN_FORM" = void ]; then
  RUNTIME_OBJECT="$RUNTIME/runtime_main_void.o"
fi

# ARCH_FLAGS is a fixed list selected above.
# shellcheck disable=SC2086
clang --target="$TARGET" $ARCH_FLAGS -std=c99 -fhosted -fno-pic -fno-pie \
  -fno-stack-protector -ffunction-sections -fdata-sections \
  -Wall -Wextra -Werror -pedantic-errors -nostdinc \
  -isystem "$SYSROOT/include" -isystem "$RESOURCE/include" \
  -c "$SOURCE" -o "$OBJECT"

mkdir -p "$(dirname "$OUTPUT")"
ld.lld -nostdlib --gc-sections -T "$ROOT/userspace/libc/linker.ld" \
  -o "$OUTPUT" "$RUNTIME/crt0.o" "$RUNTIME_OBJECT" \
  "$RUNTIME/os_adapter.o" "$RUNTIME/thread_context.o" \
  "$RUNTIME/locking.o" "$RUNTIME/thread_api.o" "$OBJECT" --start-group \
  "$SYSROOT/lib/libc.a" "$SYSROOT/lib/libm.a" \
  "$SYSROOT/lib/libcompiler_rt_xaios.a" --end-group

if llvm-nm -u "$OUTPUT" | awk '$1 == "U" { found = 1 } END { exit !found }'; then
  llvm-nm -u "$OUTPUT" >&2
  printf '%s\n' 'error: application has strong unresolved symbols' >&2
  exit 1
fi
llvm-readelf -h "$OUTPUT" >/dev/null
printf 'Built hosted C99 application: %s (%s, main=%s)\n' \
  "$OUTPUT" "$ARCH" "$MAIN_FORM"
