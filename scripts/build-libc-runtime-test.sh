#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
ARCH=${1:-}
case "$ARCH" in
  aarch64) TARGET=aarch64-none-elf ;;
  x86_64) TARGET=x86_64-none-elf ;;
  *) printf '%s\n' 'usage: build-libc-runtime-test.sh aarch64|x86_64' >&2; exit 2 ;;
esac

SYSROOT="$ROOT/build/libc/$ARCH/sysroot"
OUT="$ROOT/build/libc/$ARCH/runtime-test"
RESOURCE=$(clang -print-resource-dir)
mkdir -p "$OUT"

ARCH_FLAGS=""
if [ "$ARCH" = x86_64 ]; then
  ARCH_FLAGS="-mcmodel=large -mno-red-zone -march=core2 -mfpmath=sse -msse2"
fi

compile() {
  source=$1
  output=$2
  # ARCH_FLAGS is a fixed, whitespace-separated list selected above.
  # shellcheck disable=SC2086
  clang --target="$TARGET" $ARCH_FLAGS \
    -std=c99 -fhosted -fno-pic -fno-pie -fno-stack-protector \
    -ffunction-sections -fdata-sections -Wall -Wextra -Werror \
    -pedantic-errors -nostdinc \
    -isystem "$SYSROOT/include" -isystem "$RESOURCE/include" \
    -c "$source" -o "$output"
}

compile_main_void_runtime() {
  # shellcheck disable=SC2086
  clang --target="$TARGET" $ARCH_FLAGS \
    -std=c99 -fhosted -fno-pic -fno-pie -fno-stack-protector \
    -ffunction-sections -fdata-sections -Wall -Wextra -Werror \
    -pedantic-errors -nostdinc -DXAIOS_LIBC_MAIN_VOID=1 \
    -isystem "$SYSROOT/include" -isystem "$RESOURCE/include" \
    -c "$ROOT/userspace/libc/runtime.c" -o "$OUT/runtime_main_void.o"
}

compile_private() {
  source=$1
  output=$2
  # The adapter implements Picolibc's private OS hooks. These headers are not
  # copied into the public XAIOS application sysroot.
  # shellcheck disable=SC2086
  clang --target="$TARGET" $ARCH_FLAGS \
    -std=c99 -fhosted -fno-pic -fno-pie -fno-stack-protector \
    -ffunction-sections -fdata-sections -Wall -Wextra -Werror \
    -pedantic-errors -nostdinc \
    -isystem "$ROOT/build/libc/$ARCH/install/include" \
    -isystem "$RESOURCE/include" \
    -c "$source" -o "$output"
}

compile "$ROOT/userspace/libc/crt0.S" "$OUT/crt0.o"
compile "$ROOT/userspace/libc/runtime.c" "$OUT/runtime.o"
compile_private "$ROOT/userspace/libc/os_adapter.c" "$OUT/os_adapter.o"
compile "$ROOT/tests/libc/c99_runtime_smoke.c" "$OUT/c99_runtime_smoke.o"
compile "$ROOT/tests/libc/c99_conformance_suite.c" "$OUT/c99_conformance_suite.o"
compile "$ROOT/tests/libc/c99_language_conformance.c" "$OUT/c99_language_conformance.o"
compile_main_void_runtime
compile "$ROOT/tests/libc/c99_main_void.c" "$OUT/c99_main_void.o"
compile "$ROOT/tests/libc/c99_exit_probe.c" "$OUT/c99_exit_probe.o"
compile "$ROOT/tests/libc/c99_abort_probe.c" "$OUT/c99_abort_probe.o"

ld.lld -nostdlib --gc-sections -T "$ROOT/userspace/libc/linker.ld" \
  -o "$OUT/c99-runtime-smoke.elf" \
  "$OUT/crt0.o" "$OUT/runtime.o" "$OUT/os_adapter.o" \
  "$OUT/c99_runtime_smoke.o" "$OUT/c99_conformance_suite.o" \
  "$OUT/c99_language_conformance.o" \
  --start-group "$SYSROOT/lib/libc.a" "$SYSROOT/lib/libm.a" \
    "$SYSROOT/lib/libcompiler_rt_xaios.a" --end-group

llvm-readelf -h "$OUT/c99-runtime-smoke.elf" >/dev/null
if llvm-nm -u "$OUT/c99-runtime-smoke.elf" | grep -q .; then
  llvm-nm -u "$OUT/c99-runtime-smoke.elf" >&2
  printf '%s\n' "error: $ARCH hosted runtime has unresolved symbols" >&2
  exit 1
fi
python3 "$ROOT/tests/scripts/link-libc-symbol-probe.py" "$ARCH"

for probe in main_void exit_probe abort_probe; do
  ld.lld -nostdlib --gc-sections -T "$ROOT/userspace/libc/linker.ld" \
    -o "$OUT/c99-$probe.elf" \
    "$OUT/crt0.o" "$OUT/runtime_main_void.o" "$OUT/os_adapter.o" \
    "$OUT/c99_${probe}.o" \
    --start-group "$SYSROOT/lib/libc.a" "$SYSROOT/lib/libm.a" \
      "$SYSROOT/lib/libcompiler_rt_xaios.a" --end-group
  if llvm-nm -u "$OUT/c99-$probe.elf" | grep -q .; then
    llvm-nm -u "$OUT/c99-$probe.elf" >&2
    printf 'error: %s %s has unresolved symbols\n' "$ARCH" "$probe" >&2
    exit 1
  fi
done
