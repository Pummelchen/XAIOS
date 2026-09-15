#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
PIN=2ae376c6cdf4fef90ca2388ecf7a07457fa63cff
SOURCE="$ROOT/third_party/picolibc"
# All three, because the tree is gated on all three. It was `aarch64 x86_64`
# while every kernel leg of `compile-check` covered aarch64, x86_64 and
# riscv64 -- so the hosted library was built for two of the architectures
# the project ships and the third had no sysroot for a userspace leg to use,
# which is why `userspace/wt/` was unbuilt for RISC-V (B-91).
ARCHES=${XAIOS_LIBC_ARCHES:-"aarch64 x86_64 riscv64"}

need() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'error: required tool not found: %s\n' "$1" >&2
    exit 1
  }
}

need clang
need llvm-ar
need meson
need ninja
need python3

# Apple's clang comes first on PATH by default on macOS, and it cannot assemble
# picolibc's RISC-V sources: its driver asks the assembler for
# `-riscv-add-build-attributes`, a backend option clang does not have, so the
# build dies several hundred ninja steps in with `Unknown command line argument
# '-riscv-add-build-attributes'` -- an error that names the option and neither
# the compiler nor the fix. CONTRIBUTING.md already says to put Homebrew LLVM
# first; this says so at the point somebody has not.
case " $ARCHES " in
  *" riscv64 "*)
    case "$(clang --version 2>/dev/null | head -1)" in
      *"Apple clang"*)
        printf '%s\n' \
          'error: clang on PATH is Apple clang, which cannot assemble' \
          "       picolibc's RISC-V sources. Put Homebrew LLVM first on PATH:" \
          '         export PATH="$(brew --prefix llvm)/bin:$PATH"' >&2
        exit 1
        ;;
    esac
    ;;
esac

if [ ! -f "$SOURCE/meson.build" ]; then
  printf '%s\n' 'error: Picolibc submodule is missing; run git submodule update --init --recursive' >&2
  exit 1
fi

if [ -n "${XAIOS_PICOLIBC_REVISION_OVERRIDE:-}" ]; then
  case "$XAIOS_PICOLIBC_REVISION_OVERRIDE" in
    *[!0-9a-f]*|'')
      printf '%s\n' 'error: XAIOS_PICOLIBC_REVISION_OVERRIDE must be lowercase hexadecimal' >&2
      exit 1
      ;;
  esac
  if [ "${#XAIOS_PICOLIBC_REVISION_OVERRIDE}" -ne 40 ]; then
    printf '%s\n' 'error: XAIOS_PICOLIBC_REVISION_OVERRIDE must contain 40 characters' >&2
    exit 1
  fi
  actual_pin=$XAIOS_PICOLIBC_REVISION_OVERRIDE
else
  need git
  actual_pin=$(git -C "$SOURCE" rev-parse HEAD)
fi
if [ "$actual_pin" != "$PIN" ]; then
  printf 'error: Picolibc source is %s, expected %s\n' "$actual_pin" "$PIN" >&2
  exit 1
fi

for arch in $ARCHES; do
  case "$arch" in
    aarch64|x86_64|riscv64) ;;
    *) printf 'error: unsupported libc architecture: %s\n' "$arch" >&2; exit 1 ;;
  esac

  build="$ROOT/build/libc/$arch/picolibc"
  install="$ROOT/build/libc/$arch/install"
  sysroot="$ROOT/build/libc/$arch/sysroot"
  rm -rf "$build" "$install" "$sysroot"

  meson setup "$build" "$SOURCE" \
    --cross-file "$ROOT/config/cross/xaios-$arch.txt" \
    --prefix / \
    --libdir lib \
    --buildtype release \
    -Dmultilib=false \
    -Dtests=false \
    -Dtests-enable-posix-io=false \
    -Dsemihost=false \
    -Dpicocrt=false \
    -Dpicocrt-lib=false \
    -Dposix-console=false \
    -Dio-c99-formats=true \
    -Dio-long-long=true \
    -Dio-long-double=true \
    -Dio-float-exact=true \
    -Dprintf-percent-n=true \
    -Dio-wchar=true \
    -Dmb-capable=true \
    -Dstdio-exit-flush=true \
    -Dstdio-locking=true \
    -Dwant-math-errno=true \
    -Dtmpdir=/tmp/ \
    -Dinternal-heap=262144 \
    -Dthread-local-storage=false \
    -Dthread-local-storage-api=false \
    -Dnewlib-global-errno=false \
    -Derrno-function=__xaios_libc_errno_location
  ninja -C "$build"
  DESTDIR="$install" meson install -C "$build" --no-rebuild
  python3 "$ROOT/scripts/prepare-libc-sysroot.py" \
    --arch "$arch" --install "$install" --output "$sysroot"
  "$ROOT/scripts/build-compiler-rt.sh" "$arch"
  "$ROOT/scripts/build-libc-runtime-test.sh" "$arch"
done
