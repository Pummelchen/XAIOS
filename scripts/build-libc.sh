#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
PIN=2ae376c6cdf4fef90ca2388ecf7a07457fa63cff
SOURCE="$ROOT/third_party/picolibc"
ARCHES=${XAIOS_LIBC_ARCHES:-"aarch64 x86_64"}

need() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'error: required tool not found: %s\n' "$1" >&2
    exit 1
  }
}

need git
need clang
need llvm-ar
need meson
need ninja
need python3

if [ ! -f "$SOURCE/meson.build" ]; then
  printf '%s\n' 'error: Picolibc submodule is missing; run git submodule update --init --recursive' >&2
  exit 1
fi

actual_pin=$(git -C "$SOURCE" rev-parse HEAD)
if [ "$actual_pin" != "$PIN" ]; then
  printf 'error: Picolibc source is %s, expected %s\n' "$actual_pin" "$PIN" >&2
  exit 1
fi

for arch in $ARCHES; do
  case "$arch" in
    aarch64|x86_64) ;;
    *) printf 'error: unsupported libc architecture: %s\n' "$arch" >&2; exit 1 ;;
  esac

  build="$ROOT/build/libc/$arch/picolibc"
  install="$ROOT/build/libc/$arch/install"
  sysroot="$ROOT/build/libc/$arch/sysroot"
  rm -rf "$build" "$install" "$sysroot"

  meson setup "$build" "$SOURCE" \
    --cross-file "$ROOT/libc/cross/xaios-$arch.txt" \
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
    -Dwant-math-errno=true \
    -Dtmpdir=/tmp/ \
    -Dinternal-heap=262144 \
    -Dthread-local-storage=false \
    -Dthread-local-storage-api=false \
    -Dnewlib-global-errno=true
  ninja -C "$build"
  DESTDIR="$install" meson install -C "$build" --no-rebuild
  python3 "$ROOT/scripts/prepare-libc-sysroot.py" \
    --arch "$arch" --install "$install" --output "$sysroot"
  "$ROOT/scripts/build-compiler-rt.sh" "$arch"
  "$ROOT/scripts/build-libc-runtime-test.sh" "$arch"
done
