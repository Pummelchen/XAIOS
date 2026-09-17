#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
ARCH=""
WITH_CONTROL=0

usage() {
  printf '%s\n' \
    'usage: build-user-app.sh --arch aarch64|x86_64|riscv64 [--with-control] SOURCE OUTPUT' >&2
  exit 2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --arch) [ "$#" -ge 2 ] || usage; ARCH=$2; shift 2 ;;
    --with-control) WITH_CONTROL=1; shift ;;
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
    # The same flags the RISC-V userspace is built with. medany is required
    # rather than a preference: applications are linked above the small
    # code model's reach, and the default one relocates them out of range.
    TARGET=riscv64-unknown-elf
    ARCH_FLAGS="-march=rv64gc -mabi=lp64d -mcmodel=medany"
    ;;
  *) usage ;;
esac

CLANG=${CLANG:-$(command -v clang)}
LD_LLD=${LD_LLD:-$(command -v ld.lld)}
TEMP=$(mktemp -d "${TMPDIR:-/tmp}/xaios-user-app.XXXXXX")
trap 'rm -rf "$TEMP"' EXIT HUP INT TERM

compile() {
  # ARCH_FLAGS is a fixed target-specific list selected above.
  # shellcheck disable=SC2086
  "$CLANG" --target="$TARGET" $ARCH_FLAGS -std=c99 -ffreestanding \
    -fno-stack-protector -fno-builtin -fno-pic -fno-pie -Os \
    -Wall -Wextra -Werror -I"$ROOT/userspace/include" -c "$1" -o "$2"
}

compile "$ROOT/userspace/lib/start.S" "$TEMP/start.o"
compile "$ROOT/userspace/lib/xaios_user.c" "$TEMP/xaios_user.o"
compile "$SOURCE" "$TEMP/app.o"
set -- "$TEMP/start.o" "$TEMP/xaios_user.o"
if [ "$WITH_CONTROL" = 1 ]; then
  compile "$ROOT/userspace/lib/xaios_control_client.c" "$TEMP/control.o"
  compile "$ROOT/userspace/lib/control_render_primitives.c" "$TEMP/control-primitives.o"
  compile "$ROOT/userspace/lib/control_render_system.c" "$TEMP/control-system.o"
  compile "$ROOT/userspace/lib/control_render_storage.c" "$TEMP/control-storage.o"
  compile "$ROOT/userspace/lib/control_render_ops.c" "$TEMP/control-ops.o"
  compile "$ROOT/userspace/lib/control_render_config.c" "$TEMP/control-config.o"
  compile "$ROOT/userspace/lib/control_request.c" "$TEMP/control-request.o" "$TEMP/control-parse-flags.o" \
    "$TEMP/control-parse-validate.o" "$TEMP/control-dispatch.o"
  compile "$ROOT/userspace/lib/control_parse_flags.c" "$TEMP/control-parse-flags.o"
  compile "$ROOT/userspace/lib/control_parse_validate.c" "$TEMP/control-parse-validate.o"
  compile "$ROOT/userspace/lib/control_dispatch.c" "$TEMP/control-dispatch.o"
  set -- "$@" "$TEMP/control.o" "$TEMP/control-primitives.o" "$TEMP/control-system.o" \
    "$TEMP/control-storage.o" "$TEMP/control-ops.o" "$TEMP/control-config.o" \
    "$TEMP/control-request.o"
fi
set -- "$@" "$TEMP/app.o"
mkdir -p "$(dirname "$OUTPUT")"
"$LD_LLD" -nostdlib -z max-page-size=4096 -z common-page-size=4096 \
  -T "$ROOT/userspace/init/linker.ld" -o "$OUTPUT" "$@"
llvm-readelf -h "$OUTPUT" >/dev/null
printf 'Built freestanding application: %s (%s)\n' "$OUTPUT" "$ARCH"
