#!/bin/sh
set -eu

dry_run=0
if [ "${1:-}" = "--dry-run" ]; then
  dry_run=1
  shift
fi

if [ "$#" -ne 0 ]; then
  printf '%s\n' "usage: $0 [--dry-run]" >&2
  exit 2
fi

find_tool() {
  tool_name="$1"
  shift

  for candidate in "$@"; do
    if [ -x "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  if command -v "$tool_name" >/dev/null 2>&1; then
    command -v "$tool_name"
    return 0
  fi

  return 1
}

brew_prefix() {
  formula="$1"
  if command -v brew >/dev/null 2>&1; then
    brew --prefix "$formula" 2>/dev/null || true
  fi
}

find_ovmf_firmware() {
  if [ "${XAIOS_OVMF_CODE:-}" != "" ]; then
    [ -f "$XAIOS_OVMF_CODE" ] && printf '%s\n' "$XAIOS_OVMF_CODE" && return 0
    return 1
  fi

  for candidate in \
    /opt/homebrew/share/qemu/edk2-x86_64-code.fd \
    /opt/homebrew/share/qemu/OVMF_CODE.fd \
    /opt/homebrew/share/edk2/x64/OVMF_CODE.fd \
    /usr/local/share/qemu/edk2-x86_64-code.fd \
    /usr/local/share/qemu/OVMF_CODE.fd \
    /usr/local/share/edk2/x64/OVMF_CODE.fd \
    /usr/share/qemu/edk2-x86_64-code.fd \
    /usr/share/OVMF/OVMF_CODE_4M.fd \
    /usr/share/OVMF/OVMF_CODE.fd \
    /usr/share/ovmf/OVMF.fd \
    /usr/share/qemu/OVMF.fd \
    /usr/share/edk2/ovmf/OVMF_CODE.fd
  do
    if [ -f "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  return 1
}

print_command() {
  printf 'QEMU x86_64 command:\n'
  printf '  '
  for arg in "$@"; do
    case "$arg" in
      *[!A-Za-z0-9_./:=,+-]*|'')
        printf "'%s' " "$(printf '%s' "$arg" | sed "s/'/'\\\\''/g")"
        ;;
      *)
        printf '%s ' "$arg"
        ;;
    esac
  done
  printf '\n'
}

QEMU_PREFIX="$(brew_prefix qemu)"
QEMU_BIN=""
if [ "$QEMU_PREFIX" != "" ]; then
  QEMU_BIN="$QEMU_PREFIX/bin"
fi

if ! qemu="$(find_tool qemu-system-x86_64 "$QEMU_BIN/qemu-system-x86_64")"; then
  printf '%s\n' "error: qemu-system-x86_64 not found. Install with: brew install qemu" >&2
  exit 1
fi

if ! firmware="$(find_ovmf_firmware)"; then
  printf '%s\n' "error: x86_64 OVMF firmware not found. Set XAIOS_OVMF_CODE=/path/to/edk2-x86_64-code.fd." >&2
  exit 1
fi

accel="${XAIOS_QEMU_X86_ACCEL:-tcg}"
machine="${XAIOS_QEMU_X86_MACHINE:-q35}"
cpu="${XAIOS_QEMU_X86_CPU:-max}"
memory="${XAIOS_QEMU_X86_MEMORY:-2G}"
smp="${XAIOS_QEMU_X86_SMP:-4}"
image="${XAIOS_X86_64_IMAGE:-build/xaios-x86_64.img}"
nvme_image="${XAIOS_QEMU_X86_NVME_IMAGE:-}"

if [ "$dry_run" -eq 0 ] && [ ! -f "$image" ]; then
  printf '%s\n' "error: missing x86_64 boot image: $image" >&2
  printf '%s\n' "       Run make image-x86_64 first, or set XAIOS_X86_64_IMAGE=/path/to/image.img." >&2
  exit 1
fi

set -- "$qemu" \
  -machine "$machine" \
  -accel "$accel" \
  -cpu "$cpu" \
  -m "$memory" \
  -smp "$smp" \
  -nographic \
  -serial mon:stdio \
  -drive "if=pflash,format=raw,readonly=on,file=$firmware" \
  -drive "if=none,format=raw,id=xaios_x86_boot,file=$image" \
  -device virtio-blk-pci,drive=xaios_x86_boot,bootindex=0,disable-legacy=on \
  -netdev user,id=net0,hostfwd=tcp::2223-:22 \
  -device virtio-net-pci,netdev=net0,disable-legacy=on,mq=on

if [ "$nvme_image" != "" ]; then
  if [ "$dry_run" -eq 0 ] && [ ! -f "$nvme_image" ]; then
    printf '%s\n' "error: missing x86_64 NVMe image: $nvme_image" >&2
    exit 1
  fi
  set -- "$@" \
    -drive "if=none,format=raw,id=xaios_x86_nvme,file=$nvme_image" \
    -device nvme,drive=xaios_x86_nvme,serial=XAIOSNVME
fi

if [ "$dry_run" -eq 1 ]; then
  print_command "$@"
  exit 0
fi

exec "$@"
