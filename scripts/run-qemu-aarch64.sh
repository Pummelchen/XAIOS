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

find_aavmf_firmware() {
  if [ "${XAIOS_AAVMF_CODE:-}" != "" ]; then
    [ -f "$XAIOS_AAVMF_CODE" ] && printf '%s\n' "$XAIOS_AAVMF_CODE" && return 0
    return 1
  fi

  for candidate in \
    /opt/homebrew/share/qemu/edk2-aarch64-code.fd \
    /opt/homebrew/share/qemu/QEMU_EFI.fd \
    /opt/homebrew/share/edk2/aarch64/QEMU_EFI.fd \
    /opt/homebrew/share/edk2/aarch64/QEMU_EFI-pflash.raw \
    /usr/local/share/qemu/edk2-aarch64-code.fd \
    /usr/local/share/qemu/QEMU_EFI.fd \
    /usr/local/share/edk2/aarch64/QEMU_EFI.fd \
    /usr/local/share/edk2/aarch64/QEMU_EFI-pflash.raw \
    /usr/share/AAVMF/AAVMF_CODE.fd \
    /usr/share/AAVMF/AAVMF32_CODE.fd \
    /usr/share/qemu-efi-aarch64/QEMU_EFI.fd \
    /usr/share/edk2/aarch64/QEMU_EFI.fd
  do
    if [ -f "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  return 1
}

print_command() {
  printf 'QEMU AArch64 command:\n'
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

if ! qemu="$(find_tool qemu-system-aarch64 "$QEMU_BIN/qemu-system-aarch64")"; then
  printf '%s\n' "error: qemu-system-aarch64 not found. Install with: brew install qemu" >&2
  exit 1
fi

if ! firmware="$(find_aavmf_firmware)"; then
  printf '%s\n' "error: AArch64 UEFI firmware not found. Set XAIOS_AAVMF_CODE=/path/to/edk2-aarch64-code.fd." >&2
  exit 1
fi

accel="${XAIOS_QEMU_ACCEL:-tcg}"
if [ "$accel" = "hvf" ]; then
  printf '%s\n' \
    "warning: AArch64 HVF is experimental for XAIOS and may abort in QEMU exception handling; use XAIOS_QEMU_ACCEL=tcg for correctness gates" >&2
fi

case "$accel" in
  hvf) cpu="${XAIOS_QEMU_CPU:-host}" ;;
  *) cpu="${XAIOS_QEMU_CPU:-cortex-a72}" ;;
esac

machine="${XAIOS_QEMU_MACHINE:-virt}"
memory="${XAIOS_QEMU_MEMORY:-2G}"
smp="${XAIOS_QEMU_SMP:-4}"
image="${XAIOS_AARCH64_IMAGE:-build/xaios-aarch64.img}"
test_block_image="${XAIOS_TEST_BLOCK_IMAGE:-build/xaios-virtio-test.img}"
persistent_image="${XAIOS_PERSISTENT_IMAGE:-build/xaios-persistent.img}"
hostfwd_port="${XAIOS_QEMU_HOSTFWD_PORT:-2222}"

if [ "$dry_run" -eq 0 ] && [ ! -f "$image" ]; then
  printf '%s\n' "error: missing AArch64 boot image: $image" >&2
  printf '%s\n' "       Complete WP-003/WP-004 image creation first, or set XAIOS_AARCH64_IMAGE=/path/to/image.img." >&2
  exit 1
fi

if [ "$dry_run" -eq 0 ] && [ ! -f "$test_block_image" ]; then
  printf '%s\n' "error: missing VirtIO test block image: $test_block_image" >&2
  printf '%s\n' "       Run make image first, or set XAIOS_TEST_BLOCK_IMAGE=/path/to/image.img." >&2
  exit 1
fi

if [ "$dry_run" -eq 0 ] && [ ! -f "$persistent_image" ]; then
  printf '%s\n' "note: persistent image not found, creating: $persistent_image"
  dd if=/dev/zero of="$persistent_image" bs=512 count=8192 status=none
fi

set -- "$qemu" \
  -machine "$machine,accel=$accel,gic-version=3" \
  -cpu "$cpu" \
  -m "$memory" \
  -smp "$smp" \
  -global virtio-mmio.force-legacy=false \
  -nographic \
  -serial mon:stdio \
  -drive "if=pflash,format=raw,readonly=on,file=$firmware" \
  -drive "if=virtio,format=raw,file=$image" \
  -drive "if=none,format=raw,id=xaios_test_block,file=$test_block_image" \
  -device virtio-blk-device,drive=xaios_test_block,bus=virtio-mmio-bus.0 \
  -drive "if=none,format=raw,id=xaios_persistent,file=$persistent_image" \
  -device virtio-blk-device,drive=xaios_persistent,bus=virtio-mmio-bus.1

if [ "$hostfwd_port" = "none" ]; then
  set -- "$@" -netdev user,id=net0
else
  set -- "$@" -netdev "user,id=net0,hostfwd=tcp::${hostfwd_port}-:22"
fi

set -- "$@" \
  -device virtio-net-pci,netdev=net0 \
  -netdev user,id=net1 \
  -device virtio-net-device,netdev=net1

if [ "$dry_run" -eq 1 ]; then
  print_command "$@"
  exit 0
fi

exec "$@"
