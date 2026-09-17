#!/bin/sh
# Run XAIOS on the QEMU RISC-V `virt` board, in the machine shape the other
# two architectures are tested in.
#
# The disk complement is not decoration. The kernel mounts its model volume
# from virtio transport slot 4 and opens /dev/vblk0 for the initial
# filesystem, so a machine with two disks in the wrong places boots to a login
# prompt and still fails storage tests that are working correctly. This
# mirrors platform/qemu/run-qemu-aarch64.sh bus for bus.
#
# force-legacy=false matters as much. QEMU's virtio-mmio transports default to
# the legacy interface, which the driver refuses -- it requires version 2 --
# so without it every MMIO slot reads as empty and the model volume is simply
# absent, with nothing said about why.
set -eu

# --dry-run prints the command this machine would be started with and stops,
# which is the same contract the other two runners offer. It exists so the
# machine's shape can be checked without an emulator, a build or a boot -- the
# matrix uses it that way, and until now RISC-V was the one architecture whose
# shape nothing could inspect.
dry_run=0
if [ "${1:-}" = "--dry-run" ]; then
  dry_run=1
  shift
fi

print_command() {
  printf 'QEMU RISC-V command:\n'
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

# Under --dry-run nothing that the machine would read has to exist: the point
# is the command, and requiring a built kernel to print it would make this
# useless for exactly the check it is for.
require_file() {
  if [ "$dry_run" -eq 1 ]; then
    return 0
  fi
  if [ ! -f "$1" ]; then
    printf 'error: %s\n' "$2" >&2
    exit 1
  fi
}

# The EDK2 firmware this board flashes in for a UEFI boot, wherever it lives.
#
# One name per platform and they do not agree: Homebrew ships edk2-riscv-*.fd,
# Debian's qemu-efi-riscv64 ships RISCV_VIRT_CODE.fd and RISCV_VIRT_VARS.fd.
# An explicit override comes first, as it does in the AArch64 runner, so
# firmware somewhere else is a variable rather than a patch.
find_riscv_firmware() {
  case "$1" in
    code)
      if [ "${XAIOS_RISCV64_FIRMWARE_CODE:-}" != "" ]; then
        [ -f "$XAIOS_RISCV64_FIRMWARE_CODE" ] &&
          printf '%s\n' "$XAIOS_RISCV64_FIRMWARE_CODE" && return 0
        return 1
      fi
      set -- \
        /opt/homebrew/share/qemu/edk2-riscv-code.fd \
        /usr/local/share/qemu/edk2-riscv-code.fd \
        /usr/share/qemu-efi-riscv64/RISCV_VIRT_CODE.fd \
        /usr/share/qemu/edk2-riscv-code.fd \
        /usr/share/edk2/riscv/RISCV_VIRT_CODE.fd
      ;;
    vars)
      if [ "${XAIOS_RISCV64_FIRMWARE_VARS:-}" != "" ]; then
        [ -f "$XAIOS_RISCV64_FIRMWARE_VARS" ] &&
          printf '%s\n' "$XAIOS_RISCV64_FIRMWARE_VARS" && return 0
        return 1
      fi
      set -- \
        /opt/homebrew/share/qemu/edk2-riscv-vars.fd \
        /usr/local/share/qemu/edk2-riscv-vars.fd \
        /usr/share/qemu-efi-riscv64/RISCV_VIRT_VARS.fd \
        /usr/share/qemu/edk2-riscv-vars.fd \
        /usr/share/edk2/riscv/RISCV_VIRT_VARS.fd
      ;;
    *) return 1 ;;
  esac
  for candidate do
    if [ -f "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

run_qemu() {
  if [ "$dry_run" -eq 1 ]; then
    print_command "$@"
    exit 0
  fi
  exec "$@"
}

. "$(dirname -- "$0")/run-qemu-riscv64-machine.sh"
# shellcheck disable=SC2086
run_qemu "$QEMU" \
  -machine "$MACHINE" -cpu "$CPU_MODEL" -smp "$CPUS" -m "$MEMORY" -display none \
  -global virtio-mmio.force-legacy=false \
  $IOMMU_ARGS \
  $SERIAL_ARGS \
  $FIRMWARE_ARGS \
  $KERNEL_ARGS \
  $BOOT_ARGS \
  -drive "if=none,format=raw,snapshot=on,id=xtest,file=$INITFS" \
  -device virtio-blk-device,drive=xtest,bus=virtio-mmio-bus.0 \
  -drive "if=none,format=raw,id=xpers,file=$PERSISTENT_IMAGE" \
  -device virtio-blk-device,drive=xpers,bus=virtio-mmio-bus.1 \
  $MODELS_ARGS \
  -drive "if=none,format=raw,id=xadmin,file=$ADMIN_IMAGE" \
  -device virtio-blk-device,drive=xadmin,bus=virtio-mmio-bus.5 \
  $SYSTEM_ARGS \
  $RNG_ARGS \
  -netdev user,id=n0 \
  -device virtio-net-pci,netdev=n0,disable-legacy=on \
  $NET1_ARGS \
  $KEYBOARD_ARGS \
  $NVME_ARGS \
  $QMP_ARGS $EXTRA_ARGS "$@"
