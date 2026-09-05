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

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
BUILD="$ROOT_DIR/build"
LOG="${XAIOS_RISCV64_LOG:-$BUILD/qemu-riscv64.log}"
CPUS="${XAIOS_RISCV64_CPUS:-4}"
MEMORY="${XAIOS_RISCV64_MEMORY:-1024}"
SSH_PORT="${XAIOS_RISCV64_SSH_PORT:-2222}"
# "none" means claim no host port, which the other two runners already
# understand. A gate that does not use SSH should not be holding a fixed port:
# one stale emulator anywhere then turns every later run into a boot that
# never happened.
if [ "$SSH_PORT" = none ]; then
  HOSTFWD_ARG=""
else
  HOSTFWD_ARG=",hostfwd=tcp::$SSH_PORT-:22"
fi
QEMU="${QEMU_SYSTEM_RISCV64:-qemu-system-riscv64}"

KERNEL="$BUILD/kernel-riscv64/kernel.elf"
INITFS="$BUILD/xaios-riscv64-initfs.img"
BOOT_MEDIUM="$BUILD/xaios-riscv64.img"
[ -f "$KERNEL" ] || { printf 'error: no kernel; run scripts/build-riscv64.sh\n' >&2; exit 1; }
[ -f "$INITFS" ] || { printf 'error: no initial filesystem; run scripts/build-riscv64-image.sh\n' >&2; exit 1; }

# Volumes the guest writes to, kept out of the build tree's inputs so a run
# does not change what the next run starts from.
STATE="${XAIOS_RISCV64_STATE:-$BUILD/riscv64-run}"
mkdir -p "$STATE"
# Each volume may be named by the caller, as the other two runners allow. A
# gate that writes to a volume and then reads back what survived has to
# supply the copy it is willing to have written, and one that crashes the
# machine on purpose has to keep the wreckage. Without an override the state
# directory keeps its own, made or seeded once.
PERSISTENT_IMAGE="${XAIOS_PERSISTENT_IMAGE:-$STATE/persistent.img}"
PERSISTENT_SECTORS="${XAIOS_PERSISTENT_SECTORS:-32768}"
if [ ! -f "$PERSISTENT_IMAGE" ]; then
  dd if=/dev/zero of="$PERSISTENT_IMAGE" bs=512 count="$PERSISTENT_SECTORS" \
    status=none
fi
# The models volume. A caller may name its own, as the other two runners let
# one -- a gate that writes to this volume and then checks what survived has
# to supply the copy it is willing to have written. Without the override the
# state directory keeps its own, seeded once from the build.
if [ -n "${XAIOS_XAI_FS_IMAGE:-}" ]; then
  MODELS_IMAGE="$XAIOS_XAI_FS_IMAGE"
else
  MODELS_IMAGE="$STATE/models.img"
  [ -f "$MODELS_IMAGE" ] || cp "$BUILD/xaios-xaifs.img" "$MODELS_IMAGE"
fi
# This architecture's own signed system volume, not another architecture's:
# the loader verifies the slot and then refuses a kernel built for a machine
# this is not, which is the correct behaviour and a confusing way to discover
# that the wrong file was copied.
RISCV_SYSTEM="$BUILD/xaios-riscv64-system.img"
SYSTEM_IMAGE="${XAIOS_SYSTEM_VOLUME_IMAGE:-$STATE/system.img}"
[ -f "$SYSTEM_IMAGE" ] || cp "$RISCV_SYSTEM" "$SYSTEM_IMAGE"
# The administrative scratch disk. The aarch64 smoke gate leaves one behind in
# build/, but a fresh tree has none, and a runner that fails at `cp` before
# QEMU starts leaves no serial log and nothing to diagnose. Made here when
# absent: it is a blank disk by definition.
ADMIN_IMAGE="${XAIOS_STORAGE_ADMIN_IMAGE:-$STATE/storage-admin.img}"
if [ ! -f "$ADMIN_IMAGE" ]; then
  if [ -f "$BUILD/xaios-smoke-storage-admin.img" ]; then
    cp "$BUILD/xaios-smoke-storage-admin.img" "$ADMIN_IMAGE"
  else
    dd if=/dev/zero of="$ADMIN_IMAGE" bs=1m count=16 status=none
  fi
fi
BOOT_ARGS=""
if [ -f "$BOOT_MEDIUM" ]; then
  BOOT_ARGS="-drive if=none,format=raw,readonly=on,id=xboot,file=$BOOT_MEDIUM -device virtio-blk-pci,drive=xboot,bootindex=0,disable-legacy=on"
fi

# How the machine starts: from the kernel handed to QEMU, or from its own disk
# through UEFI firmware.
#
# This is not a preference. The two paths differ in what the guest knows about
# itself: with -kernel there is no loader, so nothing has chosen a system slot
# and nothing fills the boot record the A/B machinery reads -- the guest logs
# "system-slot: unavailable" and every gate about updates, rollback or
# metadata durability is untestable on this architecture. Through UEFI the
# loader verifies a slot, loads the kernel from it, and says which one, which
# is what a real machine does. The default stays -kernel because it is much
# faster and most gates do not care.
#
# acpi=off is required rather than incidental: with ACPI on, this EDK2 build
# publishes no device tree, and this port reads its interrupt controller, its
# timebase and its virtio window from one.
BOOT_MODE="${XAIOS_RISCV64_BOOT:-kernel}"
MACHINE="virt"
KERNEL_ARGS="-kernel $KERNEL"
# OpenSBI as the boot firmware, unless EDK2 is flashed in instead: QEMU takes
# one or the other, not both.
FIRMWARE_ARGS="-bios default"
case "$BOOT_MODE" in
  kernel) ;;
  uefi)
    FIRMWARE_CODE="${XAIOS_RISCV64_FIRMWARE_CODE:-/opt/homebrew/share/qemu/edk2-riscv-code.fd}"
    FIRMWARE_VARS="${XAIOS_RISCV64_FIRMWARE_VARS:-/opt/homebrew/share/qemu/edk2-riscv-vars.fd}"
    for file in "$FIRMWARE_CODE" "$FIRMWARE_VARS"; do
      [ -f "$file" ] || {
        printf 'error: no EDK2 RISC-V firmware at %s\n' "$file" >&2; exit 1; }
    done
    [ -f "$BOOT_MEDIUM" ] || {
      printf 'error: uefi boot needs %s; run scripts/build-riscv64-boot-media.sh\n' \
        "$BOOT_MEDIUM" >&2; exit 1; }
    # The variable store is written by the firmware, so each run gets its own
    # copy rather than editing the one homebrew installed.
    cp "$FIRMWARE_VARS" "$STATE/vars.fd"
    MACHINE="virt,acpi=off"
    KERNEL_ARGS=""
    FIRMWARE_ARGS="-drive if=pflash,format=raw,unit=0,readonly=on,file=$FIRMWARE_CODE -drive if=pflash,format=raw,unit=1,file=$STATE/vars.fd"
    ;;
  *)
    printf 'error: XAIOS_RISCV64_BOOT must be kernel or uefi\n' >&2
    exit 2
    ;;
esac

# A QMP socket and extra devices, the way the other runners take them: the
# screenshot gates add a virtio-gpu and read the screen back over QMP.
# The serial line goes to the log file unless a gate wants to type on the
# console, in which case it is the runner's own stdin and stdout.
if [ "${XAIOS_RISCV64_SERIAL:-file}" = "stdio" ]; then
  SERIAL_ARGS="-serial stdio -monitor none"
else
  SERIAL_ARGS="-serial file:$LOG"
fi
QMP_ARGS=""
if [ "${XAIOS_RISCV64_QMP_SOCKET:-}" != "" ]; then
  rm -f "$XAIOS_RISCV64_QMP_SOCKET"
  QMP_ARGS="-qmp unix:${XAIOS_RISCV64_QMP_SOCKET},server=on,wait=off"
fi
EXTRA_ARGS="${XAIOS_RISCV64_EXTRA_ARGS:-}"
# shellcheck disable=SC2086
exec "$QEMU" \
  -machine "$MACHINE" -cpu rv64 -smp "$CPUS" -m "$MEMORY" -display none \
  -global virtio-mmio.force-legacy=false \
  $SERIAL_ARGS \
  $FIRMWARE_ARGS \
  $KERNEL_ARGS \
  $BOOT_ARGS \
  -drive "if=none,format=raw,snapshot=on,id=xtest,file=$INITFS" \
  -device virtio-blk-device,drive=xtest,bus=virtio-mmio-bus.0 \
  -drive "if=none,format=raw,id=xpers,file=$PERSISTENT_IMAGE" \
  -device virtio-blk-device,drive=xpers,bus=virtio-mmio-bus.1 \
  -drive "if=none,format=raw,id=xmodels,file=$MODELS_IMAGE" \
  -device virtio-blk-device,drive=xmodels,bus=virtio-mmio-bus.4 \
  -drive "if=none,format=raw,id=xadmin,file=$ADMIN_IMAGE" \
  -device virtio-blk-device,drive=xadmin,bus=virtio-mmio-bus.5 \
  -blockdev "driver=file,node-name=sysf,filename=$SYSTEM_IMAGE,locking=off" \
  -blockdev driver=raw,node-name=sysraw,file=sysf \
  -device virtio-blk-pci,drive=sysraw,bootindex=1,disable-legacy=on \
  -blockdev "driver=file,node-name=sysf2,filename=$SYSTEM_IMAGE,locking=off" \
  -blockdev driver=raw,node-name=sysraw2,file=sysf2 \
  -device virtio-blk-device,drive=sysraw2,bus=virtio-mmio-bus.6 \
  -device virtio-rng-pci,disable-legacy=on \
  -netdev "user,id=n0$HOSTFWD_ARG" \
  -device virtio-net-pci,netdev=n0,disable-legacy=on \
  $QMP_ARGS $EXTRA_ARGS "$@"
