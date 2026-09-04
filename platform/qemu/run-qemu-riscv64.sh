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
[ -f "$STATE/persistent.img" ] || dd if=/dev/zero of="$STATE/persistent.img" bs=1m count=16 status=none
[ -f "$STATE/models.img" ] || cp "$BUILD/xaios-xaifs.img" "$STATE/models.img"
# This architecture's own signed system volume, not another architecture's:
# the loader verifies the slot and then refuses a kernel built for a machine
# this is not, which is the correct behaviour and a confusing way to discover
# that the wrong file was copied.
RISCV_SYSTEM="$BUILD/xaios-riscv64-system.img"
[ -f "$STATE/system.img" ] || cp "$RISCV_SYSTEM" "$STATE/system.img"
# The administrative scratch disk. The aarch64 smoke gate leaves one behind in
# build/, but a fresh tree has none, and a runner that fails at `cp` before
# QEMU starts leaves no serial log and nothing to diagnose. Made here when
# absent: it is a blank disk by definition.
if [ ! -f "$STATE/storage-admin.img" ]; then
  if [ -f "$BUILD/xaios-smoke-storage-admin.img" ]; then
    cp "$BUILD/xaios-smoke-storage-admin.img" "$STATE/storage-admin.img"
  else
    dd if=/dev/zero of="$STATE/storage-admin.img" bs=1m count=16 status=none
  fi
fi
BOOT_ARGS=""
if [ -f "$BOOT_MEDIUM" ]; then
  BOOT_ARGS="-drive if=none,format=raw,readonly=on,id=xboot,file=$BOOT_MEDIUM -device virtio-blk-pci,drive=xboot,bootindex=0,disable-legacy=on"
fi

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
  -machine virt -cpu rv64 -smp "$CPUS" -m "$MEMORY" -display none \
  -bios default -global virtio-mmio.force-legacy=false \
  $SERIAL_ARGS \
  -kernel "$KERNEL" \
  $BOOT_ARGS \
  -drive "if=none,format=raw,snapshot=on,id=xtest,file=$INITFS" \
  -device virtio-blk-device,drive=xtest,bus=virtio-mmio-bus.0 \
  -drive "if=none,format=raw,id=xpers,file=$STATE/persistent.img" \
  -device virtio-blk-device,drive=xpers,bus=virtio-mmio-bus.1 \
  -drive "if=none,format=raw,id=xmodels,file=$STATE/models.img" \
  -device virtio-blk-device,drive=xmodels,bus=virtio-mmio-bus.4 \
  -drive "if=none,format=raw,id=xadmin,file=$STATE/storage-admin.img" \
  -device virtio-blk-device,drive=xadmin,bus=virtio-mmio-bus.5 \
  -blockdev "driver=file,node-name=sysf,filename=$STATE/system.img,locking=off" \
  -blockdev driver=raw,node-name=sysraw,file=sysf \
  -device virtio-blk-pci,drive=sysraw,bootindex=1,disable-legacy=on \
  -blockdev "driver=file,node-name=sysf2,filename=$STATE/system.img,locking=off" \
  -blockdev driver=raw,node-name=sysraw2,file=sysf2 \
  -device virtio-blk-device,drive=sysraw2,bus=virtio-mmio-bus.6 \
  -device virtio-rng-pci,disable-legacy=on \
  -netdev "user,id=n0,hostfwd=tcp::$SSH_PORT-:22" \
  -device virtio-net-pci,netdev=n0,disable-legacy=on \
  $QMP_ARGS $EXTRA_ARGS "$@"
