#!/bin/sh
# Build one file that boots a machine with no disk.
#
# Network boot gives firmware exactly one thing to fetch. It asks DHCP for a
# filename, pulls that file over TFTP, and runs it -- and then it is done. There
# is no filesystem behind it, no second request, nowhere to go back to for a
# kernel. So the one file has to be the whole system.
#
# This appends the kernel, the initial filesystem and an entropy seed to the
# loader as PE sections. The loader looks for them in the image the firmware
# mapped for it and uses them when they are there; the ordinary loader on an
# EFI System Partition has no such sections and reads its files as it always
# has. One binary, two ways of finding what it needs.
#
# What this deliberately does not do is fetch anything itself. A loader with a
# network stack would be a second implementation of DHCP and TFTP living in
# firmware context, to save copying eleven megabytes once.
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
BUILD_DIR="$ROOT_DIR/build"
ARCH="${XAIOS_TARGET_ARCH:-aarch64}"

case "$ARCH" in
  aarch64)
    LOADER="$BUILD_DIR/uefi/BOOTAA64.EFI"
    KERNEL="$BUILD_DIR/kernel/kernel.elf"
    INITFS="$BUILD_DIR/xaios-virtio-test.img"
    OUTPUT="${XAIOS_NETBOOT_IMAGE:-$BUILD_DIR/netboot/BOOTAA64.EFI}"
    ;;
  x86_64)
    LOADER="$BUILD_DIR/uefi-x86_64/BOOTX64.EFI"
    KERNEL="$BUILD_DIR/kernel-x86_64/kernel.elf"
    INITFS="$BUILD_DIR/xaios-x86-virtio-test.img"
    OUTPUT="${XAIOS_NETBOOT_IMAGE:-$BUILD_DIR/netboot/BOOTX64.EFI}"
    ;;
  riscv64)
    LOADER="$BUILD_DIR/riscv64-uefi/BOOTRISCV64.EFI"
    KERNEL="$BUILD_DIR/kernel-riscv64/kernel.elf"
    INITFS="$BUILD_DIR/xaios-riscv64-initfs.img"
    OUTPUT="${XAIOS_NETBOOT_IMAGE:-$BUILD_DIR/netboot/BOOTRISCV64.EFI}"
    ;;
  *)
    printf '%s\n' \
      "error: XAIOS_TARGET_ARCH must be aarch64, x86_64 or riscv64" >&2
    exit 2
    ;;
esac

OBJCOPY="${XAIOS_OBJCOPY:-}"
if [ -z "$OBJCOPY" ]; then
  for candidate in llvm-objcopy /opt/homebrew/opt/llvm/bin/llvm-objcopy \
                   /usr/lib/llvm-18/bin/llvm-objcopy objcopy; do
    if command -v "$candidate" >/dev/null 2>&1; then OBJCOPY="$candidate"; break; fi
    if [ -x "$candidate" ]; then OBJCOPY="$candidate"; break; fi
  done
fi
[ -n "$OBJCOPY" ] || {
  printf '%s\n' "error: no llvm-objcopy or objcopy found" >&2
  exit 1
}

for required in "$LOADER" "$KERNEL" "$INITFS"; do
  [ -f "$required" ] || {
    printf 'missing: %s\nrun ./scripts/build-image.sh first\n' "$required" >&2
    exit 1
  }
done

SEED="$BUILD_DIR/netboot-entropy.seed"
# Exactly XAIOS_BOOT_INFO_ENTROPY_SEED_BYTES. The loader ignores a section of
# any other length rather than seeding from a short read.
[ -f "$SEED" ] || dd if=/dev/urandom of="$SEED" bs=64 count=1 status=none

mkdir -p "$(dirname "$OUTPUT")"
rm -f "$OUTPUT"

# Section names are eight bytes in PE, which is why these are terse rather
# than descriptive. Read-only data: nothing writes to them, and a section the
# firmware need not make writable is one fewer thing to get wrong.
#
# .xaiosl is a copy of the loader as a file, and it is here because a netbooted
# machine installing onto a disk has to write one. It cannot write the binary
# it is running: firmware maps a PE with its sections at their virtual
# addresses, so the image in memory is not the file it came from, and writing
# that back out produces something firmware faults on rather than boots --
# measured, as a synchronous exception in ArmCpuDxe before any of our code ran.
#
# Carrying the plain loader avoids the circularity of embedding a copy of the
# finished file inside itself, and produces a better installed disk: an
# ordinary EFI System Partition with a loader, a kernel and an initial
# filesystem, exactly as an installer from media would write.
"$OBJCOPY" \
  --add-section .xaiosl="$LOADER" --set-section-flags .xaiosl=readonly,data \
  --add-section .xaiosk="$KERNEL" --set-section-flags .xaiosk=readonly,data \
  --add-section .xaiosi="$INITFS" --set-section-flags .xaiosi=readonly,data \
  --add-section .xaiose="$SEED" --set-section-flags .xaiose=readonly,data \
  "$LOADER" "$OUTPUT"

printf '%s\n' "XAIOS netboot image: $OUTPUT"
printf '%s\n' "  architecture: $ARCH"
printf '%s\n' "  size:         $(wc -c < "$OUTPUT" | tr -d ' ') bytes"
printf '%s\n' "  loader:       $(wc -c < "$LOADER" | tr -d ' ') bytes"
printf '%s\n' "  kernel:       $(wc -c < "$KERNEL" | tr -d ' ') bytes"
printf '%s\n' "  initfs:       $(wc -c < "$INITFS" | tr -d ' ') bytes"
printf '%s\n' "  serve as:     the DHCP boot filename, over TFTP"
