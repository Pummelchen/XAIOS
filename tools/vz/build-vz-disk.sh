#!/bin/sh
# Build a Virtualization.framework boot disk for XAIOS.
#
# The QEMU boot image cannot be used directly. It is a bare FAT filesystem
# with no partition table, and it carries no initfs: under QEMU the initramfs
# arrives on a second virtio-mmio device, a transport Virtualization.framework
# does not offer. This assembles the layout the UEFI loader actually looks
# for, the same one the Fusion bundle uses, and wraps it in a GPT whose single
# partition is a real EFI System Partition.
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
BUILD_DIR="$ROOT_DIR/build"
OUT_DIR="$BUILD_DIR/vz"
ESP_IMAGE="$OUT_DIR/esp.img"
DISK_IMAGE="${1:-$OUT_DIR/xaios-vz-disk.img}"
ESP_MIB="${XAIOS_VZ_ESP_MIB:-64}"

for required in "$BUILD_DIR/uefi/BOOTAA64.EFI" "$BUILD_DIR/kernel/kernel.elf" \
                "$BUILD_DIR/xaios-virtio-test.img"; do
  [ -f "$required" ] || { printf 'missing: %s\nrun ./scripts/build-image.sh first\n' "$required" >&2; exit 1; }
done

mkdir -p "$OUT_DIR"

# The loader treats the entropy seed as optional, but a boot without one draws
# attention to itself in the logs; provide the same file the Fusion path does.
ENTROPY_SEED="$BUILD_DIR/fusion-entropy.seed"
if [ ! -f "$ENTROPY_SEED" ]; then
  # The loader requires exactly XAIOS_BOOT_INFO_ENTROPY_SEED_BYTES, which is
  # 64. A short file makes it return EFI_LOAD_ERROR and the machine powers off
  # with nothing printed, because this platform gives it no console.
  dd if=/dev/urandom of="$ENTROPY_SEED" bs=64 count=1 status=none
fi

rm -f "$ESP_IMAGE"
dd if=/dev/zero of="$ESP_IMAGE" bs=1048576 count="$ESP_MIB" status=none
mformat -i "$ESP_IMAGE" -F -v XAIOS_ESP ::
mmd -i "$ESP_IMAGE" ::/EFI ::/EFI/BOOT ::/EFI/XAIOS
# No chainloader here: the loader goes straight on the removable-media path,
# which is what firmware tries when no boot entry names anything else.
mcopy -i "$ESP_IMAGE" "$BUILD_DIR/uefi/BOOTAA64.EFI" ::/EFI/BOOT/BOOTAA64.EFI
mcopy -i "$ESP_IMAGE" "$BUILD_DIR/uefi/BOOTAA64.EFI" ::/EFI/XAIOS/XAIOS.EFI
mcopy -i "$ESP_IMAGE" "$BUILD_DIR/kernel/kernel.elf" ::/EFI/XAIOS/kernel.elf
mcopy -i "$ESP_IMAGE" "$BUILD_DIR/xaios-virtio-test.img" ::/EFI/XAIOS/initfs.img
mcopy -i "$ESP_IMAGE" "$ENTROPY_SEED" ::/EFI/XAIOS/entropy.seed

python3 "$ROOT_DIR/tools/vz/make_vz_disk.py" "$ESP_IMAGE" "$DISK_IMAGE"
printf 'ESP contents:\n'
mdir -i "$ESP_IMAGE" ::/EFI/XAIOS
