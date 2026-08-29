#!/bin/sh
# Build a disk that looks like a machine XAIOS has been installed onto, rather
# than a machine running XAIOS from an image with volumes attached beside it.
#
# The difference is the whole point of this script. Every other disk this
# repository builds is part of a test bench: the boot medium is one device and
# each volume the kernel wants is another, pinned to a known slot, because that
# makes a gate deterministic. A real installation has one disk. Its firmware
# partition and its durable state are partitions of that single disk, and
# nothing tells the kernel where either one is -- it has to look.
#
# So this produces a GPT disk with two partitions:
#
#   1. An EFI System Partition, FAT, holding the loader and the kernel. This is
#      what the firmware boots.
#   2. A partition typed XAIOS_GPT_TYPE_STATEFS holding a xaibootFS volume.
#      This is what the kernel finds by walking the partition table, and it is
#      found by its type rather than its position, because its position is not
#      knowable in advance.
#
# Booting the result with a single -drive and nothing else attached is the
# configuration an installed machine actually has, and it is the only
# configuration that exercises the discovery path at all.
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
BUILD_DIR="$ROOT_DIR/build"
OUTPUT="${XAIOS_INSTALLED_DISK:-$BUILD_DIR/installed-disk.img}"

# Sizes in 512-byte sectors. The ESP is sized for two architectures' loaders,
# kernels and initial filesystems with room to spare; the state partition is
# sized for the xaibootFS image the generator produces.
ESP_FIRST=2048
ESP_LAST=198655
STATE_FIRST=198656
STATE_LAST=329727
DISK_SECTORS=$((STATE_LAST + 2049))

for tool in mformat mmd mcopy; do
  command -v "$tool" >/dev/null 2>&1 || {
    printf 'error: %s is required\n' "$tool" >&2
    exit 1
  }
done

LOADER="$BUILD_DIR/uefi/BOOTAA64.EFI"
KERNEL="$BUILD_DIR/kernel/kernel.elf"
INITFS="$BUILD_DIR/xaios-virtio-test.img"
for required in "$LOADER" "$KERNEL" "$INITFS"; do
  [ -f "$required" ] || {
    printf 'missing: %s\nrun ./scripts/build-image.sh first\n' "$required" >&2
    exit 1
  }
done

ENTROPY_SEED="$BUILD_DIR/installed-entropy.seed"
# Exactly XAIOS_BOOT_INFO_ENTROPY_SEED_BYTES; a short file makes the loader
# return EFI_LOAD_ERROR and the machine powers off having printed nothing.
[ -f "$ENTROPY_SEED" ] || dd if=/dev/urandom of="$ENTROPY_SEED" bs=64 count=1 status=none

ESP_IMAGE="$BUILD_DIR/installed-esp.img"
ESP_SECTORS=$((ESP_LAST - ESP_FIRST + 1))
rm -f "$ESP_IMAGE"
dd if=/dev/zero of="$ESP_IMAGE" bs=512 count="$ESP_SECTORS" status=none
mformat -i "$ESP_IMAGE" -v XAIOS ::
mmd -i "$ESP_IMAGE" ::/EFI ::/EFI/BOOT ::/EFI/XAIOS
mcopy -i "$ESP_IMAGE" "$LOADER" ::/EFI/BOOT/BOOTAA64.EFI
mcopy -i "$ESP_IMAGE" "$LOADER" ::/EFI/XAIOS/XAIOS.EFI
mcopy -i "$ESP_IMAGE" "$KERNEL" ::/EFI/XAIOS/kernel.elf
mcopy -i "$ESP_IMAGE" "$INITFS" ::/EFI/XAIOS/initfs.img
mcopy -i "$ESP_IMAGE" "$ENTROPY_SEED" ::/EFI/XAIOS/entropy.sed

# A freshly formatted durable volume, not a copy of the shared one: the
# lifecycle record lives on it, and inheriting another gate's boot counts is
# what once put a healthy system into rescue mode.
STATE_IMAGE="$BUILD_DIR/installed-state.img"
rm -f "$STATE_IMAGE"
XAIOS_PERSISTENT_IMAGE="$STATE_IMAGE" "$ROOT_DIR/scripts/create-persistent-image.sh" >/dev/null

rm -f "$OUTPUT"
dd if=/dev/zero of="$OUTPUT" bs=512 count="$DISK_SECTORS" status=none
dd if="$ESP_IMAGE" of="$OUTPUT" bs=512 seek="$ESP_FIRST" conv=notrunc status=none
dd if="$STATE_IMAGE" of="$OUTPUT" bs=512 seek="$STATE_FIRST" conv=notrunc status=none

XAIOS_GPT_ESP_FIRST="$ESP_FIRST" XAIOS_GPT_ESP_LAST="$ESP_LAST" \
XAIOS_GPT_STATE_FIRST="$STATE_FIRST" XAIOS_GPT_STATE_LAST="$STATE_LAST" \
XAIOS_GPT_DISK="$OUTPUT" XAIOS_GPT_SECTORS="$DISK_SECTORS" \
  "${PYTHON:-python3}" "$ROOT_DIR/tools/xaios_write_gpt.py"

printf '%s\n' "XAIOS installed disk: $OUTPUT"
printf '%s\n' "  size:      $(wc -c < "$OUTPUT") bytes"
printf '%s\n' "  ESP:       LBA $ESP_FIRST-$ESP_LAST"
printf '%s\n' "  xaibootFS: LBA $STATE_FIRST-$STATE_LAST"
printf '%s\n' "  boot with: one drive and nothing else attached"
