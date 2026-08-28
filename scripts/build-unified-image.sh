#!/bin/sh
# Build one bootable XAIOS image for every environment that can run it.
#
# The output is a hybrid: an ISO 9660 filesystem that is simultaneously a
# GPT-partitioned disk carrying an EFI System Partition. One file, three ways
# in, which is what makes it a single deliverable rather than four:
#
#   - Firmware that boots optical media reads the El Torito entry. VMware
#     Fusion attaches this as a CD-ROM and boots it that way.
#   - Firmware that boots disks finds the EFI System Partition in the GPT.
#     QEMU and Virtualization.framework attach it as a drive; a USB stick
#     written with dd is the same thing on real hardware.
#   - Anything that just wants to read it mounts the ISO. On macOS that is
#     hdiutil attach; on Linux, mount -o loop.
#
# Both architectures ride along. UEFI firmware picks its own loader from the
# removable-media path -- BOOTAA64.EFI on ARM, BOOTX64.EFI on Intel -- and
# each loader asks for its own kernel by name, so the image is one file rather
# than one file per instruction set.
#
# What it deliberately does not carry is the durable volume. An ISO is
# read-only, and XAIOS keeps its state on a writable xaibootFS volume; that
# stays a separate disk the platform attaches. Booting from read-only media
# without one is a supported thing to do -- the system comes up and says the
# volume is missing rather than pretending otherwise.
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
BUILD_DIR="$ROOT_DIR/build"
STAGE_DIR="$BUILD_DIR/unified-root"
ESP_IMAGE="$BUILD_DIR/unified-esp.img"
# Named for the build it is, so a file that has left this repository still
# says which one it came from. BUILD_NUMBER is the single source.
BUILD_NUMBER="$(tr -d ' \n' < "$ROOT_DIR/BUILD_NUMBER" 2>/dev/null || printf '%s' 0)"
OUTPUT="${XAIOS_UNIFIED_IMAGE:-$BUILD_DIR/xaios_b${BUILD_NUMBER}.iso}"
ESP_MIB="${XAIOS_UNIFIED_ESP_MIB:-96}"

for tool in xorriso mformat mmd mcopy; do
  command -v "$tool" >/dev/null 2>&1 || {
    printf 'error: %s is required\n' "$tool" >&2
    exit 1
  }
done

AARCH64_LOADER="$BUILD_DIR/uefi/BOOTAA64.EFI"
# VMware Fusion's firmware will not launch the XAIOS loader from the
# removable-media path directly -- it boots nothing and prints nothing. It does
# launch GRUB, which then chainloads the same loader, and that is why the
# Fusion profile has carried a chainloader all along. Putting GRUB at
# \EFI\BOOT\BOOTAA64.EFI here is what makes one image boot on all four rather
# than three: the other three launch GRUB perfectly well, and its only job is
# to search for XAIOS.EFI and hand over.
GRUB_EFI="$BUILD_DIR/vmware-fusion/BOOTAA64.EFI"
AARCH64_KERNEL="$BUILD_DIR/kernel/kernel.elf"
X86_64_LOADER="$BUILD_DIR/uefi-x86_64/BOOTX64.EFI"
X86_64_KERNEL="$BUILD_DIR/kernel-x86_64/kernel.elf"
INITFS="$BUILD_DIR/xaios-virtio-test.img"
INITFS_X86="$BUILD_DIR/xaios-x86-virtio-test.img"

# The ARM half is required; the Intel half is included when it has been built.
# Refusing to produce anything until both architectures are present would make
# this unusable on a machine that only builds one, and the resulting image is
# still correct -- it simply boots on fewer machines, and says so below.
for required in "$AARCH64_LOADER" "$AARCH64_KERNEL" "$INITFS"; do
  [ -f "$required" ] || {
    printf 'missing: %s\nrun ./scripts/build-image.sh first\n' "$required" >&2
    exit 1
  }
done

INCLUDE_X86=0
if [ -f "$X86_64_LOADER" ] && [ -f "$X86_64_KERNEL" ] && [ -f "$INITFS_X86" ]; then
  INCLUDE_X86=1
fi

ENTROPY_SEED="$BUILD_DIR/unified-entropy.seed"
if [ ! -f "$ENTROPY_SEED" ]; then
  # Exactly XAIOS_BOOT_INFO_ENTROPY_SEED_BYTES. A short file makes the loader
  # return EFI_LOAD_ERROR and the machine powers off with nothing printed.
  dd if=/dev/urandom of="$ENTROPY_SEED" bs=64 count=1 status=none
fi

rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"

# The EFI System Partition. This exact image is both the El Torito boot image
# and the contents of the GPT partition, so optical and disk boots run the
# same bytes rather than two copies that can drift apart.
rm -f "$ESP_IMAGE"
dd if=/dev/zero of="$ESP_IMAGE" bs=1048576 count="$ESP_MIB" status=none
# FAT16, not FAT32, and this is not a detail. VMware Fusion's firmware boots
# an El Torito image with a FAT16 filesystem and silently boots nothing at all
# from a FAT32 one -- no output, no error, a VM that runs and does nothing.
# QEMU and Virtualization.framework read either, so this only shows up on the
# one platform, and only on the optical path. Letting mformat choose the type
# for the size is what the Fusion profile has always done.
mformat -i "$ESP_IMAGE" -v XAIOS ::
mmd -i "$ESP_IMAGE" ::/EFI ::/EFI/BOOT ::/EFI/XAIOS
if [ -f "$GRUB_EFI" ]; then
  mcopy -i "$ESP_IMAGE" "$GRUB_EFI" ::/EFI/BOOT/BOOTAA64.EFI
else
  printf '%s\n' "note: no chainloader at $GRUB_EFI; this image will not boot" \
    "      on VMware Fusion. Run make vmware-fusion-image to build one." >&2
  mcopy -i "$ESP_IMAGE" "$AARCH64_LOADER" ::/EFI/BOOT/BOOTAA64.EFI
fi
mcopy -i "$ESP_IMAGE" "$AARCH64_LOADER" ::/EFI/XAIOS/XAIOS.EFI
# The ARM kernel keeps the plain name and only the Intel one is qualified.
# Both loaders ask for their architecture-specific name first and fall back to
# kernel.elf, so this is enough to tell them apart -- and it matters because
# VMware Fusion boots an image whose kernel is called kernel.elf and boots
# nothing at all, with no output, from an otherwise identical image where the
# only change is that name. Measured by renaming that one file in a working
# image and watching it stop booting. Why its firmware cares is not
# understood; naming the file what it has always been called costs nothing.
mcopy -i "$ESP_IMAGE" "$AARCH64_KERNEL" ::/EFI/XAIOS/kernel.elf
if [ "$INCLUDE_X86" -eq 1 ]; then
  mcopy -i "$ESP_IMAGE" "$X86_64_LOADER" ::/EFI/BOOT/BOOTX64.EFI
  mcopy -i "$ESP_IMAGE" "$X86_64_KERNEL" ::/EFI/XAIOS/kernel-x86_64.elf
  mcopy -i "$ESP_IMAGE" "$INITFS_X86" ::/EFI/XAIOS/initfs-x86_64.img
fi
# The initial filesystem holds userspace ELFs, so it is per-architecture too:
# booting x86_64 against the ARM one loads /init and faults on the first
# instruction. The ARM copy keeps the plain name for the same reason the ARM
# kernel does.
mcopy -i "$ESP_IMAGE" "$INITFS" ::/EFI/XAIOS/initfs.img
mcopy -i "$ESP_IMAGE" "$ENTROPY_SEED" ::/EFI/XAIOS/entropy.seed

# The ISO 9660 side carries the same files so that mounting the image shows
# what it contains, rather than one opaque efi.img.
cp "$ESP_IMAGE" "$STAGE_DIR/efi.img"
mkdir -p "$STAGE_DIR/EFI/BOOT" "$STAGE_DIR/EFI/XAIOS"
if [ -f "$GRUB_EFI" ]; then
  cp "$GRUB_EFI" "$STAGE_DIR/EFI/BOOT/BOOTAA64.EFI"
else
  cp "$AARCH64_LOADER" "$STAGE_DIR/EFI/BOOT/BOOTAA64.EFI"
fi
cp "$AARCH64_LOADER" "$STAGE_DIR/EFI/XAIOS/XAIOS.EFI"
cp "$AARCH64_KERNEL" "$STAGE_DIR/EFI/XAIOS/kernel.elf"
if [ "$INCLUDE_X86" -eq 1 ]; then
  cp "$X86_64_LOADER" "$STAGE_DIR/EFI/BOOT/BOOTX64.EFI"
  cp "$X86_64_KERNEL" "$STAGE_DIR/EFI/XAIOS/kernel-x86_64.elf"
  cp "$INITFS_X86" "$STAGE_DIR/EFI/XAIOS/initfs-x86_64.img"
fi
cp "$INITFS" "$STAGE_DIR/EFI/XAIOS/initfs.img"
cp "$ENTROPY_SEED" "$STAGE_DIR/EFI/XAIOS/entropy.seed"

# -e efi.img            the El Torito EFI entry, for firmware booting media
# -append_partition     the same image again as a real GPT partition of type
#                       0xef, which is what makes a dd'd USB stick bootable
#                       and what disk-attaching hypervisors look for
# -appended_part_as_gpt describe the appended partition in a GPT rather than
#                       only an MBR entry. Without this the image still has a
#                       partition, but firmware looking for a GUID partition
#                       table finds none and will not boot it from a disk.
# -partition_cyl_align  pad so the partition ends on a cylinder boundary,
#                       which some firmware requires before it will parse it
xorriso -as mkisofs -quiet \
  -R -J -V XAIOS \
  -e efi.img -no-emul-boot \
  -append_partition 2 0xef "$ESP_IMAGE" \
  -appended_part_as_gpt \
  -partition_cyl_align all \
  -o "$OUTPUT" "$STAGE_DIR"

printf '%s\n' "XAIOS unified image: $OUTPUT"
printf '%s\n' "  size:          $(wc -c < "$OUTPUT") bytes"
printf '%s\n' "  build:         $BUILD_NUMBER"
printf '%s\n' "  architectures: aarch64$([ "$INCLUDE_X86" -eq 1 ] && printf ', x86_64')"
printf '%s\n' "  boot as:       optical media, or a disk with an EFI System Partition"
printf '%s\n' "  usb stick:     dd if=$OUTPUT of=/dev/rdiskN bs=4m"
printf '%s\n' "  mount:         hdiutil attach $OUTPUT"
