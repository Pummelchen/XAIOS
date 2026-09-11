#!/bin/sh
# Build one bootable XAIOS image, for one architecture.
#
# The output is a hybrid: an ISO 9660 filesystem that is simultaneously a
# GPT-partitioned disk carrying an EFI System Partition. One file, three ways
# in:
#
#   - Firmware that boots optical media reads the El Torito entry. VMware
#     Fusion attaches this as a CD-ROM and boots it that way.
#   - Firmware that boots disks finds the EFI System Partition in the GPT.
#     QEMU and Virtualization.framework attach it as a drive; a USB stick
#     written with dd is the same thing on real hardware.
#   - Anything that just wants to read it mounts the ISO. On macOS that is
#     hdiutil attach; on Linux, mount -o loop.
#
# One architecture per image, and this used to be otherwise. All three rode in
# a single file, which UEFI makes possible -- firmware picks its own loader
# from the removable-media path and never sees the others -- and which was
# genuinely one deliverable rather than three. What it was not was easy to
# reason about. A boot that went wrong on one machine had three kernels, three
# initial filesystems and three loaders on the medium to be wrong about, the
# image was 220 MB of which about 30 was payload, and an architecture whose
# build had quietly not happened produced an image that still booted here and
# not on the machine it was carried to. Separating them costs the one-file
# property and buys a medium where everything on it is for the machine in
# front of you.
#
# What this deliberately does not carry is the durable volume. An ISO is
# read-only, and XAIOS keeps its state on a writable xaibootFS volume; that
# stays a separate disk the platform attaches. Booting from read-only media
# without one is a supported thing to do -- the system comes up and says the
# volume is missing rather than pretending otherwise.
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
BUILD_DIR="$ROOT_DIR/build"
ARCH="${XAIOS_TARGET_ARCH:-aarch64}"
# Named for the build and the machine it is for, so a file that has left this
# repository still says both. BUILD_NUMBER is the single source.
BUILD_NUMBER="$(tr -d ' \n' < "$ROOT_DIR/BUILD_NUMBER" 2>/dev/null || printf '%s' 0)"
STAGE_DIR="$BUILD_DIR/image-root-$ARCH"
ESP_IMAGE="$BUILD_DIR/esp-$ARCH.img"
OUTPUT="${XAIOS_ARCH_IMAGE:-$BUILD_DIR/xaios_b${BUILD_NUMBER}-${ARCH}.iso}"

for tool in xorriso mformat mmd mcopy minfo; do
  command -v "$tool" >/dev/null 2>&1 || {
    printf 'error: %s is required\n' "$tool" >&2
    exit 1
  }
done

# Per architecture: the loader, the kernel, the initial filesystem, the names
# they are written under, and how big the EFI System Partition is.
#
# The names are the ones each loader asks for and are not free to change. The
# AArch64 kernel is `kernel.elf' and nothing else: VMware Fusion boots an image
# whose kernel has that name and boots nothing at all, with no output, from an
# otherwise identical image where the only change is that name. Measured by
# renaming that one file in a working image and watching it stop booting. Why
# its firmware cares is not understood. The other two loaders ask for their
# qualified name first and fall back to kernel.elf, so they keep the qualified
# spelling they have always been given -- a rename here would be a change to
# the loader contract for no gain.
case "$ARCH" in
  aarch64)
    LOADER="$BUILD_DIR/uefi/BOOTAA64.EFI"
    LOADER_NAME="BOOTAA64.EFI"
    KERNEL="$BUILD_DIR/kernel/kernel.elf"
    KERNEL_NAME="kernel.elf"
    INITFS="$BUILD_DIR/xaios-virtio-test.img"
    INITFS_NAME="initfs.img"
    BUILDER="./scripts/build-image.sh"
    # 96 MiB, and this number is not free either. The ESP appears twice in the
    # finished ISO -- once as the El Torito boot image, once as the appended
    # GPT partition -- so every megabyte here costs two in the output, and the
    # payload below is about eighteen. It is not shrunk because this is the
    # architecture VMware Fusion boots, Fusion is the one firmware here that is
    # particular about the filesystem on this partition, and 96 MiB is the size
    # every image it has ever booted was built at. Shrinking it is a Fusion
    # re-qualification rather than an edit; see the note below on FAT16.
    ESP_MIB_DEFAULT=96
    ;;
  x86_64)
    LOADER="$BUILD_DIR/uefi-x86_64/BOOTX64.EFI"
    LOADER_NAME="BOOTX64.EFI"
    KERNEL="$BUILD_DIR/kernel-x86_64/kernel.elf"
    KERNEL_NAME="kernel-x86_64.elf"
    INITFS="$BUILD_DIR/xaios-x86-virtio-test.img"
    INITFS_NAME="initfs-x86_64.img"
    BUILDER="XAIOS_TARGET_ARCH=x86_64 ./scripts/build-image.sh"
    ESP_MIB_DEFAULT=32
    ;;
  riscv64)
    LOADER="$BUILD_DIR/riscv64-uefi/BOOTRISCV64.EFI"
    LOADER_NAME="BOOTRISCV64.EFI"
    KERNEL="$BUILD_DIR/kernel-riscv64/kernel.elf"
    KERNEL_NAME="kernel-riscv64.elf"
    INITFS="$BUILD_DIR/xaios-riscv64-initfs.img"
    INITFS_NAME="initfs-riscv64.img"
    BUILDER="./scripts/build-riscv64.sh && ./scripts/build-riscv64-image.sh"
    ESP_MIB_DEFAULT=32
    ;;
  *)
    printf '%s\n' \
      "error: XAIOS_TARGET_ARCH must be aarch64, x86_64 or riscv64" >&2
    exit 2
    ;;
esac
ESP_MIB="${XAIOS_ARCH_IMAGE_ESP_MIB:-$ESP_MIB_DEFAULT}"

# VMware Fusion's firmware will not launch the XAIOS loader from the
# removable-media path directly -- it boots nothing and prints nothing. It does
# launch GRUB, which then chainloads the same loader, and that is why the
# Fusion profile has carried a chainloader all along. Putting GRUB at
# \EFI\BOOT\BOOTAA64.EFI is what makes the AArch64 image boot on Fusion as well
# as the other three environments: those three launch GRUB perfectly well, and
# its only job is to search for XAIOS.EFI and hand over.
#
# It is AArch64-only because Fusion on this host is AArch64-only. The other two
# images put their own loader on the removable-media path with nothing in
# between.
GRUB_EFI="$BUILD_DIR/vmware-fusion/BOOTAA64.EFI"

for required in "$LOADER" "$KERNEL" "$INITFS"; do
  [ -f "$required" ] || {
    printf 'missing: %s\nrun: %s\n' "$required" "$BUILDER" >&2
    exit 1
  }
done

KERNEL_TO_CHECK="$KERNEL"
FAULT_TEST_REBUILD="$BUILDER"
# A kernel built to fault on purpose must not be wrapped into anything.
#
# `make qemu-fault-matrix` compiles three of them, each into the same
# build/kernel*/kernel.elf a packaging script reads, and restores the normal
# image when it finishes. That restoration is a courtesy and not a guarantee:
# interrupt it, crash it, or run a packaging script beside it, and the tree is
# left holding a kernel that halts on purpose under a name that means "the
# kernel". One netboot binary was built that way and looked exactly like a
# release binary; it took booting it to find out.
#
# The kernel says so in its own bytes when it is one of those builds. This
# reads that rather than trusting the filename. LC_ALL=C because the file is
# binary and a locale that tries to decode it can make grep give up on the
# line the marker is in.
XAIOS_FAULT_TEST_MARKER="fault-test-build: this kernel faults on purpose and must not be shipped"
if LC_ALL=C grep -a -q -F "$XAIOS_FAULT_TEST_MARKER" "$KERNEL_TO_CHECK"; then
  printf '%s\n' \
    "error: $KERNEL_TO_CHECK was built with XAIOS_FAULT_TEST and halts on" \
    "       purpose. It must not be packaged. Rebuild without it:" \
    "         $FAULT_TEST_REBUILD" >&2
  exit 1
fi

ENTROPY_SEED="$BUILD_DIR/image-entropy-$ARCH.seed"
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
mformat -i "$ESP_IMAGE" -v XAIOS ::
# FAT16, not FAT32, and not FAT12 either. VMware Fusion's firmware boots an El
# Torito image with a FAT16 filesystem and silently boots nothing at all from a
# FAT32 one -- no output, no error, a VM that runs and does nothing. QEMU and
# Virtualization.framework read either, so it shows up on one platform and only
# on the optical path, which is the worst way for a constraint to be enforced.
#
# mformat picks the type from the size, so the size is what has to be right,
# and a size that was right is not self-evidently still right after it changes.
# This asks the filesystem what it became. A check that costs one process is
# worth more than the sentence explaining the rule, because the sentence cannot
# fail and this can.
FAT_TYPE=$(minfo -i "$ESP_IMAGE" :: 2>/dev/null |
           sed -n 's/^disk type="\{0,1\}\([A-Z0-9]*\).*/\1/p' | head -1)
if [ "$FAT_TYPE" != FAT16 ]; then
  printf '%s\n' \
    "error: the $ESP_MIB MiB EFI System Partition formatted as ${FAT_TYPE:-an unreadable type}," \
    "       not FAT16. VMware Fusion boots FAT16 from the El Torito path and" \
    "       boots nothing, silently, from anything else. Choose a size that" \
    "       mformat makes FAT16, or set XAIOS_ARCH_IMAGE_ESP_MIB." >&2
  exit 1
fi

mmd -i "$ESP_IMAGE" ::/EFI ::/EFI/BOOT ::/EFI/XAIOS
if [ "$ARCH" = aarch64 ] && [ -f "$GRUB_EFI" ]; then
  mcopy -i "$ESP_IMAGE" "$GRUB_EFI" "::/EFI/BOOT/$LOADER_NAME"
  mcopy -i "$ESP_IMAGE" "$LOADER" ::/EFI/XAIOS/XAIOS.EFI
  CHAINLOADED=1
else
  if [ "$ARCH" = aarch64 ]; then
    printf '%s\n' "note: no chainloader at $GRUB_EFI; this image will not boot" \
      "      on VMware Fusion. Run make vmware-fusion-image to build one." >&2
  fi
  mcopy -i "$ESP_IMAGE" "$LOADER" "::/EFI/BOOT/$LOADER_NAME"
  CHAINLOADED=0
fi
mcopy -i "$ESP_IMAGE" "$KERNEL" "::/EFI/XAIOS/$KERNEL_NAME"
mcopy -i "$ESP_IMAGE" "$INITFS" "::/EFI/XAIOS/$INITFS_NAME"
mcopy -i "$ESP_IMAGE" "$ENTROPY_SEED" ::/EFI/XAIOS/entropy.sed

# The ISO 9660 side carries the same files so that mounting the image shows
# what it contains, rather than one opaque efi.img.
cp "$ESP_IMAGE" "$STAGE_DIR/efi.img"
mkdir -p "$STAGE_DIR/EFI/BOOT" "$STAGE_DIR/EFI/XAIOS"
if [ "$CHAINLOADED" -eq 1 ]; then
  cp "$GRUB_EFI" "$STAGE_DIR/EFI/BOOT/$LOADER_NAME"
  cp "$LOADER" "$STAGE_DIR/EFI/XAIOS/XAIOS.EFI"
else
  cp "$LOADER" "$STAGE_DIR/EFI/BOOT/$LOADER_NAME"
fi
cp "$KERNEL" "$STAGE_DIR/EFI/XAIOS/$KERNEL_NAME"
cp "$INITFS" "$STAGE_DIR/EFI/XAIOS/$INITFS_NAME"
cp "$ENTROPY_SEED" "$STAGE_DIR/EFI/XAIOS/entropy.sed"

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

printf '%s\n' "XAIOS image: $OUTPUT"
printf '%s\n' "  size:         $(wc -c < "$OUTPUT") bytes"
printf '%s\n' "  build:        $BUILD_NUMBER"
printf '%s\n' "  architecture: $ARCH"
printf '%s\n' "  esp:          $ESP_MIB MiB, FAT16"
printf '%s\n' "  loader:       \\EFI\\BOOT\\$LOADER_NAME$([ "$CHAINLOADED" -eq 1 ] && printf ' (GRUB, chainloads \\EFI\\XAIOS\\XAIOS.EFI)')"
printf '%s\n' "  boot as:      optical media, or a disk with an EFI System Partition"
printf '%s\n' "  usb stick:    dd if=$OUTPUT of=/dev/rdiskN bs=4m"
printf '%s\n' "  mount:        hdiutil attach $OUTPUT"
