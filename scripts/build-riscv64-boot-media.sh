#!/bin/sh
# A disk XAIOS boots from on RISC-V, rather than a kernel handed to QEMU.
#
# Until this existed, every RISC-V boot needed -kernel pointing at a file on
# the host: there was no medium to hand anyone. This builds the same shape the
# other two architectures ship -- a FAT EFI System Partition with a loader at
# the removable-media path and the kernel beside it -- and it boots under EDK2
# on the virt board.
#
# The one thing that is genuinely different here is the loader's container.
# UEFI loads PE/COFF images, and LLVM has no RISC-V COFF backend: clang with
# --target=riscv64-unknown-windows silently produces ELF and lld-link cannot
# link it. So the loader is built as a position-independent ELF and wrapped in
# a PE container by scripts/elf-to-efi.py, which is the approach the Linux EFI
# stub takes for the same reason.
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD_DIR="$ROOT_DIR/build/riscv64-uefi"
IMAGE="$ROOT_DIR/build/xaios-riscv64.img"
KERNEL="$ROOT_DIR/build/kernel-riscv64/kernel.elf"
INITFS="$ROOT_DIR/build/xaios-riscv64-initfs.img"
TARGET=riscv64-unknown-elf
CLANG=${CLANG:-clang}
LD_LLD=${LD_LLD:-ld.lld}
PYTHON3=${PYTHON3:-python3}
MFORMAT=${MFORMAT:-mformat}
MMD=${MMD:-mmd}
MCOPY=${MCOPY:-mcopy}

[ -f "$KERNEL" ] || { printf 'error: no kernel; run scripts/build-riscv64.sh\n' >&2; exit 1; }
[ -f "$INITFS" ] || { printf 'error: no initial filesystem; run scripts/build-riscv64-image.sh\n' >&2; exit 1; }

mkdir -p "$BUILD_DIR"
rm -f "$BUILD_DIR"/*.o "$BUILD_DIR/loader.elf"

# -fpie, because the PE carries base relocations and UEFI may load it
# anywhere. An image with no relocations is marked relocations-stripped and
# must load at its ImageBase, which firmware is free to refuse.
for source in boot/uefi/loader_main.c boot/uefi/system_volume_loader.c \
    kernel/runtime/sha256.c userspace/sshd/ssh_crypto.c \
    userspace/sshd/tweetnacl_subset.c; do
  object="$BUILD_DIR/$(basename "${source%.c}").o"
  "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d -mcmodel=medany \
    -ffreestanding -fno-stack-protector -fno-builtin -fshort-wchar \
    -ffunction-sections -fdata-sections -fpie -Wall -Wextra -Werror \
    -DXAIOS_BOOT_TEST_APPS="${XAIOS_BOOT_TEST_APPS:-1}" \
    -I"$ROOT_DIR/boot/uefi" -I"$ROOT_DIR/kernel/include" \
    -I"$ROOT_DIR/userspace/include" -I"$ROOT_DIR/userspace/sshd" \
    -c "$ROOT_DIR/$source" -o "$object"
done

# Each loadable segment page-aligned, because PE section addresses have to be
# multiples of the section alignment and lld packs segments tightly by
# default.
"$LD_LLD" -pie --no-dynamic-linker -e efi_main --gc-sections \
  -z separate-loadable-segments -z max-page-size=4096 \
  -o "$BUILD_DIR/loader.elf" "$BUILD_DIR"/*.o

"$PYTHON3" "$ROOT_DIR/scripts/elf-to-efi.py" --machine riscv64 \
  "$BUILD_DIR/loader.elf" "$BUILD_DIR/BOOTRISCV64.EFI"

# The signed A/B system volume, which is where a real machine reads its
# kernel from: the EFI System Partition is the fallback for a medium that
# carries no system volume. Building one for this architecture is what lets
# the update and rollback path be exercised here at all.
SYSTEM_VOLUME="$ROOT_DIR/build/xaios-riscv64-system.img"
printf '%s\n' "Creating signed A/B system volume: $SYSTEM_VOLUME"
PYTHONPATH="$ROOT_DIR" "$PYTHON3" "$ROOT_DIR/tools/xaios_system_volume.py" \
  create "$SYSTEM_VOLUME" "$KERNEL"
PYTHONPATH="$ROOT_DIR" "$PYTHON3" "$ROOT_DIR/tools/xaios_system_volume.py" \
  verify "$SYSTEM_VOLUME"

printf '%s\n' "Creating RISC-V boot medium: $IMAGE"
rm -f "$IMAGE"
dd if=/dev/zero of="$IMAGE" bs=1m count=128 status=none
"$MFORMAT" -i "$IMAGE" -F -v XAIOSRV64 ::
"$MMD" -i "$IMAGE" ::/EFI ::/EFI/BOOT ::/EFI/XAIOS
"$MCOPY" -i "$IMAGE" "$BUILD_DIR/BOOTRISCV64.EFI" ::/EFI/BOOT/BOOTRISCV64.EFI
"$MCOPY" -i "$IMAGE" "$KERNEL" ::/EFI/XAIOS/kernel-riscv64.elf
"$MCOPY" -i "$IMAGE" "$INITFS" ::/EFI/XAIOS/initfs-riscv64.img
printf '%s\n' "Created $IMAGE"
