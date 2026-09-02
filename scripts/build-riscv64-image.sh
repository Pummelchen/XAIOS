#!/bin/sh
# The RISC-V initial filesystem: three user programs and the two files that
# describe them.
#
# Separate from build-image.sh because that script also builds a UEFI loader
# and a FAT boot volume, and this board has neither -- QEMU loads the kernel
# directly and the rofs arrives as a disk. What the two share is the packer
# and the layout, so a volume built here is the same shape the kernel already
# knows how to mount.
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
BUILD_DIR="$ROOT_DIR/build/riscv64-userspace"
IMAGE="$ROOT_DIR/build/xaios-riscv64-initfs.img"
TARGET=riscv64-unknown-elf
CLANG=${CLANG:-clang}
LD_LLD=${LD_LLD:-ld.lld}
PYTHON3=${PYTHON3:-python3}

mkdir -p "$BUILD_DIR"

build_program() {
  source_path=$1
  elf_path=$2
  "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d \
    -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
    -Wall -Wextra -Werror -c "$source_path" -o "$elf_path.o"
  "$LD_LLD" -nostdlib -T "$ROOT_DIR/userspace/init/linker.ld" \
    -o "$elf_path" "$elf_path.o"
}

printf '%s\n' "Building riscv64 userspace..."
build_program "$ROOT_DIR/userspace/init/init-riscv64.S" "$BUILD_DIR/init.elf"
build_program "$ROOT_DIR/userspace/service-manager/service-manager-riscv64.S" \
  "$BUILD_DIR/service-manager.elf"
build_program "$ROOT_DIR/userspace/worker/worker-riscv64.S" \
  "$BUILD_DIR/worker.elf"

# The same 4 MiB volume shape the other architectures' test image uses, with
# the marker the boot-storage check reads in sector zero and the rofs from
# sector one.
rm -f "$IMAGE"
dd if=/dev/zero of="$IMAGE" bs=512 count=8192 status=none
printf 'XAIOS-VIRTIO-BLOCK-TEST\n' | \
  dd of="$IMAGE" bs=512 count=1 conv=notrunc status=none
"$PYTHON3" "$ROOT_DIR/scripts/create-initfs.py" \
  "$IMAGE" \
  "$BUILD_DIR/init.elf" \
  "$BUILD_DIR/service-manager.elf" \
  "$BUILD_DIR/worker.elf" \
  "$ROOT_DIR/userspace/init/xaios-init.conf" \
  "$ROOT_DIR/userspace/service-manager/source-index.svc" \
  "$@"
printf '%s\n' "Created $IMAGE"
