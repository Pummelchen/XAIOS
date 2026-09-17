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
# medany, because userspace links at 0x3fc0000000. The default medlow code
# model addresses through lui, which reaches only the lowest and highest two
# gigabytes, and every string constant in every app is a relocation out of
# range. medany is pc-relative and has no such limit.
CODE_MODEL="-mcmodel=medany" 
CLANG=${CLANG:-clang}
LD_LLD=${LD_LLD:-ld.lld}
PYTHON3=${PYTHON3:-python3}

mkdir -p "$BUILD_DIR"

build_program() {
  source_path=$1
  elf_path=$2
  "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL \
    -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
    -Wall -Wextra -Werror -c "$source_path" -o "$elf_path.o"
  "$LD_LLD" -nostdlib -T "$ROOT_DIR/userspace/init/linker.ld" \
    -o "$elf_path" "$elf_path.o"
}

. "$ROOT_DIR/scripts/lib/riscv64-build-policy.sh"

printf '%s\n' "Building riscv64 userspace..."
build_program "$ROOT_DIR/userspace/init/init-riscv64.S" "$BUILD_DIR/init.elf"
build_program "$ROOT_DIR/userspace/service-manager/service-manager-riscv64.S" \
  "$BUILD_DIR/service-manager.elf"
build_program "$ROOT_DIR/userspace/worker/worker-riscv64.S" \
  "$BUILD_DIR/worker.elf"

. "$ROOT_DIR/scripts/lib/riscv64-app-catalog.sh"
. "$ROOT_DIR/scripts/lib/riscv64-user-apps.sh"

. "$ROOT_DIR/scripts/lib/riscv64-user-utilities.sh"

. "$ROOT_DIR/scripts/lib/riscv64-hosted-apps.sh"

. "$ROOT_DIR/scripts/lib/riscv64-xapt-app.sh"

. "$ROOT_DIR/scripts/lib/riscv64-sshd-build.sh"

. "$ROOT_DIR/scripts/lib/riscv64-ssh-client-build.sh"

. "$ROOT_DIR/scripts/lib/riscv64-image-inputs.sh"

. "$ROOT_DIR/scripts/lib/riscv64-image-assembly.sh"

. "$ROOT_DIR/scripts/lib/riscv64-fixture-volumes.sh"
