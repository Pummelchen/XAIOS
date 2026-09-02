#!/bin/sh
# Build the RISC-V rv64gc bring-up kernel for the QEMU `virt` board.
#
# Separate from build-image.sh rather than a third case inside it, and the
# reason is worth stating: that script builds a UEFI loader and a FAT boot
# image, because AArch64 and x86-64 are both booted by UEFI firmware. RISC-V
# on this board is not. OpenSBI hands control straight to an ELF at a fixed
# address, so there is no loader to build, no EFI executable, and no boot
# medium -- adding this to that script would mean threading "skip all of it"
# through every step of a pipeline whose whole subject is those steps.
#
# When this port grows a UEFI path it should move; while it does not have
# one, pretending it fits is the more confusing arrangement.
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build/kernel-riscv64"
KERNEL_ELF="$BUILD_DIR/kernel.elf"

CC="${XAIOS_RISCV64_CC:-clang}"
LD="${XAIOS_RISCV64_LD:-ld.lld}"

for tool in "$CC" "$LD"; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf '%s\n' "error: missing required tool: $tool" >&2
    exit 2
  fi
done

mkdir -p "$BUILD_DIR"

# -mno-relax because linker relaxation needs a global pointer this kernel does
# not set up; medany because the code has to run at 0x80200000 rather than in
# the low two gibibytes medlow assumes.
CFLAGS="-std=c99 -Wall -Wextra -Werror -pedantic -ffreestanding \
-fno-stack-protector -mno-relax -march=rv64gc -mabi=lp64d -mcmodel=medany \
--target=riscv64-unknown-elf -I$ROOT_DIR/kernel/include -I$ROOT_DIR/engine/include"

OBJECTS=""
compile() {
  source_path="$1"
  object_path="$BUILD_DIR/$(basename "${source_path%.*}").o"
  # shellcheck disable=SC2086
  $CC $CFLAGS -c "$source_path" -o "$object_path"
  OBJECTS="$OBJECTS $object_path"
}

compile "$ROOT_DIR/kernel/arch/riscv64/entry.S"
compile "$ROOT_DIR/kernel/arch/riscv64/sbi.c"
compile "$ROOT_DIR/kernel/arch/riscv64/console.c"
compile "$ROOT_DIR/kernel/arch/riscv64/boot.c"
# Shared kernel source, compiled from the same file the other two
# architectures use. Building it here is the point of the exercise: if it
# needed an edit to work on a third architecture, the platform-neutrality
# rule would have been contradicted rather than tested.
compile "$ROOT_DIR/kernel/runtime/sha256.c"

# shellcheck disable=SC2086
$LD -T "$ROOT_DIR/kernel/arch/riscv64/linker.ld" -o "$KERNEL_ELF" $OBJECTS

printf '%s\n' "Built RISC-V bring-up kernel: $KERNEL_ELF"
