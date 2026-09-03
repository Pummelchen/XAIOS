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
# medany, because userspace links at 0x7fc0000000. The default medlow code
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

printf '%s\n' "Building riscv64 userspace..."
build_program "$ROOT_DIR/userspace/init/init-riscv64.S" "$BUILD_DIR/init.elf"
build_program "$ROOT_DIR/userspace/service-manager/service-manager-riscv64.S" \
  "$BUILD_DIR/service-manager.elf"
build_program "$ROOT_DIR/userspace/worker/worker-riscv64.S" \
  "$BUILD_DIR/worker.elf"

# The applications the kernel launches after userspace services are up. Plain
# freestanding C99 against the userspace library -- nothing in them was
# architecture-specific once the syscall stub and the entry stub knew about
# this one.
# Exactly the applications kmain launches. xapt, nano, htop, pong and
# xaios-setup are not among them and need BearSSL and a libc sysroot of
# their own, which is separate work from booting.
USER_APPS="xaios-shell xaiosctl hello sysinfo systest smptest smpstress perfbench nettest lstm-xor sshtest mltest posix-shell agenttest xaios-setup"
APP_ARGS=""
for app in $USER_APPS; do
  printf '%s\n' "Building /bin/$app..."
  "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL \
    -std=c99 -ffreestanding -fno-stack-protector -fno-builtin -fno-pic \
    -fno-pie -Wall -Wextra -Werror -DXAIOS_BOOT_TEST_APPS=1 \
    -I"$ROOT_DIR/userspace/include" -I"$ROOT_DIR/userspace/sshd" \
    -I"$ROOT_DIR/engine/include" \
    -c "$ROOT_DIR/userspace/apps/$app.c" -o "$BUILD_DIR/$app.o"
  "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL -ffreestanding \
    -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
    -c "$ROOT_DIR/userspace/lib/start.S" -o "$BUILD_DIR/start-$app.o"
  "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL -std=c99 \
    -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
    -I"$ROOT_DIR/userspace/include" \
    -c "$ROOT_DIR/userspace/lib/xaios_user.c" -o "$BUILD_DIR/lib-$app.o"
  # The control-plane client, which xaiosctl and the shell call into.
  "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL -std=c99 \
    -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
    -I"$ROOT_DIR/userspace/include" \
    -c "$ROOT_DIR/userspace/lib/xaios_control_client.c" \
    -o "$BUILD_DIR/control-$app.o"
  # xaios-setup writes the credential records sshd reads, so it hashes them
  # with the same code sshd verifies them with -- two implementations of
  # PBKDF2 that disagree produce an account that cannot be logged into, and
  # the disagreement would only show at the login prompt.
  EXTRA_OBJS=""
  if [ "$app" = "xaios-setup" ]; then
    for setup_src in ssh_crypto tweetnacl_subset; do
      "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL \
        -std=c99 -ffreestanding -fno-stack-protector -fno-builtin -fno-pic \
        -fno-pie -Wall -Wextra -Werror \
        -I"$ROOT_DIR/userspace/include" -I"$ROOT_DIR/userspace/sshd" \
        -c "$ROOT_DIR/userspace/sshd/$setup_src.c" \
        -o "$BUILD_DIR/setup-$setup_src.o"
      EXTRA_OBJS="$EXTRA_OBJS $BUILD_DIR/setup-$setup_src.o"
    done
  fi
  # shellcheck disable=SC2086
  "$LD_LLD" -nostdlib -T "$ROOT_DIR/userspace/init/linker.ld" \
    -o "$BUILD_DIR/$app.elf" "$BUILD_DIR/start-$app.o" "$BUILD_DIR/$app.o" \
    "$BUILD_DIR/lib-$app.o" "$BUILD_DIR/control-$app.o" $EXTRA_OBJS
  APP_ARGS="$APP_ARGS /bin/$app=$BUILD_DIR/$app.elf"
done

# The same 4 MiB volume shape the other architectures' test image uses, with
# the marker the boot-storage check reads in sector zero and the rofs from
# sector one.
rm -f "$IMAGE"
dd if=/dev/zero of="$IMAGE" bs=512 count=65536 status=none
printf 'XAIOS-VIRTIO-BLOCK-TEST\n' | \
  dd of="$IMAGE" bs=512 count=1 conv=notrunc status=none
"$PYTHON3" "$ROOT_DIR/scripts/create-initfs.py" \
  "$IMAGE" \
  "$BUILD_DIR/init.elf" \
  "$BUILD_DIR/service-manager.elf" \
  "$BUILD_DIR/worker.elf" \
  "$ROOT_DIR/userspace/init/xaios-init.conf" \
  "$ROOT_DIR/userspace/service-manager/source-index.svc" \
  $APP_ARGS \
  "$@"
printf '%s\n' "Created $IMAGE"
