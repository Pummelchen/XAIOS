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
# The applications kmain launches, plus the ones sshd launches on demand --
# xtop is reached by typing its name at a login, not during boot, and a shell
# that offers a command whose binary is not in the image is worse than one
# that does not offer it.
# The same switch the kernel builder reads: 1 is the boot-test configuration
# the RISC-V gates run, 0 is the release configuration the other architectures
# ship as `make image`, where sshd dispatches on-demand applications such as
# xtop instead of the built-in test shell commands.
USER_APPS="xaios-shell xaiosctl hello sysinfo systest smptest smpstress perfbench nettest lstm-xor sshtest mltest posix-shell agenttest xaios-setup xtop"
APP_ARGS=""
for app in $USER_APPS; do
  printf '%s\n' "Building /bin/$app..."
  "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL \
    -std=c99 -ffreestanding -fno-stack-protector -fno-builtin -fno-pic \
    -fno-pie -Wall -Wextra -Werror -DXAIOS_BOOT_TEST_APPS="${XAIOS_BOOT_TEST_APPS:-1}" \
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
  # The screen framework, for programs that draw a screen.
  "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL -std=c99 \
    -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie -Os \
    -I"$ROOT_DIR/userspace/include" \
    -c "$ROOT_DIR/userspace/lib/xaios_screen.c" -o "$BUILD_DIR/screen-$app.o"
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
    "$BUILD_DIR/lib-$app.o" "$BUILD_DIR/control-$app.o" \
    "$BUILD_DIR/screen-$app.o" $EXTRA_OBJS
  APP_ARGS="$APP_ARGS /bin/$app=$BUILD_DIR/$app.elf"
done

# The hosted ISO C99 demonstration and the termination probes, built against
# the same picolibc sysroot the other architectures use. The kernel launches
# these when XAIOS_LIBC_TEST is set, which build-riscv64.sh now defaults on.
HOSTED_ARGS=""
LIBC_RUNTIME="$ROOT_DIR/build/libc/riscv64/runtime-test"
if [ -f "$ROOT_DIR/build/libc/riscv64/sysroot/lib/libc.a" ] &&
   [ -f "$LIBC_RUNTIME/crt0.o" ]; then
  printf '%s\n' "Building hosted C99 /bin/helloworldc99..."
  "$ROOT_DIR/scripts/build-c99-app.sh" --arch riscv64 --main void \
    "$ROOT_DIR/userspace/apps/hosted/helloworldc99.c" \
    "$BUILD_DIR/helloworldc99.elf"
  HOSTED_ARGS="/bin/helloworldc99=$BUILD_DIR/helloworldc99.elf"
  for probe in c99-runtime-smoke:c99-runtime-smoke \
      c99-main-void:c99-main_void c99-exit-probe:c99-exit_probe \
      c99-abort-probe:c99-abort_probe \
      c99-thread-context:c99-thread-context; do
    guest=${probe%%:*}
    host=${probe#*:}
    HOSTED_ARGS="$HOSTED_ARGS /bin/$guest=$LIBC_RUNTIME/$host.elf"
  done
else
  printf '%s\n' "warning: no riscv64 libc; C99 applications omitted" >&2
fi

# xapt, which needs TLS and therefore BearSSL and the libc sysroot. Built
# separately from the loop above because it is the only application with
# dependencies outside the userspace tree.
XAPT_ARGS=""
XAPT_BEARSSL="$ROOT_DIR/build/bearssl/riscv64/libbearssl-xapt.a"
if [ -f "$XAPT_BEARSSL" ] &&
   [ -f "$ROOT_DIR/build/libc/riscv64/sysroot/lib/libc.a" ]; then
  printf '%s\n' "Building /bin/xapt..."
  for xapt_src in xapt xapt_tls xapt_trust_anchors; do
    "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL \
      -std=c99 -ffreestanding -fno-stack-protector -fno-builtin -fno-pic \
      -fno-pie -Os -Wall -Wextra -Werror \
      -isystem "$ROOT_DIR/build/libc/riscv64/sysroot/include" \
      -I"$ROOT_DIR/userspace/include" -I"$ROOT_DIR/userspace/apps" \
      -I"$ROOT_DIR/third_party/bearssl/inc" \
      -c "$ROOT_DIR/userspace/apps/$xapt_src.c" -o "$BUILD_DIR/$xapt_src.o"
  done
  "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL \
    -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
    -c "$ROOT_DIR/userspace/lib/start.S" -o "$BUILD_DIR/start-xapt.o"
  "$LD_LLD" -nostdlib -T "$ROOT_DIR/userspace/init/linker.ld" \
    -o "$BUILD_DIR/xapt.elf" "$BUILD_DIR/start-xapt.o" \
    "$BUILD_DIR/lib-hello.o" "$BUILD_DIR/control-hello.o" \
    "$BUILD_DIR/xapt.o" "$BUILD_DIR/xapt_tls.o" \
    "$BUILD_DIR/xapt_trust_anchors.o" "$XAPT_BEARSSL"
  XAPT_ARGS="/bin/xapt=$BUILD_DIR/xapt.elf"
else
  printf '%s\n' "warning: no riscv64 BearSSL or libc; xapt omitted" >&2
fi

# /bin/sshd, and the terminal applications it hosts. This is what turns a
# machine that boots into a machine anyone can reach: without it the boot
# stops at a setup prompt and there is nothing to log into.
printf '%s\n' "Building /bin/sshd..."
SSHD_OBJS=""
for sshd_src in sshd ssh_crypto ssh_mlkem tweetnacl_subset ssh_protocol \
    ssh_channel ssh_client_proxy ssh_host_key ssh_connection sftp_server \
    less_pager; do
  sshd_opt=""
  [ "$sshd_src" = sshd ] && sshd_opt="-Os"
  # shellcheck disable=SC2086
  "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL \
    -std=c99 -ffreestanding -fno-stack-protector -fno-builtin -fno-pic \
    -fno-pie $sshd_opt -Wall -Wextra -Werror \
    -DXAIOS_PASSWORD_AUTH_AVAILABLE=1 \
    -DMLK_CONFIG_FILE='"mlkem_xaios_config.h"' \
    -I"$ROOT_DIR/userspace/include" -I"$ROOT_DIR/userspace/sshd" \
    -I"$ROOT_DIR/third_party/mlkem-native/mlkem" \
    -I"$ROOT_DIR/userspace/apps/terminal" \
    -c "$ROOT_DIR/userspace/sshd/$sshd_src.c" -o "$BUILD_DIR/sshd-$sshd_src.o"
  SSHD_OBJS="$SSHD_OBJS $BUILD_DIR/sshd-$sshd_src.o"
done
"$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL \
  -std=c99 -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
  -Wall -Wextra -Werror -DMLK_CONFIG_FILE='"mlkem_xaios_config.h"' \
  -I"$ROOT_DIR/userspace/sshd" -I"$ROOT_DIR/third_party/mlkem-native/mlkem" \
  -c "$ROOT_DIR/third_party/mlkem-native/mlkem/mlkem_native.c" \
  -o "$BUILD_DIR/sshd-mlkem.o"
SSHD_OBJS="$SSHD_OBJS $BUILD_DIR/sshd-mlkem.o"
for app_src in nano_editor pong_game; do
  app_opt=""
  [ "$app_src" = pong_game ] && app_opt="-Os"
  # shellcheck disable=SC2086
  "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL \
    -std=c99 -ffreestanding -fno-stack-protector -fno-builtin -fno-pic \
    -fno-pie $app_opt -Wall -Wextra -Werror \
    -I"$ROOT_DIR/userspace/include" -I"$ROOT_DIR/userspace/apps/terminal" \
    -c "$ROOT_DIR/userspace/apps/terminal/$app_src.c" \
    -o "$BUILD_DIR/sshd-$app_src.o"
  SSHD_OBJS="$SSHD_OBJS $BUILD_DIR/sshd-$app_src.o"
done
"$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL \
  -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
  -c "$ROOT_DIR/userspace/lib/start.S" -o "$BUILD_DIR/start-sshd.o"
# shellcheck disable=SC2086
"$LD_LLD" -nostdlib -T "$ROOT_DIR/userspace/init/linker.ld" \
  -o "$BUILD_DIR/sshd.elf" "$BUILD_DIR/start-sshd.o" \
  "$BUILD_DIR/lib-hello.o" "$BUILD_DIR/control-hello.o" \
  "$BUILD_DIR/screen-hello.o" $SSHD_OBJS
SSHD_ARGS="/bin/sshd=$BUILD_DIR/sshd.elf"

# The development account, so the machine has something to log into and the
# boot does not stop at a setup prompt with nobody standing in front of it.
# Development only: a release medium packages no credential anybody outside
# the build has, and setup makes one on first boot instead.
CREDENTIAL_ARGS=""
if [ "${XAIOS_RISCV64_MODE:-development}" = development ]; then
  CREDENTIAL_ARGS="/etc/xaios_sshd_users=$ROOT_DIR/config/development-sshd-users"
  CREDENTIAL_ARGS="$CREDENTIAL_ARGS /etc/xaios_console_pin=$ROOT_DIR/config/development-console-pin"
fi

# A public key the SSH server will accept, when a caller supplies one. The
# other builder has taken this since sshd grew key authentication; this one
# had not, so every gate that logs in with a key it generated itself could
# reach two machines out of three.
AUTHORIZED_KEYS_ARGS=""
if [ "${XAIOS_AUTHORIZED_KEYS_FILE:-}" != "" ]; then
  if [ ! -f "$XAIOS_AUTHORIZED_KEYS_FILE" ]; then
    printf '%s\n' \
      "error: authorized keys file not found: $XAIOS_AUTHORIZED_KEYS_FILE" >&2
    exit 1
  fi
  AUTHORIZED_KEYS_ARGS="/etc/xaios_authorized_keys=$XAIOS_AUTHORIZED_KEYS_FILE"
fi

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
  $HOSTED_ARGS \
  $XAPT_ARGS \
  $SSHD_ARGS \
  $CREDENTIAL_ARGS \
  $AUTHORIZED_KEYS_ARGS \
  "/etc/xapt.conf=$ROOT_DIR/userspace/init/xapt.conf" \
  "$@"
printf '%s\n' "Created $IMAGE"
