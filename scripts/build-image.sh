#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build"
TARGET_ARCH="${XAIOS_TARGET_ARCH:-aarch64}"
case "$TARGET_ARCH" in
  aarch64)
    TARGET_TRIPLE=aarch64-none-elf
    UEFI_TARGET=aarch64-unknown-windows
    UEFI_MACHINE=arm64
    UEFI_BOOT_NAME=BOOTAA64.EFI
    ARCH_BUILD_SUFFIX=""
    ARCH_KERNEL_DIR=aarch64
    ARCH_LINKER="$ROOT_DIR/kernel/arch/aarch64/linker.ld"
    INIT_SOURCE="$ROOT_DIR/userspace/init/init.S"
    SERVICE_MANAGER_SOURCE="$ROOT_DIR/userspace/service-manager/service-manager.S"
    WORKER_SOURCE="$ROOT_DIR/userspace/worker/worker.S"
    IMAGE_PATH="${XAIOS_AARCH64_IMAGE:-$BUILD_DIR/xaios-aarch64.img}"
    TEST_BLOCK_IMAGE="${XAIOS_TEST_BLOCK_IMAGE:-$BUILD_DIR/xaios-virtio-test.img}"
    PERSISTENT_IMAGE="${XAIOS_PERSISTENT_IMAGE:-$BUILD_DIR/xaios-persistent.img}"
    ;;
  x86_64)
    TARGET_TRIPLE=x86_64-none-elf
    UEFI_TARGET=x86_64-unknown-windows
    UEFI_MACHINE=x64
    UEFI_BOOT_NAME=BOOTX64.EFI
    ARCH_BUILD_SUFFIX=-x86_64
    ARCH_KERNEL_DIR=x86_64
    ARCH_LINKER="$ROOT_DIR/kernel/arch/x86_64/linker.ld"
    INIT_SOURCE="$ROOT_DIR/userspace/init/init-x86_64.S"
    SERVICE_MANAGER_SOURCE="$ROOT_DIR/userspace/service-manager/service-manager-x86_64.S"
    WORKER_SOURCE="$ROOT_DIR/userspace/worker/worker-x86_64.S"
    IMAGE_PATH="${XAIOS_X86_64_IMAGE:-$BUILD_DIR/xaios-x86_64.img}"
    TEST_BLOCK_IMAGE="${XAIOS_X86_TEST_BLOCK_IMAGE:-$BUILD_DIR/xaios-x86-virtio-test.img}"
    PERSISTENT_IMAGE="${XAIOS_X86_PERSISTENT_IMAGE:-$BUILD_DIR/xaios-x86-persistent.img}"
    ;;
  *)
    printf '%s\n' "error: XAIOS_TARGET_ARCH must be aarch64 or x86_64" >&2
    exit 2
    ;;
esac
EFI_BUILD_DIR="$BUILD_DIR/uefi$ARCH_BUILD_SUFFIX"
KERNEL_BUILD_DIR="$BUILD_DIR/kernel$ARCH_BUILD_SUFFIX"
INIT_BUILD_DIR="$BUILD_DIR/init$ARCH_BUILD_SUFFIX"

XAI_FS_IMAGE_CONFIGURED="${XAIOS_XAI_FS_IMAGE:-}"
if [ "$TARGET_ARCH" = x86_64 ]; then
  XAI_FS_IMAGE="${XAI_FS_IMAGE_CONFIGURED:-$BUILD_DIR/xaios-x86-xaifs.img}"
else
  XAI_FS_IMAGE="${XAI_FS_IMAGE_CONFIGURED:-$BUILD_DIR/xaios-xaifs.img}"
fi
SYSTEM_VOLUME_IMAGE_CONFIGURED="${XAIOS_SYSTEM_VOLUME_IMAGE:-}"
if [ "$TARGET_ARCH" = x86_64 ]; then
  SYSTEM_VOLUME_IMAGE="${SYSTEM_VOLUME_IMAGE_CONFIGURED:-$BUILD_DIR/xaios-x86-system.img}"
  STORAGE_ADMIN_IMAGE="${XAIOS_X86_STORAGE_ADMIN_IMAGE:-$BUILD_DIR/xaios-x86-storage-admin.img}"
else
  SYSTEM_VOLUME_IMAGE="${SYSTEM_VOLUME_IMAGE_CONFIGURED:-$BUILD_DIR/xaios-system.img}"
  STORAGE_ADMIN_IMAGE=""
fi
LOADER_OBJ="$EFI_BUILD_DIR/loader_main.obj"
LOADER_SYSTEM_OBJ="$EFI_BUILD_DIR/system_volume_loader.obj"
LOADER_SHA256_OBJ="$EFI_BUILD_DIR/sha256.obj"
LOADER_SSH_CRYPTO_OBJ="$EFI_BUILD_DIR/ssh_crypto.obj"
LOADER_TWEETNACL_OBJ="$EFI_BUILD_DIR/tweetnacl_subset.obj"
LOADER_EFI="$EFI_BUILD_DIR/$UEFI_BOOT_NAME"
KERNEL_ELF="$KERNEL_BUILD_DIR/kernel.elf"
INIT_OBJ="$INIT_BUILD_DIR/init.o"
INIT_ELF="$INIT_BUILD_DIR/init.elf"
SERVICE_MANAGER_OBJ="$INIT_BUILD_DIR/service-manager.o"
SERVICE_MANAGER_ELF="$INIT_BUILD_DIR/service-manager.elf"
WORKER_OBJ="$INIT_BUILD_DIR/worker.o"
WORKER_ELF="$INIT_BUILD_DIR/worker.elf"
USER_START_OBJ="$INIT_BUILD_DIR/user-start.o"
USER_LIB_OBJ="$INIT_BUILD_DIR/xaios-user.o"
USER_CONTROL_OBJ="$INIT_BUILD_DIR/xaios-control-client.o"
USER_APPS="xaios-shell xaiosctl xapt nano htop pong hello sysinfo systest smptest smpstress perfbench nettest lstm-xor sshtest mltest posix-shell agenttest clustertest xaios-setup"

# Which end of a cluster this image is, and where its peer is.
#
# The two ends are mirror images: one listens, the other dials, and each is the
# other's peer. A server image needs no address; a client image is pointed at
# one, which is what lets a machine here reach a machine somewhere else rather
# than only the host process on the other side of the QEMU user network.
CLUSTER_ROLE_SERVER="${XAIOS_CLUSTER_ROLE_SERVER:-0}"
case "$CLUSTER_ROLE_SERVER" in
  0|1) ;;
  *)
    printf '%s\n' "error: XAIOS_CLUSTER_ROLE_SERVER must be 0 or 1" >&2
    exit 1
    ;;
esac
CLUSTER_APP_CFLAGS="-DXAIOS_CLUSTER_ROLE_SERVER=$CLUSTER_ROLE_SERVER"
if [ -n "${XAIOS_CLUSTER_PEER_IPV4:-}" ]; then
  # Four octets, checked here rather than discovered as a link failure or, far
  # worse, as a machine quietly dialling the wrong address.
  cluster_peer_ok=$(printf '%s' "$XAIOS_CLUSTER_PEER_IPV4" | awk -F. '
    NF == 4 {
      for (i = 1; i <= 4; ++i) {
        if ($i !~ /^[0-9]+$/ || $i + 0 > 255) { print "no"; exit }
      }
      print "yes"; exit
    }
    { print "no" }')
  if [ "$cluster_peer_ok" != yes ]; then
    printf '%s\n' "error: XAIOS_CLUSTER_PEER_IPV4 must be a dotted IPv4 address" >&2
    exit 1
  fi
  cluster_a=$(printf '%s' "$XAIOS_CLUSTER_PEER_IPV4" | cut -d. -f1)
  cluster_b=$(printf '%s' "$XAIOS_CLUSTER_PEER_IPV4" | cut -d. -f2)
  cluster_c=$(printf '%s' "$XAIOS_CLUSTER_PEER_IPV4" | cut -d. -f3)
  cluster_d=$(printf '%s' "$XAIOS_CLUSTER_PEER_IPV4" | cut -d. -f4)
  CLUSTER_APP_CFLAGS="$CLUSTER_APP_CFLAGS -DXAIOS_CLUSTER_PEER_IPV4_A=${cluster_a}U"
  CLUSTER_APP_CFLAGS="$CLUSTER_APP_CFLAGS -DXAIOS_CLUSTER_PEER_IPV4_B=${cluster_b}U"
  CLUSTER_APP_CFLAGS="$CLUSTER_APP_CFLAGS -DXAIOS_CLUSTER_PEER_IPV4_C=${cluster_c}U"
  CLUSTER_APP_CFLAGS="$CLUSTER_APP_CFLAGS -DXAIOS_CLUSTER_PEER_IPV4_D=${cluster_d}U"
fi
if [ -n "${XAIOS_CLUSTER_PEER_PORT:-}" ]; then
  CLUSTER_APP_CFLAGS="$CLUSTER_APP_CFLAGS -DCLUSTER_PEER_PORT=${XAIOS_CLUSTER_PEER_PORT}U"
fi
UTILITY_APPS="ls mkdir touch cp mv rm rmdir stat cat head tail less grep find sed write tar cpio zip unzip ps df du"
HOSTED_USER_APPS="helloworldc99"

BUILD_MODE="${XAIOS_BUILD_MODE:-development}"
case "$BUILD_MODE" in
  development|release) ;;
  *)
    printf '%s\n' "error: XAIOS_BUILD_MODE must be development or release" >&2
    exit 2
    ;;
esac
BOOT_TEST_APPS="${XAIOS_BOOT_TEST_APPS:-0}"
case "$BOOT_TEST_APPS" in
  0|1) ;;
  *)
    printf '%s\n' "error: XAIOS_BOOT_TEST_APPS must be 0 or 1" >&2
    exit 2
    ;;
esac
LIBC_TEST="${XAIOS_LIBC_TEST:-0}"
case "$LIBC_TEST" in
  0|1) ;;
  *)
    printf '%s\n' "error: XAIOS_LIBC_TEST must be 0 or 1" >&2
    exit 2
    ;;
esac
BOOT_VERBOSE="${XAIOS_BOOT_VERBOSE:-0}"
case "$BOOT_VERBOSE" in
  0|1) ;;
  *)
    printf '%s\n' "error: XAIOS_BOOT_VERBOSE must be 0 or 1" >&2
    exit 2
    ;;
esac
FAILURE_TEST_APP="${XAIOS_FAILURE_TEST_APP:-0}"
case "$FAILURE_TEST_APP" in
  0) ;;
  1) USER_APPS="$USER_APPS app-fail app-crash" ;;
  *)
    printf '%s\n' "error: XAIOS_FAILURE_TEST_APP must be 0 or 1" >&2
    exit 2
    ;;
esac
PASSWORD_AUTH_CFLAG="-DXAIOS_PASSWORD_AUTH_AVAILABLE=0"
SSH_USERS_FILE="${XAIOS_SSH_USERS_FILE:-}"
if [ "${XAIOS_SSH_PASSWORD_AUTH+x}" = "x" ]; then
  SSH_PASSWORD_AUTH_EXPLICIT=1
else
  SSH_PASSWORD_AUTH_EXPLICIT=0
fi
# "none" asks for a development image that packages no account, so the first
# boot runs setup exactly as a release image does. Without it every
# development build has the development credential and setup is unreachable.
if [ "$SSH_USERS_FILE" = "none" ]; then
  SSH_USERS_FILE=""
  SSH_PASSWORD_AUTH_EXPLICIT=1
elif [ "$BUILD_MODE" = "development" ] && [ "$SSH_USERS_FILE" = "" ] && \
   [ "$SSH_PASSWORD_AUTH_EXPLICIT" = 0 ]; then
  SSH_USERS_FILE="$ROOT_DIR/config/development-sshd-users"
fi
# The rule here used to be "release images have no password authentication".
# That forbade the code, which forbade the only way a released machine could
# ever get an account: a person making one on it. The property worth keeping
# is narrower and is the one that actually matters -- a released image
# contains no credential anybody outside this build has. So the code is
# always compiled, and packaging a credential into a release image is what is
# refused.
#
# /bin/xaios-setup creates the account on first boot, with a salt from the
# machine's own entropy, and writes it to that machine's state volume. Nothing
# secret is in the download, which is what the old rule was protecting.
PASSWORD_AUTH_CFLAG="-DXAIOS_PASSWORD_AUTH_AVAILABLE=1"
if [ "$SSH_USERS_FILE" != "" ]; then
  if [ "${XAIOS_SSH_PASSWORD_AUTH:-}" != "1" ]; then
    if [ "$SSH_USERS_FILE" != "$ROOT_DIR/config/development-sshd-users" ]; then
      printf '%s\n' "error: password credentials require XAIOS_SSH_PASSWORD_AUTH=1" >&2
      exit 2
    fi
  fi
  if [ "$BUILD_MODE" = "release" ]; then
    printf '%s\n' \
      "error: a release image must not package a password credential." \
      "       Password support is compiled in and /bin/xaios-setup creates" \
      "       the account on first boot; a packaged record would be a" \
      "       credential every copy of the download shares." >&2
    exit 2
  fi
elif [ "${XAIOS_SSH_PASSWORD_AUTH:-0}" != "0" ]; then
  printf '%s\n' "error: XAIOS_SSH_PASSWORD_AUTH requires XAIOS_SSH_USERS_FILE" >&2
  exit 2
fi

# Local console PIN. It is console-only and never accepted over SSH, and it
# rides along with password authentication: an image without a password user
# database stays key-only and packages no PIN record.
CONSOLE_PIN_FILE="${XAIOS_CONSOLE_PIN_FILE:-}"
if [ "$BUILD_MODE" = "development" ] && [ "$CONSOLE_PIN_FILE" = "" ] && \
   [ "$SSH_USERS_FILE" = "$ROOT_DIR/config/development-sshd-users" ]; then
  CONSOLE_PIN_FILE="$ROOT_DIR/config/development-console-pin"
fi
if [ "$CONSOLE_PIN_FILE" != "" ]; then
  if [ "$BUILD_MODE" = "release" ]; then
    printf '%s\n' \
      "error: a release image must not package a console PIN." \
      "       Setup enrols one on first boot; see the password rule above." >&2
    exit 2
  fi
  if [ "$SSH_USERS_FILE" = "" ]; then
    printf '%s\n' "error: XAIOS_CONSOLE_PIN_FILE requires XAIOS_SSH_USERS_FILE" >&2
    exit 2
  fi
fi

# Cleanup only failures that occur after the build profile has been accepted.
cleanup() {
  if [ $? -ne 0 ]; then
    printf '%s\n' "Build failed, cleaning up partial artifacts..." >&2
    # What this build produced, and nothing else that happens to live in
    # build/. The Virtualization.framework harness, the vmnet helper and its
    # socket, SSH test keys and durable volumes are all created by other
    # tooling and kept here; taking them out on an unrelated build failure has
    # cost real time more than once. A running helper ends up holding an
    # unlinked socket that nothing can connect to, and the next run fails with
    # nothing more useful than "command not found".
    find "$BUILD_DIR" -mindepth 1 -maxdepth 1 ! -name vz -exec rm -rf {} +
    printf '%s\n' "Cleaned up $BUILD_DIR (kept $BUILD_DIR/vz)" >&2
  fi
}
trap cleanup EXIT

find_tool() {
  tool_name="$1"
  shift

  for candidate in "$@"; do
    if [ -x "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  if command -v "$tool_name" >/dev/null 2>&1; then
    command -v "$tool_name"
    return 0
  fi

  return 1
}

require_tool() {
  label="$1"
  tool_name="$2"
  install_hint="$3"
  shift 3

  if tool_path="$(find_tool "$tool_name" "$@")"; then
    printf '%s\n' "$tool_path"
    return 0
  fi

  printf '%s\n' "error: $label not found. $install_hint" >&2
  exit 1
}

brew_prefix() {
  formula="$1"
  if command -v brew >/dev/null 2>&1; then
    brew --prefix "$formula" 2>/dev/null || true
  fi
}

LLVM_PREFIX="$(brew_prefix llvm)"
LLD_PREFIX="$(brew_prefix lld)"

LLVM_BIN=""
if [ "$LLVM_PREFIX" != "" ]; then
  LLVM_BIN="$LLVM_PREFIX/bin"
fi

LLD_BIN=""
if [ "$LLD_PREFIX" != "" ]; then
  LLD_BIN="$LLD_PREFIX/bin"
fi

CLANG="$(require_tool "Clang" clang "Install with: brew install llvm" "$LLVM_BIN/clang" /usr/bin/clang)"
LLD_LINK="$(require_tool "LLD COFF linker" lld-link "Install with: brew install lld" "$LLD_BIN/lld-link" "$LLVM_BIN/lld-link")"
LD_LLD="$(require_tool "LLD ELF linker" ld.lld "Install with: brew install lld" "$LLD_BIN/ld.lld" "$LLVM_BIN/ld.lld")"
MFORMAT="$(require_tool "mtools mformat" mformat "Install with: brew install mtools" /opt/homebrew/bin/mformat /usr/local/bin/mformat)"
MMD="$(require_tool "mtools mmd" mmd "Install with: brew install mtools" /opt/homebrew/bin/mmd /usr/local/bin/mmd)"
MCOPY="$(require_tool "mtools mcopy" mcopy "Install with: brew install mtools" /opt/homebrew/bin/mcopy /usr/local/bin/mcopy)"
PYTHON3="$(require_tool "Python 3" python3 "Install with: brew install python" /opt/homebrew/bin/python3 /usr/local/bin/python3)"

mkdir -p "$EFI_BUILD_DIR" "$KERNEL_BUILD_DIR" "$INIT_BUILD_DIR"

printf '%s\n' "Building $TARGET_ARCH UEFI loader..."
UEFI_ARCH_CFLAG=""
if [ "$TARGET_ARCH" = x86_64 ]; then
  UEFI_ARCH_CFLAG=-DXAIOS_UEFI_TARGET_X86_64=1
fi
"$CLANG" \
  --target="$UEFI_TARGET" \
  $UEFI_ARCH_CFLAG \
  -ffreestanding \
  -fno-stack-protector \
  -fno-builtin \
  -fshort-wchar \
  -ffunction-sections \
  -fdata-sections \
  -Wall \
  -Wextra \
  -Werror \
  -DXAIOS_BOOT_TEST_APPS="$BOOT_TEST_APPS" \
  -I"$ROOT_DIR/boot/uefi" \
  -I"$ROOT_DIR/kernel/include" \
  -c "$ROOT_DIR/boot/uefi/loader_main.c" \
  -o "$LOADER_OBJ"

for loader_source in \
  "boot/uefi/system_volume_loader.c:$LOADER_SYSTEM_OBJ" \
  "kernel/runtime/sha256.c:$LOADER_SHA256_OBJ" \
  "userspace/sshd/ssh_crypto.c:$LOADER_SSH_CRYPTO_OBJ" \
  "userspace/sshd/tweetnacl_subset.c:$LOADER_TWEETNACL_OBJ"
do
  source_path=${loader_source%%:*}
  object_path=${loader_source#*:}
  "$CLANG" \
    --target="$UEFI_TARGET" \
    $UEFI_ARCH_CFLAG \
    -ffreestanding \
    -fno-stack-protector \
    -fno-builtin \
    -fshort-wchar \
    -mno-stack-arg-probe \
    -ffunction-sections \
    -fdata-sections \
    -DXAIOS_SHA256_NO_SELF_TEST=1 \
    -DXAIOS_CRYPTO_HASHES_ONLY=1 \
    -Wall \
    -Wextra \
    -Werror \
    -I"$ROOT_DIR/boot/uefi" \
    -I"$ROOT_DIR/kernel/include" \
    -I"$ROOT_DIR/userspace/include" \
    -I"$ROOT_DIR/userspace/sshd" \
    -c "$ROOT_DIR/$source_path" \
    -o "$object_path"
done

"$LLD_LINK" \
  /nologo \
  /subsystem:efi_application \
  /entry:efi_main \
  /nodefaultlib \
  /machine:"$UEFI_MACHINE" \
  "$LOADER_OBJ" \
  "$LOADER_SYSTEM_OBJ" \
  "$LOADER_SHA256_OBJ" \
  "$LOADER_SSH_CRYPTO_OBJ" \
  "$LOADER_TWEETNACL_OBJ" \
  /opt:ref \
  /out:"$LOADER_EFI"

printf '%s\n' "Building $TARGET_ARCH kernel ELF..."
KERNEL_CFLAGS="
  --target=$TARGET_TRIPLE
  -std=c99
  -ffreestanding
  -fno-stack-protector
  -fno-builtin
  -fno-pic
  -fno-pie
  -Os
  -Wall
  -Wextra
  -Werror
"
# Deny the compiler FP/SIMD registers in kernel code.
#
# Without this it emits q-register loads and stores for ordinary struct
# copies, including in the device drivers, which is wrong twice over. The
# kernel does not save FP/SIMD state across exceptions, so a handler that
# touches those registers can corrupt whatever owned them. And a SIMD access
# to device memory reports no instruction syndrome to a hypervisor, which is
# why booting under Apple's HVF aborted QEMU inside the xHCI and GIC MMIO
# paths: both objects carried SIMD stores the compiler chose on its own.
#
# The few files that use SIMD deliberately are built with compile_kernel_simd
# and manage the register state themselves.
KERNEL_NO_SIMD_CFLAGS=""
# Whether this kernel can be loaded anywhere, or must land where it was linked.
#
# AArch64 builds position-independent: it emits nothing but R_AARCH64_RELATIVE
# relocations, which the UEFI loader applies after choosing an address. That is
# what lets one image boot on machines whose memory starts in three different
# places and at any size -- a fixed 0x90000000 is simply absent on a QEMU guest
# with a gibibyte, and on Virtualization.framework until it has enough memory.
#
# x86_64 stays fixed-address. Its code model emits R_X86_64_32 relocations that
# cannot appear in a position-independent link at all, and it does not need to
# move: it already boots at every size tested. The loader accepts both, and
# applies no bias to a fixed-address kernel.
KERNEL_LDFLAGS=""
if [ "$TARGET_ARCH" = aarch64 ]; then
  KERNEL_CFLAGS="$KERNEL_CFLAGS -fpie"
  KERNEL_LDFLAGS="-pie -z notext --no-dynamic-linker"
  KERNEL_NO_SIMD_CFLAGS="-mgeneral-regs-only"
  # No -march bump here. Every atomic therefore compiles to a load-exclusive
  # and store-exclusive pair rather than an LSE LDADD or CAS. LSE is the better
  # instruction selection on paper -- one instruction instead of two, and no
  # retry loop -- but it needs ARMv8.1, and QEMU's default aarch64 CPU model is
  # ARMv8.0: LDADD does not decode there and the kernel takes an undefined
  # instruction before it finishes booting. That is the platform every gate
  # runs on, so the baseline stays at ARMv8.0. Raising it means giving QEMU an
  # explicit -cpu with LSE across every gate first.
fi
if [ "$TARGET_ARCH" = x86_64 ]; then
  KERNEL_CFLAGS="$KERNEL_CFLAGS -mno-red-zone -DXAIOS_X86_COMMON_RUNTIME=1"
fi

# The stress app soaks for fifteen seconds by default, so it runs only when
# asked for rather than in every test-apps boot.
case "${XAIOS_STRESS_TEST:-0}" in
  0) ;;
  1) KERNEL_CFLAGS="$KERNEL_CFLAGS -DXAIOS_STRESS_TEST=1" ;;
  *)
    printf '%s\n' "error: XAIOS_STRESS_TEST must be 0 or 1" >&2
    exit 2
    ;;
esac

# The cluster data plane test dials a peer, so it is built into the image only
# when something is going to answer. See kmain for what an unanswered dial
# costs a gate that counts packets.
case "${XAIOS_CLUSTER_TEST:-0}" in
  0) ;;
  1) KERNEL_CFLAGS="$KERNEL_CFLAGS -DXAIOS_CLUSTER_TEST=1" ;;
  *)
    printf '%s\n' "error: XAIOS_CLUSTER_TEST must be 0 or 1" >&2
    exit 1
    ;;
esac

# One log line per block write and per flush, so a gate can check that the
# ordering volatile-cache safety depends on is actually being issued. Behind a
# flag because an ordinary boot should not pay a klog per request.
case "${XAIOS_IO_TRACE:-0}" in
  0) ;;
  1) KERNEL_CFLAGS="$KERNEL_CFLAGS -DXAIOS_IO_TRACE=1" ;;
  *)
    printf '%s\n' "error: XAIOS_IO_TRACE must be 0 or 1" >&2
    exit 1
    ;;
esac

# Ingest a staged xaiFS package continuously so the crash gate has something
# to interrupt. Behind a flag because it never returns on its own.
case "${XAIOS_CRASH_WRITER:-0}" in
  0) ;;
  1) KERNEL_CFLAGS="$KERNEL_CFLAGS -DXAIOS_CRASH_WRITER=1" ;;
  *)
    printf '%s\n' "error: XAIOS_CRASH_WRITER must be 0 or 1" >&2
    exit 1
    ;;
esac

# Install onto the scratch disk at boot, unasked. Behind a flag because it
# writes a partition table and a filesystem onto whatever is in slot 5 with
# nobody confirming it -- correct for a gate that attaches a scratch disk,
# wrong for an image anyone boots on a machine of their own.
case "${XAIOS_INSTALL_SELF_TEST:-0}" in
  0) ;;
  1) KERNEL_CFLAGS="$KERNEL_CFLAGS -DXAIOS_INSTALL_SELF_TEST=1" ;;
  *)
    printf '%s\n' "error: XAIOS_INSTALL_SELF_TEST must be 0 or 1" >&2
    exit 1
    ;;
esac

# Storage throughput measurement. Behind a flag because it writes to a device
# and takes time, and an ordinary boot should do neither.
case "${XAIOS_STORAGE_BENCH:-0}" in
  0) ;;
  1) KERNEL_CFLAGS="$KERNEL_CFLAGS -DXAIOS_STORAGE_BENCH=1" ;;
  *)
    printf '%s\n' "error: XAIOS_STORAGE_BENCH must be 0 or 1" >&2
    exit 1
    ;;
esac

case "${XAIOS_FAULT_TEST:-}" in
  "") ;;
  page) KERNEL_CFLAGS="$KERNEL_CFLAGS -DXAIOS_FAULT_TEST_PAGE=1" ;;
  ro) KERNEL_CFLAGS="$KERNEL_CFLAGS -DXAIOS_FAULT_TEST_RO=1" ;;
  nx) KERNEL_CFLAGS="$KERNEL_CFLAGS -DXAIOS_FAULT_TEST_NX=1" ;;
  *)
    printf '%s\n' "error: unsupported XAIOS_FAULT_TEST=${XAIOS_FAULT_TEST}" >&2
    exit 2
    ;;
esac

case "${XAIOS_PANIC_SELFTEST:-}" in
  "") ;;
  1)
    KERNEL_CFLAGS="$KERNEL_CFLAGS -DXAIOS_PANIC_SELFTEST=1"
    ;;
  *)
    printf '%s\n' \
      "error: XAIOS_PANIC_SELFTEST must be unset or 1, got ${XAIOS_PANIC_SELFTEST}" >&2
    exit 2
    ;;
esac

case "${XAIOS_STORAGE_CRASH_POINT:-}" in
  "") ;;
  system-backup-flushed)
    KERNEL_CFLAGS="$KERNEL_CFLAGS -DXAIOS_STORAGE_CRASH_AFTER_SYSTEM_BACKUP=1"
    ;;
  system-primary-written)
    KERNEL_CFLAGS="$KERNEL_CFLAGS -DXAIOS_STORAGE_CRASH_AFTER_SYSTEM_PRIMARY=1"
    ;;
  *)
    printf '%s\n' \
      "error: unsupported XAIOS_STORAGE_CRASH_POINT=${XAIOS_STORAGE_CRASH_POINT}" >&2
    exit 2
    ;;
esac

if [ -n "${XAIOS_BUILD_REVISION_OVERRIDE:-}" ]; then
  if ! printf '%s' "$XAIOS_BUILD_REVISION_OVERRIDE" | grep -Eq '^[0-9a-f]{40}$'; then
    printf '%s\n' 'error: XAIOS_BUILD_REVISION_OVERRIDE must be 40 lowercase hex characters' >&2
    exit 2
  fi
  BUILD_REVISION="$XAIOS_BUILD_REVISION_OVERRIDE"
else
  BUILD_REVISION="$(git -C "$ROOT_DIR" rev-parse --verify HEAD 2>/dev/null || printf '%s' unknown)"
fi
# What this build is, single-sourced from BUILD_NUMBER at the repository root.
#
# XAIOS is identified by build number, not by a MAJOR.MINOR.PATCH version.
# There was one, 0.1.0, and it was invented rather than earned: nothing had
# been released, so the three numbers encoded no history and promised
# compatibility rules nobody had agreed. A build number says the one true
# thing -- which build this is -- and says it without implying the rest.
#
# The file is not called BUILD because this repository is developed on a
# case-insensitive filesystem, where that name is already the build directory.
BUILD_NUMBER="$(tr -d ' \n' < "$ROOT_DIR/BUILD_NUMBER" 2>/dev/null || printf '%s' 0)"
if ! printf '%s' "$BUILD_NUMBER" | grep -Eq '^[0-9]+$'; then
  printf '%s\n' "error: BUILD_NUMBER must be a whole number, found '$BUILD_NUMBER'" >&2
  exit 1
fi

BUILD_IDENTIFIER="xaios-admin-control"
if [ -n "${XAIOS_BUILD_REVISION_OVERRIDE:-}" ] ||
   ! git -C "$ROOT_DIR" diff-index --quiet HEAD -- 2>/dev/null ||
   [ -n "$(git -C "$ROOT_DIR" ls-files --others --exclude-standard 2>/dev/null)" ]; then
  BUILD_IDENTIFIER="${BUILD_IDENTIFIER}-dirty"
fi
KERNEL_CFLAGS="$KERNEL_CFLAGS $PASSWORD_AUTH_CFLAG -DXAIOS_BOOT_TEST_APPS=$BOOT_TEST_APPS -DXAIOS_BOOT_VERBOSE=$BOOT_VERBOSE -DXAIOS_FAILURE_TEST_APP=$FAILURE_TEST_APP -DXAIOS_LIBC_TEST=$LIBC_TEST -DXAIOS_BUILD_NUMBER=$BUILD_NUMBER"

# Extra flags for the kernel only, appended last so they win.
#
# This exists so a tunable can be rebuilt at a different setting and measured,
# rather than argued about: the storage benchmark reconstructs the old
# one-sector transfer path with -DVIRTIO_BLK_MAX_TRANSFER=512ULL and compares
# against the same tree. Nothing in CI sets it; a build with it set is not the
# build that ships.
if [ -n "${XAIOS_KERNEL_CFLAGS_EXTRA:-}" ]; then
  KERNEL_CFLAGS="$KERNEL_CFLAGS $XAIOS_KERNEL_CFLAGS_EXTRA"
  printf '%s\n' "Kernel built with extra flags: $XAIOS_KERNEL_CFLAGS_EXTRA"
fi

# Files that use FP/SIMD on purpose opt back in; everything else is built
# without it. See KERNEL_NO_SIMD_CFLAGS below for why.
compile_kernel_simd() {
  KERNEL_ALLOW_SIMD=1 compile_kernel "$1" "$2"
}

compile_kernel() {
  source_path="$1"
  object_path="$2"
  extra_cflags="${3:-}"
  simd_cflags="$KERNEL_NO_SIMD_CFLAGS"
  if [ "${KERNEL_ALLOW_SIMD:-0}" = 1 ]; then
    simd_cflags=""
  fi
  "$CLANG" $KERNEL_CFLAGS $simd_cflags $extra_cflags \
    "-DXAIOS_BUILD_IDENTIFIER=\"$BUILD_IDENTIFIER\"" \
    "-DXAIOS_BUILD_REVISION=\"$BUILD_REVISION\"" \
    "-DXAIOS_BUILD_MODE=\"$BUILD_MODE\"" \
    -I"$ROOT_DIR/kernel/include" \
    -I"$ROOT_DIR/engine/include" \
    -I"$ROOT_DIR/engine/src" \
    -I"$ROOT_DIR/userspace/include" \
    -I"$ROOT_DIR/userspace/sshd" \
    -I"$ROOT_DIR/third_party/bearssl/inc" \
    -c "$source_path" -o "$object_path"
}

if [ "$TARGET_ARCH" = aarch64 ]; then
  ARCH_KERNEL_OBJECTS="
  $KERNEL_BUILD_DIR/entry.o
  $KERNEL_BUILD_DIR/secondary.o
  $KERNEL_BUILD_DIR/vectors.o
  $KERNEL_BUILD_DIR/acpi.o
  $KERNEL_BUILD_DIR/context.o
  $KERNEL_BUILD_DIR/exception.o
  $KERNEL_BUILD_DIR/timer.o
  $KERNEL_BUILD_DIR/rtc.o
  $KERNEL_BUILD_DIR/power.o
  $KERNEL_BUILD_DIR/watchdog.o
  $KERNEL_BUILD_DIR/smmu.o
  $KERNEL_BUILD_DIR/pci.o
  $KERNEL_BUILD_DIR/gic.o
  $KERNEL_BUILD_DIR/gic_its.o
  $KERNEL_BUILD_DIR/smp.o
  $KERNEL_BUILD_DIR/sve.o
  $KERNEL_BUILD_DIR/sve_canary.o
  $KERNEL_BUILD_DIR/virtio_transport_mmio.o
  $KERNEL_BUILD_DIR/virtio_transport_pci.o
  "
else
  ARCH_KERNEL_OBJECTS="
  $KERNEL_BUILD_DIR/entry.o
  $KERNEL_BUILD_DIR/acpi.o
  $KERNEL_BUILD_DIR/early.o
  $KERNEL_BUILD_DIR/engine_packed.o
  $KERNEL_BUILD_DIR/timer.o
  $KERNEL_BUILD_DIR/platform.o
  $KERNEL_BUILD_DIR/power.o
  $KERNEL_BUILD_DIR/watchdog.o
  $KERNEL_BUILD_DIR/pci.o
  $KERNEL_BUILD_DIR/smp.o
  "
fi

KERNEL_OBJECTS="
  $ARCH_KERNEL_OBJECTS
  $KERNEL_BUILD_DIR/kmain.o
  $KERNEL_BUILD_DIR/boot_ui.o
  $KERNEL_BUILD_DIR/klog.o
  $KERNEL_BUILD_DIR/input.o
  $KERNEL_BUILD_DIR/klog_ring.o
  $KERNEL_BUILD_DIR/telemetry.o
  $KERNEL_BUILD_DIR/panic.o
  $KERNEL_BUILD_DIR/assert.o
  $KERNEL_BUILD_DIR/stack_canary.o
  $KERNEL_BUILD_DIR/nvme.o
  $KERNEL_BUILD_DIR/ahci.o
  $KERNEL_BUILD_DIR/virtio_transport.o
  $KERNEL_BUILD_DIR/block_device.o
  $KERNEL_BUILD_DIR/virtio_blk.o
  $KERNEL_BUILD_DIR/virtio_net.o
  $KERNEL_BUILD_DIR/e1000e.o
  $KERNEL_BUILD_DIR/vmxnet3.o
  $KERNEL_BUILD_DIR/net_device.o
  $KERNEL_BUILD_DIR/virtio_rng.o
  $KERNEL_BUILD_DIR/virtio_gpu.o
  $KERNEL_BUILD_DIR/virtio_console.o
  $KERNEL_BUILD_DIR/arch_random.o
  $KERNEL_BUILD_DIR/entropy.o
  $KERNEL_BUILD_DIR/initramfs.o
  $KERNEL_BUILD_DIR/xaiboot_fs.o
  $KERNEL_BUILD_DIR/fat.o
  $KERNEL_BUILD_DIR/vfs.o
  $KERNEL_BUILD_DIR/vfs_xaiboot.o
  $KERNEL_BUILD_DIR/vfs_initramfs.o
  $KERNEL_BUILD_DIR/vfs_xaifs.o
  $KERNEL_BUILD_DIR/model_cache.o
  $KERNEL_BUILD_DIR/ram_residency.o
  $KERNEL_BUILD_DIR/ram_block.o
  $KERNEL_BUILD_DIR/setup_apply.o
  $KERNEL_BUILD_DIR/xai_fs_admin.o
  $KERNEL_BUILD_DIR/service.o
  $KERNEL_BUILD_DIR/syscall.o
  $KERNEL_BUILD_DIR/core_lease.o
  $KERNEL_BUILD_DIR/security.o
  $KERNEL_BUILD_DIR/child_channel.o
  $KERNEL_BUILD_DIR/remote_login.o
  $KERNEL_BUILD_DIR/operations.o
  $KERNEL_BUILD_DIR/admin_control.o
  $KERNEL_BUILD_DIR/control_protocol.o
  $KERNEL_BUILD_DIR/app_store.o
  $KERNEL_BUILD_DIR/cpu_ai_runtime.o
  $KERNEL_BUILD_DIR/ai_kernels.o
  $KERNEL_BUILD_DIR/paged_kv_cache.o
  $KERNEL_BUILD_DIR/inference_batcher.o
  $KERNEL_BUILD_DIR/inference_preempt.o
  $KERNEL_BUILD_DIR/model_parallel.o
  $KERNEL_BUILD_DIR/speculative_decoding.o
  $KERNEL_BUILD_DIR/flash_attention.o
  $KERNEL_BUILD_DIR/model_compilation.o
  $KERNEL_BUILD_DIR/math_intrinsics.o
  $KERNEL_BUILD_DIR/user.o
  $KERNEL_BUILD_DIR/model_arena.o
  $KERNEL_BUILD_DIR/ai_cell.o
  $KERNEL_BUILD_DIR/sandbox.o
  $KERNEL_BUILD_DIR/persistence.o
  $KERNEL_BUILD_DIR/update.o
  $KERNEL_BUILD_DIR/system_slot.o
  $KERNEL_BUILD_DIR/sha256.o
  $KERNEL_BUILD_DIR/crc32.o
  $KERNEL_BUILD_DIR/inflate.o
  $KERNEL_BUILD_DIR/gpt.o
  $KERNEL_BUILD_DIR/partition_device.o
  $KERNEL_BUILD_DIR/storage_admin.o
  $KERNEL_BUILD_DIR/install.o
  $KERNEL_BUILD_DIR/storage_bench.o
  $KERNEL_BUILD_DIR/crash_writer.o
  $KERNEL_BUILD_DIR/rate_limit.o
  $KERNEL_BUILD_DIR/source_index.o
  $KERNEL_BUILD_DIR/network_stack.o
  $KERNEL_BUILD_DIR/network_config.o
  $KERNEL_BUILD_DIR/git_workspace.o
  $KERNEL_BUILD_DIR/agent_protocol.o
  $KERNEL_BUILD_DIR/pmm.o
  $KERNEL_BUILD_DIR/numa.o
  $KERNEL_BUILD_DIR/arena.o
  $KERNEL_BUILD_DIR/kheap.o
  $KERNEL_BUILD_DIR/mmu.o
  $KERNEL_BUILD_DIR/scheduler.o
  $KERNEL_BUILD_DIR/thread.o
  $KERNEL_BUILD_DIR/topology.o
  $KERNEL_BUILD_DIR/arp.o
  $KERNEL_BUILD_DIR/ipv4.o
  $KERNEL_BUILD_DIR/icmp.o
  $KERNEL_BUILD_DIR/ipv6.o
  $KERNEL_BUILD_DIR/icmpv6.o
  $KERNEL_BUILD_DIR/ndp.o
  $KERNEL_BUILD_DIR/dhcpv6.o
  $KERNEL_BUILD_DIR/socket_buffer.o
  $KERNEL_BUILD_DIR/routing.o
  $KERNEL_BUILD_DIR/dns.o
  $KERNEL_BUILD_DIR/dnssec.o
  $KERNEL_BUILD_DIR/ntp.o
  $KERNEL_BUILD_DIR/elf_loader.o
  $KERNEL_BUILD_DIR/string.o
  $KERNEL_BUILD_DIR/bpe_tokenizer.o
  $KERNEL_BUILD_DIR/engine_xai_fs.o
  $KERNEL_BUILD_DIR/engine_xai_fs_writer.o
  $KERNEL_BUILD_DIR/engine_sha256.o
  $KERNEL_BUILD_DIR/engine_sha256_accel.o
  $KERNEL_BUILD_DIR/engine_sha256_dispatch.o
  $KERNEL_BUILD_DIR/kernel_ssh_crypto.o
  $KERNEL_BUILD_DIR/kernel_tweetnacl_subset.o
"

if [ "$TARGET_ARCH" = aarch64 ]; then
  compile_kernel "$ROOT_DIR/kernel/arch/aarch64/entry.S" "$KERNEL_BUILD_DIR/entry.o"
  compile_kernel "$ROOT_DIR/kernel/arch/aarch64/secondary.S" "$KERNEL_BUILD_DIR/secondary.o"
  compile_kernel "$ROOT_DIR/kernel/arch/aarch64/vectors.S" "$KERNEL_BUILD_DIR/vectors.o"
  compile_kernel "$ROOT_DIR/kernel/arch/aarch64/acpi.c" "$KERNEL_BUILD_DIR/acpi.o"
else
  compile_kernel "$ROOT_DIR/kernel/arch/x86_64/entry.S" "$KERNEL_BUILD_DIR/entry.o"
  compile_kernel "$ROOT_DIR/kernel/arch/x86_64/acpi.c" "$KERNEL_BUILD_DIR/acpi.o"
fi
compile_kernel "$ROOT_DIR/kernel/core/kmain.c" "$KERNEL_BUILD_DIR/kmain.o"
compile_kernel "$ROOT_DIR/kernel/core/boot_ui.c" "$KERNEL_BUILD_DIR/boot_ui.o"
compile_kernel "$ROOT_DIR/kernel/core/klog.c" "$KERNEL_BUILD_DIR/klog.o"
compile_kernel "$ROOT_DIR/kernel/dev/input.c" "$KERNEL_BUILD_DIR/input.o"
compile_kernel "$ROOT_DIR/kernel/core/klog_ring.c" "$KERNEL_BUILD_DIR/klog_ring.o"
compile_kernel "$ROOT_DIR/kernel/core/telemetry.c" "$KERNEL_BUILD_DIR/telemetry.o"
compile_kernel "$ROOT_DIR/kernel/core/panic.c" "$KERNEL_BUILD_DIR/panic.o"
compile_kernel "$ROOT_DIR/kernel/core/assert.c" "$KERNEL_BUILD_DIR/assert.o"
compile_kernel "$ROOT_DIR/kernel/core/stack_canary.c" "$KERNEL_BUILD_DIR/stack_canary.o"
if [ "$TARGET_ARCH" = aarch64 ]; then
  compile_kernel "$ROOT_DIR/kernel/arch/aarch64/exception.c" "$KERNEL_BUILD_DIR/exception.o"
  compile_kernel "$ROOT_DIR/kernel/arch/aarch64/timer.c" "$KERNEL_BUILD_DIR/timer.o"
  compile_kernel "$ROOT_DIR/kernel/arch/aarch64/rtc.c" "$KERNEL_BUILD_DIR/rtc.o"
  compile_kernel "$ROOT_DIR/kernel/arch/aarch64/power.c" "$KERNEL_BUILD_DIR/power.o"
  compile_kernel "$ROOT_DIR/kernel/arch/aarch64/watchdog.c" "$KERNEL_BUILD_DIR/watchdog.o"
  compile_kernel "$ROOT_DIR/kernel/arch/aarch64/smmu.c" "$KERNEL_BUILD_DIR/smmu.o"
  compile_kernel "$ROOT_DIR/kernel/arch/aarch64/pci.c" "$KERNEL_BUILD_DIR/pci.o"
  compile_kernel "$ROOT_DIR/kernel/arch/aarch64/gic.c" "$KERNEL_BUILD_DIR/gic.o"
  compile_kernel "$ROOT_DIR/kernel/arch/aarch64/gic_its.c" "$KERNEL_BUILD_DIR/gic_its.o"
  compile_kernel "$ROOT_DIR/kernel/arch/aarch64/smp.c" "$KERNEL_BUILD_DIR/smp.o"
  compile_kernel_simd "$ROOT_DIR/kernel/arch/aarch64/sve.c" "$KERNEL_BUILD_DIR/sve.o"
  compile_kernel_simd "$ROOT_DIR/kernel/arch/aarch64/sve_canary.S" "$KERNEL_BUILD_DIR/sve_canary.o"
else
  compile_kernel "$ROOT_DIR/kernel/arch/x86_64/early.c" "$KERNEL_BUILD_DIR/early.o"
  compile_kernel_simd "$ROOT_DIR/engine/src/packed.c" "$KERNEL_BUILD_DIR/engine_packed.o"
  compile_kernel "$ROOT_DIR/kernel/arch/x86_64/timer.c" "$KERNEL_BUILD_DIR/timer.o"
  compile_kernel "$ROOT_DIR/kernel/arch/x86_64/platform.c" "$KERNEL_BUILD_DIR/platform.o"
  compile_kernel "$ROOT_DIR/kernel/arch/x86_64/power.c" "$KERNEL_BUILD_DIR/power.o"
  compile_kernel "$ROOT_DIR/kernel/arch/x86_64/watchdog.c" "$KERNEL_BUILD_DIR/watchdog.o"
  compile_kernel "$ROOT_DIR/kernel/arch/x86_64/pci.c" "$KERNEL_BUILD_DIR/pci.o"
  compile_kernel "$ROOT_DIR/kernel/arch/x86_64/smp.c" "$KERNEL_BUILD_DIR/smp.o"
fi
compile_kernel "$ROOT_DIR/kernel/arch/aarch64/topology.c" "$KERNEL_BUILD_DIR/topology.o"
compile_kernel "$ROOT_DIR/kernel/dev/nvme.c" "$KERNEL_BUILD_DIR/nvme.o"
compile_kernel "$ROOT_DIR/kernel/dev/ahci.c" "$KERNEL_BUILD_DIR/ahci.o"
if [ "$TARGET_ARCH" = aarch64 ]; then
  # aarch64 can meet virtio on either transport, so both are built and a
  # dispatcher picks between them. x86_64 only ever sees PCI.
  compile_kernel "$ROOT_DIR/kernel/dev/virtio/virtio_transport.c" \
    "$KERNEL_BUILD_DIR/virtio_transport_mmio.o" "-DXAIOS_VIRTIO_MMIO_BACKEND=1"
  compile_kernel "$ROOT_DIR/kernel/dev/virtio/virtio_transport_pci.c" \
    "$KERNEL_BUILD_DIR/virtio_transport_pci.o" "-DXAIOS_VIRTIO_PCI_BACKEND=1"
  compile_kernel "$ROOT_DIR/kernel/dev/virtio/virtio_transport_dispatch.c" \
    "$KERNEL_BUILD_DIR/virtio_transport.o"
else
  compile_kernel "$ROOT_DIR/kernel/dev/virtio/virtio_transport_pci.c" "$KERNEL_BUILD_DIR/virtio_transport.o"
fi
compile_kernel "$ROOT_DIR/kernel/dev/block_device.c" "$KERNEL_BUILD_DIR/block_device.o"
compile_kernel "$ROOT_DIR/kernel/dev/virtio/virtio_blk.c" "$KERNEL_BUILD_DIR/virtio_blk.o"
compile_kernel "$ROOT_DIR/kernel/dev/virtio/virtio_net.c" "$KERNEL_BUILD_DIR/virtio_net.o"
compile_kernel "$ROOT_DIR/kernel/dev/e1000e.c" "$KERNEL_BUILD_DIR/e1000e.o"
compile_kernel "$ROOT_DIR/kernel/dev/vmxnet3.c" "$KERNEL_BUILD_DIR/vmxnet3.o"
compile_kernel "$ROOT_DIR/kernel/dev/net_device.c" "$KERNEL_BUILD_DIR/net_device.o"
compile_kernel "$ROOT_DIR/kernel/dev/virtio/virtio_rng.c" "$KERNEL_BUILD_DIR/virtio_rng.o"
compile_kernel "$ROOT_DIR/kernel/dev/virtio/virtio_gpu.c" "$KERNEL_BUILD_DIR/virtio_gpu.o"
compile_kernel "$ROOT_DIR/kernel/dev/virtio/virtio_console.c" "$KERNEL_BUILD_DIR/virtio_console.o"
compile_kernel "$ROOT_DIR/kernel/runtime/arch_random.c" "$KERNEL_BUILD_DIR/arch_random.o"
compile_kernel "$ROOT_DIR/kernel/runtime/entropy.c" "$KERNEL_BUILD_DIR/entropy.o"
compile_kernel "$ROOT_DIR/kernel/fs/initramfs.c" "$KERNEL_BUILD_DIR/initramfs.o"
compile_kernel "$ROOT_DIR/kernel/fs/xaiboot_fs.c" "$KERNEL_BUILD_DIR/xaiboot_fs.o"
compile_kernel "$ROOT_DIR/kernel/fs/fat.c" "$KERNEL_BUILD_DIR/fat.o"
compile_kernel "$ROOT_DIR/kernel/fs/vfs.c" "$KERNEL_BUILD_DIR/vfs.o"
compile_kernel "$ROOT_DIR/kernel/fs/vfs_xaiboot.c" "$KERNEL_BUILD_DIR/vfs_xaiboot.o"
compile_kernel "$ROOT_DIR/kernel/fs/vfs_initramfs.c" "$KERNEL_BUILD_DIR/vfs_initramfs.o"
compile_kernel "$ROOT_DIR/kernel/fs/vfs_xaifs.c" "$KERNEL_BUILD_DIR/vfs_xaifs.o"
compile_kernel "$ROOT_DIR/kernel/fs/model_cache.c" "$KERNEL_BUILD_DIR/model_cache.o"
compile_kernel "$ROOT_DIR/kernel/mm/ram_residency.c" "$KERNEL_BUILD_DIR/ram_residency.o"
compile_kernel "$ROOT_DIR/kernel/dev/ram_block.c" "$KERNEL_BUILD_DIR/ram_block.o"
compile_kernel "$ROOT_DIR/kernel/runtime/setup_apply.c" "$KERNEL_BUILD_DIR/setup_apply.o"
compile_kernel "$ROOT_DIR/kernel/fs/xai_fs_admin.c" "$KERNEL_BUILD_DIR/xai_fs_admin.o"
compile_kernel "$ROOT_DIR/kernel/user/service.c" "$KERNEL_BUILD_DIR/service.o"
compile_kernel "$ROOT_DIR/kernel/user/syscall.c" "$KERNEL_BUILD_DIR/syscall.o"
compile_kernel "$ROOT_DIR/kernel/runtime/core_lease.c" "$KERNEL_BUILD_DIR/core_lease.o"
compile_kernel "$ROOT_DIR/kernel/runtime/security.c" "$KERNEL_BUILD_DIR/security.o"
compile_kernel "$ROOT_DIR/kernel/runtime/child_channel.c" "$KERNEL_BUILD_DIR/child_channel.o"
compile_kernel "$ROOT_DIR/kernel/runtime/remote_login.c" "$KERNEL_BUILD_DIR/remote_login.o"
compile_kernel "$ROOT_DIR/kernel/runtime/operations.c" "$KERNEL_BUILD_DIR/operations.o"
compile_kernel "$ROOT_DIR/kernel/runtime/admin_control.c" "$KERNEL_BUILD_DIR/admin_control.o"
compile_kernel "$ROOT_DIR/kernel/runtime/control_protocol.c" "$KERNEL_BUILD_DIR/control_protocol.o"
compile_kernel "$ROOT_DIR/kernel/runtime/app_store.c" "$KERNEL_BUILD_DIR/app_store.o"
compile_kernel "$ROOT_DIR/kernel/user/user.c" "$KERNEL_BUILD_DIR/user.o"
compile_kernel "$ROOT_DIR/kernel/runtime/model_arena.c" "$KERNEL_BUILD_DIR/model_arena.o"
compile_kernel "$ROOT_DIR/kernel/runtime/ai_cell.c" "$KERNEL_BUILD_DIR/ai_cell.o"
compile_kernel "$ROOT_DIR/kernel/runtime/cpu_ai_runtime.c" "$KERNEL_BUILD_DIR/cpu_ai_runtime.o"
compile_kernel_simd "$ROOT_DIR/kernel/runtime/ai_kernels.c" "$KERNEL_BUILD_DIR/ai_kernels.o"
compile_kernel_simd "$ROOT_DIR/kernel/runtime/paged_kv_cache.c" "$KERNEL_BUILD_DIR/paged_kv_cache.o"
compile_kernel "$ROOT_DIR/kernel/runtime/inference_batcher.c" "$KERNEL_BUILD_DIR/inference_batcher.o"
compile_kernel "$ROOT_DIR/kernel/runtime/inference_preempt.c" "$KERNEL_BUILD_DIR/inference_preempt.o"
compile_kernel_simd "$ROOT_DIR/kernel/runtime/model_parallel.c" "$KERNEL_BUILD_DIR/model_parallel.o"
compile_kernel "$ROOT_DIR/kernel/runtime/speculative_decoding.c" "$KERNEL_BUILD_DIR/speculative_decoding.o"
compile_kernel_simd "$ROOT_DIR/kernel/runtime/flash_attention.c" "$KERNEL_BUILD_DIR/flash_attention.o"
compile_kernel "$ROOT_DIR/kernel/runtime/model_compilation.c" "$KERNEL_BUILD_DIR/model_compilation.o"
compile_kernel_simd "$ROOT_DIR/kernel/runtime/math_intrinsics.c" "$KERNEL_BUILD_DIR/math_intrinsics.o"
compile_kernel "$ROOT_DIR/kernel/runtime/sandbox.c" "$KERNEL_BUILD_DIR/sandbox.o"
compile_kernel "$ROOT_DIR/kernel/runtime/persistence.c" "$KERNEL_BUILD_DIR/persistence.o"
compile_kernel "$ROOT_DIR/kernel/runtime/update.c" "$KERNEL_BUILD_DIR/update.o"
compile_kernel "$ROOT_DIR/kernel/runtime/system_slot.c" "$KERNEL_BUILD_DIR/system_slot.o"
compile_kernel "$ROOT_DIR/kernel/runtime/sha256.c" "$KERNEL_BUILD_DIR/sha256.o"
compile_kernel "$ROOT_DIR/kernel/lib/crc32.c" "$KERNEL_BUILD_DIR/crc32.o"
compile_kernel "$ROOT_DIR/kernel/lib/inflate.c" "$KERNEL_BUILD_DIR/inflate.o"
compile_kernel "$ROOT_DIR/kernel/storage/gpt.c" "$KERNEL_BUILD_DIR/gpt.o"
compile_kernel "$ROOT_DIR/kernel/storage/partition_device.c" "$KERNEL_BUILD_DIR/partition_device.o"
compile_kernel "$ROOT_DIR/kernel/storage/storage_admin.c" "$KERNEL_BUILD_DIR/storage_admin.o"
compile_kernel "$ROOT_DIR/kernel/storage/install.c" "$KERNEL_BUILD_DIR/install.o"
compile_kernel "$ROOT_DIR/kernel/storage/storage_bench.c" "$KERNEL_BUILD_DIR/storage_bench.o"
compile_kernel "$ROOT_DIR/kernel/storage/crash_writer.c" "$KERNEL_BUILD_DIR/crash_writer.o"
compile_kernel "$ROOT_DIR/kernel/runtime/rate_limit.c" "$KERNEL_BUILD_DIR/rate_limit.o"
compile_kernel "$ROOT_DIR/kernel/runtime/source_index.c" "$KERNEL_BUILD_DIR/source_index.o"
compile_kernel "$ROOT_DIR/kernel/runtime/network_stack.c" "$KERNEL_BUILD_DIR/network_stack.o"
compile_kernel "$ROOT_DIR/kernel/net/network_config.c" "$KERNEL_BUILD_DIR/network_config.o"
compile_kernel "$ROOT_DIR/kernel/runtime/git_workspace.c" "$KERNEL_BUILD_DIR/git_workspace.o"
compile_kernel "$ROOT_DIR/kernel/runtime/agent_protocol.c" "$KERNEL_BUILD_DIR/agent_protocol.o"
compile_kernel "$ROOT_DIR/kernel/mm/pmm.c" "$KERNEL_BUILD_DIR/pmm.o"
compile_kernel "$ROOT_DIR/kernel/mm/numa.c" "$KERNEL_BUILD_DIR/numa.o"
compile_kernel "$ROOT_DIR/kernel/mm/arena.c" "$KERNEL_BUILD_DIR/arena.o"
compile_kernel "$ROOT_DIR/kernel/mm/kheap.c" "$KERNEL_BUILD_DIR/kheap.o"
compile_kernel "$ROOT_DIR/kernel/arch/$ARCH_KERNEL_DIR/mmu.c" "$KERNEL_BUILD_DIR/mmu.o"
compile_kernel "$ROOT_DIR/kernel/sched/scheduler.c" "$KERNEL_BUILD_DIR/scheduler.o"
compile_kernel "$ROOT_DIR/kernel/sched/thread.c" "$KERNEL_BUILD_DIR/thread.o"
if [ "$TARGET_ARCH" = aarch64 ]; then
  compile_kernel "$ROOT_DIR/kernel/sched/context.S" "$KERNEL_BUILD_DIR/context.o"
fi
compile_kernel "$ROOT_DIR/kernel/net/arp.c" "$KERNEL_BUILD_DIR/arp.o"
compile_kernel "$ROOT_DIR/kernel/net/ipv4.c" "$KERNEL_BUILD_DIR/ipv4.o"
compile_kernel "$ROOT_DIR/kernel/net/icmp.c" "$KERNEL_BUILD_DIR/icmp.o"
compile_kernel "$ROOT_DIR/kernel/net/ipv6.c" "$KERNEL_BUILD_DIR/ipv6.o"
compile_kernel "$ROOT_DIR/kernel/net/icmpv6.c" "$KERNEL_BUILD_DIR/icmpv6.o"
compile_kernel "$ROOT_DIR/kernel/net/ndp.c" "$KERNEL_BUILD_DIR/ndp.o"
compile_kernel "$ROOT_DIR/kernel/net/dhcpv6.c" "$KERNEL_BUILD_DIR/dhcpv6.o"
compile_kernel "$ROOT_DIR/kernel/net/socket_buffer.c" "$KERNEL_BUILD_DIR/socket_buffer.o"
compile_kernel "$ROOT_DIR/kernel/net/routing.c" "$KERNEL_BUILD_DIR/routing.o"
compile_kernel "$ROOT_DIR/kernel/net/dns.c" "$KERNEL_BUILD_DIR/dns.o"
compile_kernel "$ROOT_DIR/kernel/net/dnssec.c" "$KERNEL_BUILD_DIR/dnssec.o"
compile_kernel "$ROOT_DIR/kernel/net/ntp.c" "$KERNEL_BUILD_DIR/ntp.o"
compile_kernel "$ROOT_DIR/kernel/mm/elf_loader.c" "$KERNEL_BUILD_DIR/elf_loader.o"
compile_kernel "$ROOT_DIR/kernel/lib/string.c" "$KERNEL_BUILD_DIR/string.o"
compile_kernel "$ROOT_DIR/kernel/runtime/bpe_tokenizer.c" "$KERNEL_BUILD_DIR/bpe_tokenizer.o"
compile_kernel "$ROOT_DIR/engine/src/xai_fs.c" "$KERNEL_BUILD_DIR/engine_xai_fs.o"
compile_kernel "$ROOT_DIR/engine/src/xai_fs_writer.c" "$KERNEL_BUILD_DIR/engine_xai_fs_writer.o"
compile_kernel "$ROOT_DIR/engine/src/sha256.c" "$KERNEL_BUILD_DIR/engine_sha256.o"
# The accelerated compressor is the one file here that needs SIMD registers,
# and it asks clang for the SHA2 instructions in that function alone rather
# than raising the baseline for anything else. It runs only on a CPU that
# reported the extension; see engine_sha256_dispatch.c.
compile_kernel_simd "$ROOT_DIR/engine/src/sha256_accel.c" "$KERNEL_BUILD_DIR/engine_sha256_accel.o"
compile_kernel "$ROOT_DIR/kernel/runtime/engine_sha256_dispatch.c" "$KERNEL_BUILD_DIR/engine_sha256_dispatch.o"
compile_kernel "$ROOT_DIR/userspace/sshd/ssh_crypto.c" "$KERNEL_BUILD_DIR/kernel_ssh_crypto.o"
compile_kernel "$ROOT_DIR/userspace/sshd/tweetnacl_subset.c" "$KERNEL_BUILD_DIR/kernel_tweetnacl_subset.o"

KERNEL_RESPONSE_FILE="$KERNEL_BUILD_DIR/objects.rsp"
printf '%s\n' "$KERNEL_OBJECTS" | while IFS= read -r object_path; do
  if [ "$object_path" != "" ]; then
    printf '"%s"\n' "${object_path#  }"
  fi
done > "$KERNEL_RESPONSE_FILE"
KERNEL_BEARSSL="$BUILD_DIR/bearssl/$TARGET_ARCH/libbearssl-xapt.a"
[ -f "$KERNEL_BEARSSL" ] || "$ROOT_DIR/scripts/build-bearssl.sh" "$TARGET_ARCH"
printf '"%s"\n' "$KERNEL_BEARSSL" >> "$KERNEL_RESPONSE_FILE"

"$LD_LLD" \
  -nostdlib \
  $KERNEL_LDFLAGS \
  -T "$ARCH_LINKER" \
  -o "$KERNEL_ELF" \
  @"$KERNEL_RESPONSE_FILE"

printf '%s\n' "Building userspace /init ELF..."
USER_ARCH_CFLAGS=""
if [ "$TARGET_ARCH" = x86_64 ]; then
  USER_ARCH_CFLAGS="-mcmodel=large -mno-red-zone"
fi
"$CLANG" \
  --target="$TARGET_TRIPLE" \
  $USER_ARCH_CFLAGS \
  -ffreestanding \
  -fno-stack-protector \
  -fno-builtin \
  -fno-pic \
  -fno-pie \
  -Wall \
  -Wextra \
  -Werror \
  -c "$INIT_SOURCE" \
  -o "$INIT_OBJ"

"$LD_LLD" \
  -nostdlib \
  -T "$ROOT_DIR/userspace/init/linker.ld" \
  -o "$INIT_ELF" \
  "$INIT_OBJ"

printf '%s\n' "Building userspace /bin/service-manager ELF..."
"$CLANG" \
  --target="$TARGET_TRIPLE" \
  $USER_ARCH_CFLAGS \
  -ffreestanding \
  -fno-stack-protector \
  -fno-builtin \
  -fno-pic \
  -fno-pie \
  -Wall \
  -Wextra \
  -Werror \
  -c "$SERVICE_MANAGER_SOURCE" \
  -o "$SERVICE_MANAGER_OBJ"

"$LD_LLD" \
  -nostdlib \
  -T "$ROOT_DIR/userspace/init/linker.ld" \
  -o "$SERVICE_MANAGER_ELF" \
  "$SERVICE_MANAGER_OBJ"

printf '%s\n' "Building userspace /bin/xaios-worker ELF..."
"$CLANG" \
  --target="$TARGET_TRIPLE" \
  $USER_ARCH_CFLAGS \
  -ffreestanding \
  -fno-stack-protector \
  -fno-builtin \
  -fno-pic \
  -fno-pie \
  -Wall \
  -Wextra \
  -Werror \
  -c "$WORKER_SOURCE" \
  -o "$WORKER_OBJ"

"$LD_LLD" \
  -nostdlib \
  -T "$ROOT_DIR/userspace/init/linker.ld" \
  -o "$WORKER_ELF" \
  "$WORKER_OBJ"

printf '%s\n' "Building userspace C runtime..."
"$CLANG" \
  --target="$TARGET_TRIPLE" \
  $USER_ARCH_CFLAGS \
  -ffreestanding \
  -fno-stack-protector \
  -fno-builtin \
  -fno-pic \
  -fno-pie \
  -Wall \
  -Wextra \
  -Werror \
  -I"$ROOT_DIR/userspace/include" \
  -c "$ROOT_DIR/userspace/lib/start.S" \
  -o "$USER_START_OBJ"

"$CLANG" \
  --target="$TARGET_TRIPLE" \
  $USER_ARCH_CFLAGS \
  -std=c99 \
  -ffreestanding \
  -fno-stack-protector \
  -fno-builtin \
  -fno-pic \
  -fno-pie \
  -Wall \
  -Wextra \
  -Werror \
  -I"$ROOT_DIR/userspace/include" \
  -c "$ROOT_DIR/userspace/lib/xaios_user.c" \
  -o "$USER_LIB_OBJ"

"$CLANG" \
  --target="$TARGET_TRIPLE" \
  $USER_ARCH_CFLAGS \
  -std=c99 \
  -ffreestanding \
  -fno-stack-protector \
  -fno-builtin \
  -fno-pic \
  -fno-pie \
  -Os \
  -Wall \
  -Wextra \
  -Werror \
  -I"$ROOT_DIR/userspace/include" \
  -c "$ROOT_DIR/userspace/lib/xaios_control_client.c" \
  -o "$USER_CONTROL_OBJ"

set --
for app in $USER_APPS; do
  app_obj="$INIT_BUILD_DIR/$app.o"
  app_elf="$INIT_BUILD_DIR/$app.elf"
  printf '%s\n' "Building userspace /bin/$app ELF..."
  "$CLANG" \
    --target="$TARGET_TRIPLE" \
    $USER_ARCH_CFLAGS \
    -std=c99 \
    -ffreestanding \
    -fno-stack-protector \
    -fno-builtin \
    -fno-pic \
    -fno-pie \
    -Wall \
    -Wextra \
    -Werror \
    -DXAIOS_BOOT_TEST_APPS="$BOOT_TEST_APPS" \
    $([ "$app" = clustertest ] && printf '%s' "$CLUSTER_APP_CFLAGS") \
    -I"$ROOT_DIR/userspace/include" \
    -I"$ROOT_DIR/userspace/sshd" \
    -I"$ROOT_DIR/engine/include" \
    -c "$ROOT_DIR/userspace/apps/$app.c" \
    -o "$app_obj"

  if [ "$app" = "clustertest" ]; then
    # The cluster framing lives in engine/ and has never been built for a
    # target before -- every test of it ran hosted, which is how it kept a
    # transport-shaped hole for as long as it did. It needs the engine headers
    # and its hash; memcpy and memset come from the userspace library, which
    # provides both under their standard names.
    CLUSTER_OBJ="$INIT_BUILD_DIR/cluster.o"
    CLUSTER_SHA_OBJ="$INIT_BUILD_DIR/cluster-sha256.o"
    for source in cluster sha256; do
      "$CLANG" --target="$TARGET_TRIPLE" $USER_ARCH_CFLAGS -std=c99 \
        -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
        -Wall -Wextra -Werror \
        -I"$ROOT_DIR/engine/include" -I"$ROOT_DIR/engine/src" \
        -I"$ROOT_DIR/userspace/include" \
        -c "$ROOT_DIR/engine/src/$source.c" \
        -o "$INIT_BUILD_DIR/cluster-$source.o"
    done
    CLUSTER_OBJ="$INIT_BUILD_DIR/cluster-cluster.o"
    CLUSTER_SHA_OBJ="$INIT_BUILD_DIR/cluster-sha256.o"
  fi

  if [ "$app" = "xapt" ]; then
    XAPT_TLS_OBJ="$INIT_BUILD_DIR/xapt-tls.o"
    XAPT_BEARSSL="$BUILD_DIR/bearssl/$TARGET_ARCH/libbearssl-xapt.a"
    [ -f "$XAPT_BEARSSL" ] || "$ROOT_DIR/scripts/build-bearssl.sh" "$TARGET_ARCH"
    "$CLANG" --target="$TARGET_TRIPLE" $USER_ARCH_CFLAGS -std=c99 \
      -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
      -Os -Wall -Wextra -Werror \
      -isystem "$BUILD_DIR/libc/$TARGET_ARCH/sysroot/include" \
      -I"$ROOT_DIR/userspace/include" -I"$ROOT_DIR/userspace/apps" \
      -I"$ROOT_DIR/third_party/bearssl/inc" \
      -c "$ROOT_DIR/userspace/apps/xapt_tls.c" -o "$XAPT_TLS_OBJ"
    XAPT_TRUST_OBJ="$INIT_BUILD_DIR/xapt-trust-anchors.o"
    "$CLANG" --target="$TARGET_TRIPLE" $USER_ARCH_CFLAGS -std=c99 \
      -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
      -Os -Wall -Wextra -Werror \
      -isystem "$BUILD_DIR/libc/$TARGET_ARCH/sysroot/include" \
      -I"$ROOT_DIR/userspace/include" -I"$ROOT_DIR/userspace/apps" \
      -I"$ROOT_DIR/third_party/bearssl/inc" \
      -c "$ROOT_DIR/userspace/apps/xapt_trust_anchors.c" \
      -o "$XAPT_TRUST_OBJ"
    "$LD_LLD" -nostdlib -T "$ROOT_DIR/userspace/init/linker.ld" \
      -o "$app_elf" "$USER_START_OBJ" "$USER_LIB_OBJ" \
      "$USER_CONTROL_OBJ" "$app_obj" "$XAPT_TLS_OBJ" "$XAPT_TRUST_OBJ" \
      "$XAPT_BEARSSL"
  elif [ "$app" = "xaios-setup" ]; then
    # Setup writes the credential records sshd reads, so it hashes them with
    # the same code sshd verifies them with. Two implementations of PBKDF2
    # that disagree produce an account that cannot be logged into, and the
    # disagreement would only show at the login prompt.
    SETUP_CRYPTO_OBJ="$INIT_BUILD_DIR/setup-ssh-crypto.o"
    SETUP_NACL_OBJ="$INIT_BUILD_DIR/setup-tweetnacl.o"
    for setup_src in ssh_crypto tweetnacl_subset; do
      "$CLANG" --target="$TARGET_TRIPLE" $USER_ARCH_CFLAGS -std=c99 \
        -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
        -Wall -Wextra -Werror \
        -I"$ROOT_DIR/userspace/include" -I"$ROOT_DIR/userspace/sshd" \
        -c "$ROOT_DIR/userspace/sshd/$setup_src.c" \
        -o "$INIT_BUILD_DIR/setup-$setup_src.o"
    done
    SETUP_CRYPTO_OBJ="$INIT_BUILD_DIR/setup-ssh_crypto.o"
    SETUP_NACL_OBJ="$INIT_BUILD_DIR/setup-tweetnacl_subset.o"
    "$LD_LLD" \
      -nostdlib \
      -T "$ROOT_DIR/userspace/init/linker.ld" \
      -o "$app_elf" \
      "$USER_START_OBJ" \
      "$USER_LIB_OBJ" \
      "$USER_CONTROL_OBJ" \
      "$app_obj" \
      "$SETUP_CRYPTO_OBJ" \
      "$SETUP_NACL_OBJ"
  elif [ "$app" = "xaiosctl" ] ||
      [ "$app" = "htop" ]; then
    "$LD_LLD" \
      -nostdlib \
      -T "$ROOT_DIR/userspace/init/linker.ld" \
      -o "$app_elf" \
      "$USER_START_OBJ" \
      "$USER_LIB_OBJ" \
      "$USER_CONTROL_OBJ" \
      "$app_obj"
  elif [ "$app" = "clustertest" ]; then
    "$LD_LLD" \
      -nostdlib \
      -T "$ROOT_DIR/userspace/init/linker.ld" \
      -o "$app_elf" \
      "$USER_START_OBJ" \
      "$USER_LIB_OBJ" \
      "$app_obj" \
      "$CLUSTER_OBJ" \
      "$CLUSTER_SHA_OBJ"
  else
    "$LD_LLD" \
      -nostdlib \
      -T "$ROOT_DIR/userspace/init/linker.ld" \
      -o "$app_elf" \
      "$USER_START_OBJ" \
      "$USER_LIB_OBJ" \
      "$app_obj"
  fi
  set -- "$@" "/bin/$app=$app_elf"
done

USER_INFLATE_OBJ="$INIT_BUILD_DIR/xutils-inflate.o"
"$CLANG" \
  --target="$TARGET_TRIPLE" \
  $USER_ARCH_CFLAGS \
  -std=c99 \
  -ffreestanding \
  -fno-stack-protector \
  -fno-builtin \
  -fno-pic \
  -fno-pie \
  -Wall \
  -Wextra \
  -Werror \
  -I"$ROOT_DIR/kernel/include" \
  -c "$ROOT_DIR/kernel/lib/inflate.c" \
  -o "$USER_INFLATE_OBJ"

for app in $UTILITY_APPS; do
  app_obj="$INIT_BUILD_DIR/xutils-$app.o"
  app_elf="$INIT_BUILD_DIR/$app.elf"
  printf '%s\n' "Building userspace /bin/$app utility ELF..."
  "$CLANG" \
    --target="$TARGET_TRIPLE" \
    $USER_ARCH_CFLAGS \
    -std=c99 \
    -ffreestanding \
    -fno-stack-protector \
    -fno-builtin \
    -fno-pic \
    -fno-pie \
    -Wall \
    -Wextra \
    -Werror \
    -DXAIOS_UTILITY_NAME=\"$app\" \
    -I"$ROOT_DIR/userspace/include" \
    -c "$ROOT_DIR/userspace/apps/xutils.c" \
    -o "$app_obj"
  "$LD_LLD" \
    -nostdlib \
    -T "$ROOT_DIR/userspace/init/linker.ld" \
    -o "$app_elf" \
    "$USER_START_OBJ" \
    "$USER_LIB_OBJ" \
    "$USER_CONTROL_OBJ" \
    "$USER_INFLATE_OBJ" \
    "$app_obj"
  set -- "$@" "/bin/$app=$app_elf"
done

LIBC_SYSROOT="$BUILD_DIR/libc/$TARGET_ARCH/sysroot"
LIBC_RUNTIME="$BUILD_DIR/libc/$TARGET_ARCH/runtime-test"
LIBC_READY=1
for libc_artifact in \
    "$LIBC_SYSROOT/lib/libc.a" \
    "$LIBC_SYSROOT/lib/libm.a" \
    "$LIBC_SYSROOT/lib/libcompiler_rt_xaios.a" \
    "$LIBC_RUNTIME/crt0.o" \
    "$LIBC_RUNTIME/runtime_main_void.o" \
    "$LIBC_RUNTIME/os_adapter.o" \
    "$LIBC_RUNTIME/thread_context.o" \
    "$LIBC_RUNTIME/locking.o" \
    "$LIBC_RUNTIME/thread_api.o"; do
  if [ ! -f "$libc_artifact" ]; then
    LIBC_READY=0
  fi
done
if [ "$LIBC_READY" = 0 ]; then
  printf '%s\n' "Building hosted ISO C99 libc for $TARGET_ARCH..."
  XAIOS_LIBC_ARCHES="$TARGET_ARCH" "$ROOT_DIR/scripts/build-libc.sh"
fi
for app in $HOSTED_USER_APPS; do
  app_elf="$INIT_BUILD_DIR/$app.elf"
  printf '%s\n' "Building hosted C99 userspace /bin/$app ELF..."
  "$ROOT_DIR/scripts/build-c99-app.sh" --arch "$TARGET_ARCH" --main void \
    "$ROOT_DIR/userspace/apps/hosted/$app.c" "$app_elf"
  set -- "$@" "/bin/$app=$app_elf"
done

set -- "$@" "/etc/xapt.conf=$ROOT_DIR/userspace/init/xapt.conf"

if [ "$LIBC_TEST" = 1 ]; then
  LIBC_TEST_ELF="$BUILD_DIR/libc/$TARGET_ARCH/runtime-test/c99-runtime-smoke.elf"
  if [ ! -f "$LIBC_TEST_ELF" ]; then
    printf '%s\n' "error: hosted C99 test image missing: $LIBC_TEST_ELF" >&2
    printf '%s\n' "       Run XAIOS_LIBC_ARCHES=$TARGET_ARCH make libc first." >&2
    exit 1
  fi
  LIBC_MAIN_VOID_ELF="$BUILD_DIR/libc/$TARGET_ARCH/runtime-test/c99-main_void.elf"
  LIBC_EXIT_PROBE_ELF="$BUILD_DIR/libc/$TARGET_ARCH/runtime-test/c99-exit_probe.elf"
  LIBC_ABORT_PROBE_ELF="$BUILD_DIR/libc/$TARGET_ARCH/runtime-test/c99-abort_probe.elf"
  LIBC_THREAD_CONTEXT_ELF="$BUILD_DIR/libc/$TARGET_ARCH/runtime-test/c99-thread-context.elf"
  for libc_probe in "$LIBC_MAIN_VOID_ELF" "$LIBC_EXIT_PROBE_ELF" \
      "$LIBC_ABORT_PROBE_ELF" "$LIBC_THREAD_CONTEXT_ELF"; do
    if [ ! -f "$libc_probe" ]; then
      printf 'error: missing libc probe: %s\n' "$libc_probe" >&2
      exit 1
    fi
  done
  set -- "$@" "/bin/c99-runtime-smoke=$LIBC_TEST_ELF" \
    "/bin/c99-main-void=$LIBC_MAIN_VOID_ELF" \
    "/bin/c99-exit-probe=$LIBC_EXIT_PROBE_ELF" \
    "/bin/c99-abort-probe=$LIBC_ABORT_PROBE_ELF" \
    "/bin/c99-thread-context=$LIBC_THREAD_CONTEXT_ELF"
fi

printf '%s\n' "Building userspace /bin/sshd ELF..."
SSHD_RESPONSE_FILE="$INIT_BUILD_DIR/sshd-objects.rsp"
: > "$SSHD_RESPONSE_FILE"
for sshd_src in sshd.c ssh_crypto.c ssh_mlkem.c tweetnacl_subset.c ssh_protocol.c ssh_channel.c ssh_client_proxy.c ssh_host_key.c ssh_connection.c sftp_server.c less_pager.c; do
  sshd_obj="$INIT_BUILD_DIR/sshd-${sshd_src%.c}.o"
  sshd_opt=""
  if [ "$sshd_src" = "sshd.c" ]; then
    sshd_opt="-Os"
  fi
  "$CLANG" \
    --target="$TARGET_TRIPLE" \
    $USER_ARCH_CFLAGS \
    -std=c99 \
    -ffreestanding \
    -fno-stack-protector \
    -fno-builtin \
    -fno-pic \
    -fno-pie \
    $sshd_opt \
    -Wall \
    -Wextra \
    -Werror \
    $PASSWORD_AUTH_CFLAG \
    -DMLK_CONFIG_FILE='"mlkem_xaios_config.h"' \
    -I"$ROOT_DIR/userspace/include" \
    -I"$ROOT_DIR/userspace/sshd" \
    -I"$ROOT_DIR/third_party/mlkem-native/mlkem" \
    -I"$ROOT_DIR/userspace/apps/terminal" \
    -c "$ROOT_DIR/userspace/sshd/$sshd_src" \
    -o "$sshd_obj"
  printf '"%s"\n' "$sshd_obj" >> "$SSHD_RESPONSE_FILE"
done
SSHD_MLKEM_OBJ="$INIT_BUILD_DIR/sshd-mlkem-native.o"
"$CLANG" \
  --target="$TARGET_TRIPLE" \
  $USER_ARCH_CFLAGS \
  -std=c99 -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
  -Wall -Wextra -Werror \
  -DMLK_CONFIG_FILE='"mlkem_xaios_config.h"' \
  -I"$ROOT_DIR/userspace/sshd" \
  -I"$ROOT_DIR/third_party/mlkem-native/mlkem" \
  -c "$ROOT_DIR/third_party/mlkem-native/mlkem/mlkem_native.c" \
  -o "$SSHD_MLKEM_OBJ"
printf '"%s"\n' "$SSHD_MLKEM_OBJ" >> "$SSHD_RESPONSE_FILE"
for app_src in nano_editor.c pong_game.c; do
  app_obj="$INIT_BUILD_DIR/sshd-${app_src%.c}.o"
  app_opt=""
  if [ "$app_src" = "pong_game.c" ]; then
    app_opt="-Os"
  fi
  "$CLANG" \
    --target="$TARGET_TRIPLE" \
    $USER_ARCH_CFLAGS \
    -std=c99 \
    -ffreestanding \
    -fno-stack-protector \
    -fno-builtin \
    -fno-pic \
    -fno-pie \
    $app_opt \
    -Wall \
    -Wextra \
    -Werror \
    -I"$ROOT_DIR/userspace/include" \
    -I"$ROOT_DIR/userspace/apps/terminal" \
    -c "$ROOT_DIR/userspace/apps/terminal/$app_src" \
    -o "$app_obj"
  printf '"%s"\n' "$app_obj" >> "$SSHD_RESPONSE_FILE"
done
"$LD_LLD" \
  -nostdlib \
  -T "$ROOT_DIR/userspace/init/linker.ld" \
  -o "$INIT_BUILD_DIR/sshd.elf" \
  "$USER_START_OBJ" \
  "$USER_LIB_OBJ" \
  "$USER_CONTROL_OBJ" \
  @"$SSHD_RESPONSE_FILE"
set -- "$@" "/bin/sshd=$INIT_BUILD_DIR/sshd.elf"

printf '%s\n' "Building userspace /bin/ssh child client ELF..."
SSH_CLIENT_RESPONSE_FILE="$INIT_BUILD_DIR/ssh-client-objects.rsp"
: > "$SSH_CLIENT_RESPONSE_FILE"
for ssh_client_src in ssh.c ssh_client.c ssh_crypto.c ssh_identity.c ssh_mlkem.c tweetnacl_subset.c ssh_protocol.c ssh_connection.c; do
  ssh_client_obj="$INIT_BUILD_DIR/ssh-client-${ssh_client_src%.c}.o"
  ssh_client_path="$ROOT_DIR/userspace/apps/$ssh_client_src"
  if [ "$ssh_client_src" != "ssh.c" ]; then
    ssh_client_path="$ROOT_DIR/userspace/sshd/$ssh_client_src"
  fi
  "$CLANG" \
    --target="$TARGET_TRIPLE" \
    $USER_ARCH_CFLAGS \
    -std=c99 \
    -ffreestanding \
    -fno-stack-protector \
    -fno-builtin \
    -fno-pic \
    -fno-pie \
    -Wall \
    -Wextra \
    -Werror \
    -DXAIOS_SSH_CLIENT_APP=1 \
    -DMLK_CONFIG_FILE='"mlkem_xaios_config.h"' \
    -I"$ROOT_DIR/userspace/include" \
    -I"$ROOT_DIR/userspace/sshd" \
    -I"$ROOT_DIR/third_party/mlkem-native/mlkem" \
    -I"$ROOT_DIR/third_party/openbsd-compat" \
    -I"$ROOT_DIR/userspace/apps/terminal" \
    -c "$ssh_client_path" \
    -o "$ssh_client_obj"
  printf '"%s"\n' "$ssh_client_obj" >> "$SSH_CLIENT_RESPONSE_FILE"
done
printf '"%s"\n' "$SSHD_MLKEM_OBJ" >> "$SSH_CLIENT_RESPONSE_FILE"
for compat_src in blowfish.c bcrypt_pbkdf.c; do
  compat_obj="$INIT_BUILD_DIR/ssh-client-${compat_src%.c}.o"
  "$CLANG" \
    --target="$TARGET_TRIPLE" \
    $USER_ARCH_CFLAGS \
    -std=c99 -ffreestanding -fno-stack-protector -fno-builtin \
    -fno-pic -fno-pie -Wall -Wextra -Werror -Wno-unknown-attributes \
    -I"$ROOT_DIR/userspace/include" \
    -I"$ROOT_DIR/userspace/sshd" \
    -I"$ROOT_DIR/third_party/openbsd-compat" \
    -c "$ROOT_DIR/third_party/openbsd-compat/$compat_src" \
    -o "$compat_obj"
  printf '"%s"\n' "$compat_obj" >> "$SSH_CLIENT_RESPONSE_FILE"
done
"$LD_LLD" \
  -nostdlib \
  -T "$ROOT_DIR/userspace/init/linker.ld" \
  -o "$INIT_BUILD_DIR/ssh.elf" \
  "$USER_START_OBJ" \
  "$USER_LIB_OBJ" \
  @"$SSH_CLIENT_RESPONSE_FILE"
"$LD_LLD" \
  -nostdlib \
  -T "$ROOT_DIR/userspace/init/linker.ld" \
  -o "$INIT_BUILD_DIR/scp.elf" \
  "$USER_START_OBJ" \
  "$USER_LIB_OBJ" \
  @"$SSH_CLIENT_RESPONSE_FILE"
set -- "$@" "/bin/ssh=$INIT_BUILD_DIR/ssh.elf"
set -- "$@" "/bin/scp=$INIT_BUILD_DIR/scp.elf"

if [ "${XAIOS_AUTHORIZED_KEYS_FILE:-}" != "" ]; then
  if [ ! -f "$XAIOS_AUTHORIZED_KEYS_FILE" ]; then
    printf '%s\n' "error: authorized keys file not found: $XAIOS_AUTHORIZED_KEYS_FILE" >&2
    exit 1
  fi
  set -- "$@" "/etc/xaios_authorized_keys=$XAIOS_AUTHORIZED_KEYS_FILE"
fi
if [ "$SSH_USERS_FILE" != "" ]; then
  if [ ! -f "$SSH_USERS_FILE" ]; then
    printf '%s\n' "error: SSH users file not found: $SSH_USERS_FILE" >&2
    exit 1
  fi
  set -- "$@" "/etc/xaios_sshd_users=$SSH_USERS_FILE"
fi
if [ "$CONSOLE_PIN_FILE" != "" ]; then
  if [ ! -f "$CONSOLE_PIN_FILE" ]; then
    printf '%s\n' "error: console PIN file not found: $CONSOLE_PIN_FILE" >&2
    exit 1
  fi
  set -- "$@" "/etc/xaios_console_pin=$CONSOLE_PIN_FILE"
fi
if [ "${XAIOS_SSH_CLIENT_IDENTITY_FILE:-}" != "" ]; then
  if [ ! -f "$XAIOS_SSH_CLIENT_IDENTITY_FILE" ]; then
    printf '%s\n' "error: SSH client identity not found: $XAIOS_SSH_CLIENT_IDENTITY_FILE" >&2
    exit 1
  fi
  set -- "$@" "/etc/xaios_ssh_client_identity=$XAIOS_SSH_CLIENT_IDENTITY_FILE"
fi

rm -f "$IMAGE_PATH"
mkdir -p "$(dirname -- "$IMAGE_PATH")"

printf '%s\n' "Creating FAT boot image: $IMAGE_PATH"
dd if=/dev/zero of="$IMAGE_PATH" bs=1048576 count=64 status=none
"$MFORMAT" -i "$IMAGE_PATH" -F -v XAIOS ::
"$MMD" -i "$IMAGE_PATH" ::/EFI
"$MMD" -i "$IMAGE_PATH" ::/EFI/BOOT
"$MMD" -i "$IMAGE_PATH" ::/EFI/XAIOS
"$MCOPY" -i "$IMAGE_PATH" "$LOADER_EFI" "::/EFI/BOOT/$UEFI_BOOT_NAME"
"$MCOPY" -i "$IMAGE_PATH" "$KERNEL_ELF" ::/EFI/XAIOS/kernel.elf

printf '%s\n' "Created $IMAGE_PATH"

printf '%s\n' "Creating VirtIO block test image: $TEST_BLOCK_IMAGE"
rm -f "$TEST_BLOCK_IMAGE"
dd if=/dev/zero of="$TEST_BLOCK_IMAGE" bs=512 count=8192 status=none
printf 'XAIOS-VIRTIO-BLOCK-TEST\n' | dd of="$TEST_BLOCK_IMAGE" bs=512 count=1 conv=notrunc status=none
"$PYTHON3" "$ROOT_DIR/scripts/create-initfs.py" \
  "$TEST_BLOCK_IMAGE" \
  "$INIT_ELF" \
  "$SERVICE_MANAGER_ELF" \
  "$WORKER_ELF" \
  "$ROOT_DIR/userspace/init/xaios-init.conf" \
  "$ROOT_DIR/userspace/service-manager/source-index.svc" \
  "$@"
printf '%s\n' "Created $TEST_BLOCK_IMAGE"

PERSISTENT_BYTES=16777216
if [ ! -f "$PERSISTENT_IMAGE" ]; then
  printf '%s\n' "Creating persistent disk image: $PERSISTENT_IMAGE"
  dd if=/dev/zero of="$PERSISTENT_IMAGE" bs=512 count=32768 status=none
  printf '%s\n' "Created $PERSISTENT_IMAGE (16 MB, 32768 sectors)"
else
  PERSISTENT_SIZE=$(wc -c < "$PERSISTENT_IMAGE" | tr -d ' ')
  if [ "$PERSISTENT_SIZE" -lt "$PERSISTENT_BYTES" ]; then
    dd if=/dev/zero of="$PERSISTENT_IMAGE" bs=1 count=0 \
      seek="$PERSISTENT_BYTES" conv=notrunc status=none
    printf '%s\n' "Expanded persistent image to 16 MB without replacing data"
  fi
  printf '%s\n' "Persistent image already exists: $PERSISTENT_IMAGE"
fi

if [ "$TARGET_ARCH" = x86_64 ] && [ ! -f "$STORAGE_ADMIN_IMAGE" ]; then
  printf '%s\n' "Creating x86 storage administration scratch image: $STORAGE_ADMIN_IMAGE"
  dd if=/dev/zero of="$STORAGE_ADMIN_IMAGE" bs=512 count=16384 status=none
  printf '%s\n' "Created $STORAGE_ADMIN_IMAGE (8 MB, 16384 sectors)"
fi

if [ "$XAI_FS_IMAGE_CONFIGURED" = "" ]; then
  printf '%s\n' "Creating signed xaiFS fixture: $XAI_FS_IMAGE"
  PYTHONPATH="$ROOT_DIR/tools" "$PYTHON3" \
    "$ROOT_DIR/tests/xai_fs/create_c_fixture.py" "$XAI_FS_IMAGE"
  printf '%s\n' "Created $XAI_FS_IMAGE"
elif [ ! -f "$XAI_FS_IMAGE" ]; then
  printf '%s\n' "error: configured xaiFS image not found: $XAI_FS_IMAGE" >&2
  exit 1
else
  printf '%s\n' "Using configured xaiFS image: $XAI_FS_IMAGE"
fi

if [ "$SYSTEM_VOLUME_IMAGE_CONFIGURED" = "" ]; then
  printf '%s\n' "Creating signed A/B system volume: $SYSTEM_VOLUME_IMAGE"
  PYTHONPATH="$ROOT_DIR" "$PYTHON3" \
    "$ROOT_DIR/tools/xaios_system_volume.py" create \
    "$SYSTEM_VOLUME_IMAGE" "$KERNEL_ELF"
  PYTHONPATH="$ROOT_DIR" "$PYTHON3" \
    "$ROOT_DIR/tools/xaios_system_volume.py" verify "$SYSTEM_VOLUME_IMAGE"
  printf '%s\n' "Created $SYSTEM_VOLUME_IMAGE"
elif [ ! -f "$SYSTEM_VOLUME_IMAGE" ]; then
  printf '%s\n' "error: configured system volume not found: $SYSTEM_VOLUME_IMAGE" >&2
  exit 1
else
  PYTHONPATH="$ROOT_DIR" "$PYTHON3" \
    "$ROOT_DIR/tools/xaios_system_volume.py" verify "$SYSTEM_VOLUME_IMAGE"
  printf '%s\n' "Using configured system volume: $SYSTEM_VOLUME_IMAGE"
fi
