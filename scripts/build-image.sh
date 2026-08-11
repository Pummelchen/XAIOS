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

MODEL_VOLUME_IMAGE_CONFIGURED="${XAIOS_MODEL_VOLUME_IMAGE:-}"
if [ "$TARGET_ARCH" = x86_64 ]; then
  MODEL_VOLUME_IMAGE="${MODEL_VOLUME_IMAGE_CONFIGURED:-$BUILD_DIR/xaios-x86-model-volume.img}"
else
  MODEL_VOLUME_IMAGE="${MODEL_VOLUME_IMAGE_CONFIGURED:-$BUILD_DIR/xaios-model-volume.img}"
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
USER_APPS="xaios-shell xaiosctl xapt hello sysinfo systest smptest nettest lstm-xor sshtest mltest posix-shell agenttest"
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
  1) USER_APPS="$USER_APPS app-fail" ;;
  *)
    printf '%s\n' "error: XAIOS_FAILURE_TEST_APP must be 0 or 1" >&2
    exit 2
    ;;
esac
PASSWORD_AUTH_CFLAG="-DXAIOS_PASSWORD_AUTH_AVAILABLE=0"
if [ "${XAIOS_SSH_USERS_FILE:-}" != "" ]; then
  if [ "${XAIOS_SSH_PASSWORD_AUTH:-}" != "1" ]; then
    printf '%s\n' "error: password credentials require XAIOS_SSH_PASSWORD_AUTH=1" >&2
    exit 2
  fi
  if [ "$BUILD_MODE" = "release" ]; then
    printf '%s\n' "error: password authentication is forbidden in release builds" >&2
    exit 2
  fi
  PASSWORD_AUTH_CFLAG="-DXAIOS_PASSWORD_AUTH_AVAILABLE=1"
elif [ "${XAIOS_SSH_PASSWORD_AUTH:-0}" != "0" ]; then
  printf '%s\n' "error: XAIOS_SSH_PASSWORD_AUTH requires XAIOS_SSH_USERS_FILE" >&2
  exit 2
fi

# Cleanup only failures that occur after the build profile has been accepted.
cleanup() {
  if [ $? -ne 0 ]; then
    printf '%s\n' "Build failed, cleaning up partial artifacts..." >&2
    rm -rf "$BUILD_DIR"
    printf '%s\n' "Cleaned up $BUILD_DIR" >&2
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
if [ "$TARGET_ARCH" = x86_64 ]; then
  KERNEL_CFLAGS="$KERNEL_CFLAGS -mno-red-zone -DXAIOS_X86_COMMON_RUNTIME=1"
fi

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
BUILD_IDENTIFIER="xaios-admin-control"
if [ -n "${XAIOS_BUILD_REVISION_OVERRIDE:-}" ] ||
   ! git -C "$ROOT_DIR" diff-index --quiet HEAD -- 2>/dev/null ||
   [ -n "$(git -C "$ROOT_DIR" ls-files --others --exclude-standard 2>/dev/null)" ]; then
  BUILD_IDENTIFIER="${BUILD_IDENTIFIER}-dirty"
fi
KERNEL_CFLAGS="$KERNEL_CFLAGS $PASSWORD_AUTH_CFLAG -DXAIOS_BOOT_TEST_APPS=$BOOT_TEST_APPS -DXAIOS_BOOT_VERBOSE=$BOOT_VERBOSE -DXAIOS_FAILURE_TEST_APP=$FAILURE_TEST_APP -DXAIOS_LIBC_TEST=$LIBC_TEST"

compile_kernel() {
  source_path="$1"
  object_path="$2"
  "$CLANG" $KERNEL_CFLAGS \
    "-DXAIOS_BUILD_IDENTIFIER=\"$BUILD_IDENTIFIER\"" \
    "-DXAIOS_BUILD_REVISION=\"$BUILD_REVISION\"" \
    "-DXAIOS_BUILD_MODE=\"$BUILD_MODE\"" \
    -I"$ROOT_DIR/kernel/include" \
    -I"$ROOT_DIR/engine/include" \
    -I"$ROOT_DIR/engine/src" \
    -I"$ROOT_DIR/userspace/include" \
    -I"$ROOT_DIR/userspace/sshd" \
    -c "$source_path" -o "$object_path"
}

if [ "$TARGET_ARCH" = aarch64 ]; then
  ARCH_KERNEL_OBJECTS="
  $KERNEL_BUILD_DIR/entry.o
  $KERNEL_BUILD_DIR/secondary.o
  $KERNEL_BUILD_DIR/vectors.o
  $KERNEL_BUILD_DIR/context.o
  $KERNEL_BUILD_DIR/exception.o
  $KERNEL_BUILD_DIR/timer.o
  $KERNEL_BUILD_DIR/rtc.o
  $KERNEL_BUILD_DIR/power.o
  $KERNEL_BUILD_DIR/watchdog.o
  $KERNEL_BUILD_DIR/smmu.o
  $KERNEL_BUILD_DIR/pci.o
  $KERNEL_BUILD_DIR/gic.o
  $KERNEL_BUILD_DIR/smp.o
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
  $KERNEL_BUILD_DIR/klog_ring.o
  $KERNEL_BUILD_DIR/telemetry.o
  $KERNEL_BUILD_DIR/panic.o
  $KERNEL_BUILD_DIR/assert.o
  $KERNEL_BUILD_DIR/stack_canary.o
  $KERNEL_BUILD_DIR/nvme.o
  $KERNEL_BUILD_DIR/virtio_transport.o
  $KERNEL_BUILD_DIR/block_device.o
  $KERNEL_BUILD_DIR/virtio_blk.o
  $KERNEL_BUILD_DIR/virtio_net.o
  $KERNEL_BUILD_DIR/virtio_rng.o
  $KERNEL_BUILD_DIR/initramfs.o
  $KERNEL_BUILD_DIR/mutable_fs.o
  $KERNEL_BUILD_DIR/vfs.o
  $KERNEL_BUILD_DIR/vfs_mutable.o
  $KERNEL_BUILD_DIR/vfs_model.o
  $KERNEL_BUILD_DIR/model_volume_admin.o
  $KERNEL_BUILD_DIR/service.o
  $KERNEL_BUILD_DIR/syscall.o
  $KERNEL_BUILD_DIR/core_lease.o
  $KERNEL_BUILD_DIR/security.o
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
  $KERNEL_BUILD_DIR/rate_limit.o
  $KERNEL_BUILD_DIR/source_index.o
  $KERNEL_BUILD_DIR/network_stack.o
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
  $KERNEL_BUILD_DIR/socket_buffer.o
  $KERNEL_BUILD_DIR/routing.o
  $KERNEL_BUILD_DIR/dns.o
  $KERNEL_BUILD_DIR/ntp.o
  $KERNEL_BUILD_DIR/elf_loader.o
  $KERNEL_BUILD_DIR/string.o
  $KERNEL_BUILD_DIR/bpe_tokenizer.o
  $KERNEL_BUILD_DIR/engine_model_volume.o
  $KERNEL_BUILD_DIR/engine_model_volume_writer.o
  $KERNEL_BUILD_DIR/engine_sha256.o
  $KERNEL_BUILD_DIR/kernel_ssh_crypto.o
  $KERNEL_BUILD_DIR/kernel_tweetnacl_subset.o
"

if [ "$TARGET_ARCH" = aarch64 ]; then
  compile_kernel "$ROOT_DIR/kernel/arch/aarch64/entry.S" "$KERNEL_BUILD_DIR/entry.o"
  compile_kernel "$ROOT_DIR/kernel/arch/aarch64/secondary.S" "$KERNEL_BUILD_DIR/secondary.o"
  compile_kernel "$ROOT_DIR/kernel/arch/aarch64/vectors.S" "$KERNEL_BUILD_DIR/vectors.o"
else
  compile_kernel "$ROOT_DIR/kernel/arch/x86_64/entry.S" "$KERNEL_BUILD_DIR/entry.o"
  compile_kernel "$ROOT_DIR/kernel/arch/x86_64/acpi.c" "$KERNEL_BUILD_DIR/acpi.o"
fi
compile_kernel "$ROOT_DIR/kernel/core/kmain.c" "$KERNEL_BUILD_DIR/kmain.o"
compile_kernel "$ROOT_DIR/kernel/core/boot_ui.c" "$KERNEL_BUILD_DIR/boot_ui.o"
compile_kernel "$ROOT_DIR/kernel/core/klog.c" "$KERNEL_BUILD_DIR/klog.o"
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
  compile_kernel "$ROOT_DIR/kernel/arch/aarch64/smp.c" "$KERNEL_BUILD_DIR/smp.o"
else
  compile_kernel "$ROOT_DIR/kernel/arch/x86_64/early.c" "$KERNEL_BUILD_DIR/early.o"
  compile_kernel "$ROOT_DIR/engine/src/packed.c" "$KERNEL_BUILD_DIR/engine_packed.o"
  compile_kernel "$ROOT_DIR/kernel/arch/x86_64/timer.c" "$KERNEL_BUILD_DIR/timer.o"
  compile_kernel "$ROOT_DIR/kernel/arch/x86_64/platform.c" "$KERNEL_BUILD_DIR/platform.o"
  compile_kernel "$ROOT_DIR/kernel/arch/x86_64/power.c" "$KERNEL_BUILD_DIR/power.o"
  compile_kernel "$ROOT_DIR/kernel/arch/x86_64/watchdog.c" "$KERNEL_BUILD_DIR/watchdog.o"
  compile_kernel "$ROOT_DIR/kernel/arch/x86_64/pci.c" "$KERNEL_BUILD_DIR/pci.o"
  compile_kernel "$ROOT_DIR/kernel/arch/x86_64/smp.c" "$KERNEL_BUILD_DIR/smp.o"
fi
compile_kernel "$ROOT_DIR/kernel/arch/aarch64/topology.c" "$KERNEL_BUILD_DIR/topology.o"
compile_kernel "$ROOT_DIR/kernel/dev/nvme.c" "$KERNEL_BUILD_DIR/nvme.o"
if [ "$TARGET_ARCH" = aarch64 ]; then
  compile_kernel "$ROOT_DIR/kernel/dev/virtio/virtio_transport.c" "$KERNEL_BUILD_DIR/virtio_transport.o"
else
  compile_kernel "$ROOT_DIR/kernel/dev/virtio/virtio_transport_pci.c" "$KERNEL_BUILD_DIR/virtio_transport.o"
fi
compile_kernel "$ROOT_DIR/kernel/dev/block_device.c" "$KERNEL_BUILD_DIR/block_device.o"
compile_kernel "$ROOT_DIR/kernel/dev/virtio/virtio_blk.c" "$KERNEL_BUILD_DIR/virtio_blk.o"
compile_kernel "$ROOT_DIR/kernel/dev/virtio/virtio_net.c" "$KERNEL_BUILD_DIR/virtio_net.o"
compile_kernel "$ROOT_DIR/kernel/dev/virtio/virtio_rng.c" "$KERNEL_BUILD_DIR/virtio_rng.o"
compile_kernel "$ROOT_DIR/kernel/fs/initramfs.c" "$KERNEL_BUILD_DIR/initramfs.o"
compile_kernel "$ROOT_DIR/kernel/fs/mutable_fs.c" "$KERNEL_BUILD_DIR/mutable_fs.o"
compile_kernel "$ROOT_DIR/kernel/fs/vfs.c" "$KERNEL_BUILD_DIR/vfs.o"
compile_kernel "$ROOT_DIR/kernel/fs/vfs_mutable.c" "$KERNEL_BUILD_DIR/vfs_mutable.o"
compile_kernel "$ROOT_DIR/kernel/fs/vfs_model.c" "$KERNEL_BUILD_DIR/vfs_model.o"
compile_kernel "$ROOT_DIR/kernel/fs/model_volume_admin.c" "$KERNEL_BUILD_DIR/model_volume_admin.o"
compile_kernel "$ROOT_DIR/kernel/user/service.c" "$KERNEL_BUILD_DIR/service.o"
compile_kernel "$ROOT_DIR/kernel/user/syscall.c" "$KERNEL_BUILD_DIR/syscall.o"
compile_kernel "$ROOT_DIR/kernel/runtime/core_lease.c" "$KERNEL_BUILD_DIR/core_lease.o"
compile_kernel "$ROOT_DIR/kernel/runtime/security.c" "$KERNEL_BUILD_DIR/security.o"
compile_kernel "$ROOT_DIR/kernel/runtime/remote_login.c" "$KERNEL_BUILD_DIR/remote_login.o"
compile_kernel "$ROOT_DIR/kernel/runtime/operations.c" "$KERNEL_BUILD_DIR/operations.o"
compile_kernel "$ROOT_DIR/kernel/runtime/admin_control.c" "$KERNEL_BUILD_DIR/admin_control.o"
compile_kernel "$ROOT_DIR/kernel/runtime/control_protocol.c" "$KERNEL_BUILD_DIR/control_protocol.o"
compile_kernel "$ROOT_DIR/kernel/runtime/app_store.c" "$KERNEL_BUILD_DIR/app_store.o"
compile_kernel "$ROOT_DIR/kernel/user/user.c" "$KERNEL_BUILD_DIR/user.o"
compile_kernel "$ROOT_DIR/kernel/runtime/model_arena.c" "$KERNEL_BUILD_DIR/model_arena.o"
compile_kernel "$ROOT_DIR/kernel/runtime/ai_cell.c" "$KERNEL_BUILD_DIR/ai_cell.o"
compile_kernel "$ROOT_DIR/kernel/runtime/cpu_ai_runtime.c" "$KERNEL_BUILD_DIR/cpu_ai_runtime.o"
compile_kernel "$ROOT_DIR/kernel/runtime/ai_kernels.c" "$KERNEL_BUILD_DIR/ai_kernels.o"
compile_kernel "$ROOT_DIR/kernel/runtime/paged_kv_cache.c" "$KERNEL_BUILD_DIR/paged_kv_cache.o"
compile_kernel "$ROOT_DIR/kernel/runtime/inference_batcher.c" "$KERNEL_BUILD_DIR/inference_batcher.o"
compile_kernel "$ROOT_DIR/kernel/runtime/inference_preempt.c" "$KERNEL_BUILD_DIR/inference_preempt.o"
compile_kernel "$ROOT_DIR/kernel/runtime/model_parallel.c" "$KERNEL_BUILD_DIR/model_parallel.o"
compile_kernel "$ROOT_DIR/kernel/runtime/speculative_decoding.c" "$KERNEL_BUILD_DIR/speculative_decoding.o"
compile_kernel "$ROOT_DIR/kernel/runtime/flash_attention.c" "$KERNEL_BUILD_DIR/flash_attention.o"
compile_kernel "$ROOT_DIR/kernel/runtime/model_compilation.c" "$KERNEL_BUILD_DIR/model_compilation.o"
compile_kernel "$ROOT_DIR/kernel/runtime/math_intrinsics.c" "$KERNEL_BUILD_DIR/math_intrinsics.o"
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
compile_kernel "$ROOT_DIR/kernel/runtime/rate_limit.c" "$KERNEL_BUILD_DIR/rate_limit.o"
compile_kernel "$ROOT_DIR/kernel/runtime/source_index.c" "$KERNEL_BUILD_DIR/source_index.o"
compile_kernel "$ROOT_DIR/kernel/runtime/network_stack.c" "$KERNEL_BUILD_DIR/network_stack.o"
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
compile_kernel "$ROOT_DIR/kernel/net/socket_buffer.c" "$KERNEL_BUILD_DIR/socket_buffer.o"
compile_kernel "$ROOT_DIR/kernel/net/routing.c" "$KERNEL_BUILD_DIR/routing.o"
compile_kernel "$ROOT_DIR/kernel/net/dns.c" "$KERNEL_BUILD_DIR/dns.o"
compile_kernel "$ROOT_DIR/kernel/net/ntp.c" "$KERNEL_BUILD_DIR/ntp.o"
compile_kernel "$ROOT_DIR/kernel/mm/elf_loader.c" "$KERNEL_BUILD_DIR/elf_loader.o"
compile_kernel "$ROOT_DIR/kernel/lib/string.c" "$KERNEL_BUILD_DIR/string.o"
compile_kernel "$ROOT_DIR/kernel/runtime/bpe_tokenizer.c" "$KERNEL_BUILD_DIR/bpe_tokenizer.o"
compile_kernel "$ROOT_DIR/engine/src/model_volume.c" "$KERNEL_BUILD_DIR/engine_model_volume.o"
compile_kernel "$ROOT_DIR/engine/src/model_volume_writer.c" "$KERNEL_BUILD_DIR/engine_model_volume_writer.o"
compile_kernel "$ROOT_DIR/engine/src/sha256.c" "$KERNEL_BUILD_DIR/engine_sha256.o"
compile_kernel "$ROOT_DIR/userspace/sshd/ssh_crypto.c" "$KERNEL_BUILD_DIR/kernel_ssh_crypto.o"
compile_kernel "$ROOT_DIR/userspace/sshd/tweetnacl_subset.c" "$KERNEL_BUILD_DIR/kernel_tweetnacl_subset.o"

KERNEL_RESPONSE_FILE="$KERNEL_BUILD_DIR/objects.rsp"
printf '%s\n' "$KERNEL_OBJECTS" | while IFS= read -r object_path; do
  if [ "$object_path" != "" ]; then
    printf '"%s"\n' "${object_path#  }"
  fi
done > "$KERNEL_RESPONSE_FILE"

"$LD_LLD" \
  -nostdlib \
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
    -I"$ROOT_DIR/userspace/include" \
    -c "$ROOT_DIR/userspace/apps/$app.c" \
    -o "$app_obj"

  if [ "$app" = "xaiosctl" ] || [ "$app" = "xapt" ]; then
    "$LD_LLD" \
      -nostdlib \
      -T "$ROOT_DIR/userspace/init/linker.ld" \
      -o "$app_elf" \
      "$USER_START_OBJ" \
      "$USER_LIB_OBJ" \
      "$USER_CONTROL_OBJ" \
      "$app_obj"
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

LIBC_SYSROOT="$BUILD_DIR/libc/$TARGET_ARCH/sysroot"
LIBC_RUNTIME="$BUILD_DIR/libc/$TARGET_ARCH/runtime-test"
LIBC_READY=1
for libc_artifact in \
    "$LIBC_SYSROOT/lib/libc.a" \
    "$LIBC_SYSROOT/lib/libm.a" \
    "$LIBC_SYSROOT/lib/libcompiler_rt_xaios.a" \
    "$LIBC_RUNTIME/crt0.o" \
    "$LIBC_RUNTIME/runtime_main_void.o" \
    "$LIBC_RUNTIME/os_adapter.o"; do
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
  for libc_probe in "$LIBC_MAIN_VOID_ELF" "$LIBC_EXIT_PROBE_ELF" \
      "$LIBC_ABORT_PROBE_ELF"; do
    if [ ! -f "$libc_probe" ]; then
      printf 'error: missing libc probe: %s\n' "$libc_probe" >&2
      exit 1
    fi
  done
  set -- "$@" "/bin/c99-runtime-smoke=$LIBC_TEST_ELF" \
    "/bin/c99-main-void=$LIBC_MAIN_VOID_ELF" \
    "/bin/c99-exit-probe=$LIBC_EXIT_PROBE_ELF" \
    "/bin/c99-abort-probe=$LIBC_ABORT_PROBE_ELF"
fi

printf '%s\n' "Building userspace /bin/sshd ELF..."
SSHD_RESPONSE_FILE="$INIT_BUILD_DIR/sshd-objects.rsp"
: > "$SSHD_RESPONSE_FILE"
for sshd_src in sshd.c ssh_crypto.c tweetnacl_subset.c ssh_protocol.c ssh_channel.c ssh_client.c ssh_host_key.c ssh_connection.c sftp_server.c nano_editor.c less_pager.c pong_game.c; do
  sshd_obj="$INIT_BUILD_DIR/sshd-${sshd_src%.c}.o"
  sshd_opt=""
  if [ "$sshd_src" = "sshd.c" ] || [ "$sshd_src" = "pong_game.c" ]; then
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
    -I"$ROOT_DIR/userspace/include" \
    -I"$ROOT_DIR/userspace/sshd" \
    -c "$ROOT_DIR/userspace/sshd/$sshd_src" \
    -o "$sshd_obj"
  printf '"%s"\n' "$sshd_obj" >> "$SSHD_RESPONSE_FILE"
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
if [ "${XAIOS_AUTHORIZED_KEYS_FILE:-}" != "" ]; then
  if [ ! -f "$XAIOS_AUTHORIZED_KEYS_FILE" ]; then
    printf '%s\n' "error: authorized keys file not found: $XAIOS_AUTHORIZED_KEYS_FILE" >&2
    exit 1
  fi
  set -- "$@" "/etc/xaios_authorized_keys=$XAIOS_AUTHORIZED_KEYS_FILE"
fi
if [ "${XAIOS_SSH_USERS_FILE:-}" != "" ]; then
  if [ ! -f "$XAIOS_SSH_USERS_FILE" ]; then
    printf '%s\n' "error: SSH users file not found: $XAIOS_SSH_USERS_FILE" >&2
    exit 1
  fi
  set -- "$@" "/etc/xaios_sshd_users=$XAIOS_SSH_USERS_FILE"
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

if [ ! -f "$PERSISTENT_IMAGE" ]; then
  printf '%s\n' "Creating persistent disk image: $PERSISTENT_IMAGE"
  dd if=/dev/zero of="$PERSISTENT_IMAGE" bs=512 count=8192 status=none
  printf '%s\n' "Created $PERSISTENT_IMAGE (4 MB, 8192 sectors)"
else
  printf '%s\n' "Persistent image already exists: $PERSISTENT_IMAGE"
fi

if [ "$TARGET_ARCH" = x86_64 ] && [ ! -f "$STORAGE_ADMIN_IMAGE" ]; then
  printf '%s\n' "Creating x86 storage administration scratch image: $STORAGE_ADMIN_IMAGE"
  dd if=/dev/zero of="$STORAGE_ADMIN_IMAGE" bs=512 count=16384 status=none
  printf '%s\n' "Created $STORAGE_ADMIN_IMAGE (8 MB, 16384 sectors)"
fi

if [ "$MODEL_VOLUME_IMAGE_CONFIGURED" = "" ]; then
  printf '%s\n' "Creating signed ModelFS fixture: $MODEL_VOLUME_IMAGE"
  PYTHONPATH="$ROOT_DIR/tools" "$PYTHON3" \
    "$ROOT_DIR/tests/model_volume/create_c_fixture.py" "$MODEL_VOLUME_IMAGE"
  printf '%s\n' "Created $MODEL_VOLUME_IMAGE"
elif [ ! -f "$MODEL_VOLUME_IMAGE" ]; then
  printf '%s\n' "error: configured ModelFS image not found: $MODEL_VOLUME_IMAGE" >&2
  exit 1
else
  printf '%s\n' "Using configured ModelFS image: $MODEL_VOLUME_IMAGE"
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
