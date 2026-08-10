#!/bin/sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build"
EFI_BUILD_DIR="$BUILD_DIR/uefi-x86_64"
KERNEL_BUILD_DIR="$BUILD_DIR/kernel-x86_64"
IMAGE_PATH="${XAIOS_X86_64_IMAGE:-$BUILD_DIR/xaios-x86_64.img}"
BOOT_TEST_APPS="${XAIOS_BOOT_TEST_APPS:-0}"
LOADER_OBJ="$EFI_BUILD_DIR/loader_main.obj"
LOADER_SYSTEM_OBJ="$EFI_BUILD_DIR/system_volume_loader.obj"
LOADER_SHA256_OBJ="$EFI_BUILD_DIR/sha256.obj"
LOADER_SSH_CRYPTO_OBJ="$EFI_BUILD_DIR/ssh_crypto.obj"
LOADER_TWEETNACL_OBJ="$EFI_BUILD_DIR/tweetnacl_subset.obj"
LOADER_EFI="$EFI_BUILD_DIR/BOOTX64.EFI"
KERNEL_ENTRY_OBJ="$KERNEL_BUILD_DIR/entry.o"
KERNEL_EARLY_OBJ="$KERNEL_BUILD_DIR/early.o"
KERNEL_ACPI_OBJ="$KERNEL_BUILD_DIR/acpi.o"
KERNEL_PACKED_OBJ="$KERNEL_BUILD_DIR/packed.o"
KERNEL_STRING_OBJ="$KERNEL_BUILD_DIR/string.o"
KERNEL_CRC32_OBJ="$KERNEL_BUILD_DIR/crc32.o"
KERNEL_BLOCK_OBJ="$KERNEL_BUILD_DIR/block_device.o"
KERNEL_VFS_OBJ="$KERNEL_BUILD_DIR/vfs.o"
KERNEL_COMMON_OBJ="$KERNEL_BUILD_DIR/common_runtime.o"
KERNEL_ARCHITECTURE_OBJ="$KERNEL_BUILD_DIR/architecture.o"
KERNEL_BACKEND_SCALAR_OBJ="$KERNEL_BUILD_DIR/backend_scalar.o"
KERNEL_BACKEND_NEON_OBJ="$KERNEL_BUILD_DIR/backend_neon.o"
KERNEL_BACKEND_AVX2_OBJ="$KERNEL_BUILD_DIR/backend_avx2.o"
KERNEL_KLOG_OBJ="$KERNEL_BUILD_DIR/klog.o"
KERNEL_SECURITY_OBJ="$KERNEL_BUILD_DIR/security.o"
KERNEL_AI_KERNELS_OBJ="$KERNEL_BUILD_DIR/ai_kernels.o"
KERNEL_MATH_INTRINSICS_OBJ="$KERNEL_BUILD_DIR/math_intrinsics.o"
KERNEL_CRYPTO_OBJ="$KERNEL_BUILD_DIR/kernel_ssh_crypto.o"
KERNEL_TWEETNACL_OBJ="$KERNEL_BUILD_DIR/kernel_tweetnacl_subset.o"
KERNEL_ELF="$KERNEL_BUILD_DIR/kernel.elf"
USER_BUILD_DIR="$BUILD_DIR/userspace-x86_64"
USER_START_OBJ="$USER_BUILD_DIR/start.o"
USER_LIB_OBJ="$USER_BUILD_DIR/xaios_user.o"
USER_HELLO_OBJ="$USER_BUILD_DIR/hello.o"
USER_HELLO_ELF="$USER_BUILD_DIR/hello.elf"
USER_HELLO_BIN="$USER_BUILD_DIR/hello.bin"
USER_HELLO_BLOB_OBJ="$USER_BUILD_DIR/hello_blob.o"

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
OBJCOPY="$(require_tool "objcopy" llvm-objcopy "Install LLVM or GNU binutils" \
  "$LLVM_BIN/llvm-objcopy" /usr/bin/llvm-objcopy /usr/bin/objcopy)"
MFORMAT="$(require_tool "mtools mformat" mformat "Install with: brew install mtools" /opt/homebrew/bin/mformat /usr/local/bin/mformat)"
MMD="$(require_tool "mtools mmd" mmd "Install with: brew install mtools" /opt/homebrew/bin/mmd /usr/local/bin/mmd)"
MCOPY="$(require_tool "mtools mcopy" mcopy "Install with: brew install mtools" /opt/homebrew/bin/mcopy /usr/local/bin/mcopy)"

mkdir -p "$EFI_BUILD_DIR" "$KERNEL_BUILD_DIR" "$USER_BUILD_DIR"

printf '%s\n' "Building x86_64 userspace /bin/hello ELF..."
USER_CFLAGS="
  --target=x86_64-none-elf
  -std=c99
  -ffreestanding
  -fno-stack-protector
  -fno-builtin
  -fno-pic
  -fno-pie
  -mno-red-zone
  -ffunction-sections
  -fdata-sections
  -Wall
  -Wextra
  -Werror
"
"$CLANG" $USER_CFLAGS -I"$ROOT_DIR/userspace/include" \
  -c "$ROOT_DIR/userspace/lib/start.S" -o "$USER_START_OBJ"
"$CLANG" $USER_CFLAGS -I"$ROOT_DIR/userspace/include" \
  -c "$ROOT_DIR/userspace/lib/xaios_user.c" -o "$USER_LIB_OBJ"
"$CLANG" $USER_CFLAGS -I"$ROOT_DIR/userspace/include" \
  -c "$ROOT_DIR/userspace/apps/hello.c" -o "$USER_HELLO_OBJ"
"$LD_LLD" -nostdlib --gc-sections -T "$ROOT_DIR/userspace/init/linker.ld" \
  -o "$USER_HELLO_ELF" "$USER_START_OBJ" "$USER_LIB_OBJ" "$USER_HELLO_OBJ"
"$OBJCOPY" -O binary "$USER_HELLO_ELF" "$USER_HELLO_BIN"
(
  cd "$USER_BUILD_DIR"
  "$OBJCOPY" -I binary -O elf64-x86-64 -B i386:x86-64 \
    hello.bin hello_blob.o
)

printf '%s\n' "Building x86_64 UEFI loader..."
"$CLANG" \
  --target=x86_64-unknown-windows \
  -DXAIOS_UEFI_TARGET_X86_64=1 \
  -DXAIOS_BOOT_TEST_APPS="$BOOT_TEST_APPS" \
  -ffreestanding \
  -fno-stack-protector \
  -fno-builtin \
  -fshort-wchar \
  -ffunction-sections \
  -fdata-sections \
  -Wall \
  -Wextra \
  -Werror \
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
    --target=x86_64-unknown-windows \
    -DXAIOS_UEFI_TARGET_X86_64=1 \
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
  /machine:x64 \
  "$LOADER_OBJ" \
  "$LOADER_SYSTEM_OBJ" \
  "$LOADER_SHA256_OBJ" \
  "$LOADER_SSH_CRYPTO_OBJ" \
  "$LOADER_TWEETNACL_OBJ" \
  /opt:ref \
  /out:"$LOADER_EFI"

printf '%s\n' "Building x86_64 kernel ELF..."
KERNEL_CFLAGS="
  --target=x86_64-none-elf
  -std=c99
  -ffreestanding
  -fno-stack-protector
  -fno-builtin
  -fno-pic
  -fno-pie
  -mno-red-zone
  -ffunction-sections
  -fdata-sections
  -Wall
  -Wextra
  -Werror
"

"$CLANG" $KERNEL_CFLAGS -I"$ROOT_DIR/kernel/include" \
  -c "$ROOT_DIR/kernel/arch/x86_64/entry.S" -o "$KERNEL_ENTRY_OBJ"
"$CLANG" $KERNEL_CFLAGS -I"$ROOT_DIR/kernel/include" \
  -I"$ROOT_DIR/engine/include" \
  -c "$ROOT_DIR/kernel/arch/x86_64/early.c" -o "$KERNEL_EARLY_OBJ"
"$CLANG" $KERNEL_CFLAGS -I"$ROOT_DIR/kernel/include" \
  -c "$ROOT_DIR/kernel/arch/x86_64/acpi.c" -o "$KERNEL_ACPI_OBJ"
"$CLANG" $KERNEL_CFLAGS -I"$ROOT_DIR/engine/include" \
  -c "$ROOT_DIR/engine/src/packed.c" -o "$KERNEL_PACKED_OBJ"
for common_source in \
  "kernel/lib/string.c:$KERNEL_STRING_OBJ" \
  "kernel/lib/crc32.c:$KERNEL_CRC32_OBJ" \
  "kernel/dev/block_device.c:$KERNEL_BLOCK_OBJ" \
  "kernel/fs/vfs.c:$KERNEL_VFS_OBJ" \
  "kernel/core/common_runtime.c:$KERNEL_COMMON_OBJ" \
  "engine/src/architecture.c:$KERNEL_ARCHITECTURE_OBJ" \
  "engine/src/backend_scalar.c:$KERNEL_BACKEND_SCALAR_OBJ" \
  "engine/src/backend_neon.c:$KERNEL_BACKEND_NEON_OBJ" \
  "engine/src/backend_avx2.c:$KERNEL_BACKEND_AVX2_OBJ" \
  "kernel/core/klog.c:$KERNEL_KLOG_OBJ" \
  "kernel/runtime/security.c:$KERNEL_SECURITY_OBJ" \
  "kernel/runtime/ai_kernels.c:$KERNEL_AI_KERNELS_OBJ" \
  "kernel/runtime/math_intrinsics.c:$KERNEL_MATH_INTRINSICS_OBJ" \
  "userspace/sshd/ssh_crypto.c:$KERNEL_CRYPTO_OBJ" \
  "userspace/sshd/tweetnacl_subset.c:$KERNEL_TWEETNACL_OBJ"
do
  source_path=${common_source%%:*}
  object_path=${common_source#*:}
  "$CLANG" $KERNEL_CFLAGS -I"$ROOT_DIR/kernel/include" \
    -I"$ROOT_DIR/engine/include" -I"$ROOT_DIR/engine/src" \
    -I"$ROOT_DIR/userspace/include" -I"$ROOT_DIR/userspace/sshd" \
    -c "$ROOT_DIR/$source_path" -o "$object_path"
done

"$LD_LLD" \
  -nostdlib \
  --gc-sections \
  -T "$ROOT_DIR/kernel/arch/x86_64/linker.ld" \
  -o "$KERNEL_ELF" \
  "$KERNEL_ENTRY_OBJ" \
  "$KERNEL_EARLY_OBJ" \
  "$KERNEL_ACPI_OBJ" \
  "$KERNEL_PACKED_OBJ" \
  "$KERNEL_STRING_OBJ" \
  "$KERNEL_CRC32_OBJ" \
  "$KERNEL_BLOCK_OBJ" \
  "$KERNEL_VFS_OBJ" \
  "$KERNEL_COMMON_OBJ" \
  "$KERNEL_ARCHITECTURE_OBJ" \
  "$KERNEL_BACKEND_SCALAR_OBJ" \
  "$KERNEL_BACKEND_NEON_OBJ" \
  "$KERNEL_BACKEND_AVX2_OBJ" \
  "$KERNEL_KLOG_OBJ" \
  "$KERNEL_SECURITY_OBJ" \
  "$KERNEL_AI_KERNELS_OBJ" \
  "$KERNEL_MATH_INTRINSICS_OBJ" \
  "$KERNEL_CRYPTO_OBJ" \
  "$KERNEL_TWEETNACL_OBJ" \
  "$USER_HELLO_BLOB_OBJ"

rm -f "$IMAGE_PATH"
mkdir -p "$(dirname -- "$IMAGE_PATH")"

printf '%s\n' "Creating x86_64 FAT boot image: $IMAGE_PATH"
dd if=/dev/zero of="$IMAGE_PATH" bs=1048576 count=64 status=none
"$MFORMAT" -i "$IMAGE_PATH" -F -v XAIOSX64 ::
"$MMD" -i "$IMAGE_PATH" ::/EFI
"$MMD" -i "$IMAGE_PATH" ::/EFI/BOOT
"$MMD" -i "$IMAGE_PATH" ::/EFI/XAIOS
"$MCOPY" -i "$IMAGE_PATH" "$LOADER_EFI" ::/EFI/BOOT/BOOTX64.EFI
"$MCOPY" -i "$IMAGE_PATH" "$KERNEL_ELF" ::/EFI/XAIOS/kernel.elf

printf '%s\n' "Created $IMAGE_PATH"
