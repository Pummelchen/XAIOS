# Sourced by scripts/build-image.sh; not a standalone script.
#
# The UEFI loader: boot/uefi/loader_main.c and the six objects linked into
# $LOADER_EFI. Runs in the caller's shell, so `set -eu`, the build
# variables and the positional parameters are the parent's.

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
  "boot/uefi/loader_platform.c:$LOADER_PLATFORM_OBJ" \
  "boot/uefi/loader_image.c:$LOADER_IMAGE_OBJ" \
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
    -DXAIOS_BOOT_TEST_APPS="$BOOT_TEST_APPS" \
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
  "$LOADER_PLATFORM_OBJ" \
  "$LOADER_IMAGE_OBJ" \
  "$LOADER_SHA256_OBJ" \
  "$LOADER_SSH_CRYPTO_OBJ" \
  "$LOADER_TWEETNACL_OBJ" \
  /opt:ref \
  /out:"$LOADER_EFI"
