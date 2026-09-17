# Sourced by scripts/build-image.sh; not a standalone script.
#
# The optional credential files folded into the image argument list, then
# the FAT boot image, the VirtIO block test image, the persistent and
# xaiFS volumes and the A/B system volume. Runs in the caller's shell, so
# "$@" is the list of packaged /bin entries built above.

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

# Every user binary about to be packed has to agree with the kernel about
# where userspace lives. The linker scripts are checked from source by the ABI
# contract; these are build artefacts, and a stale one is produced by a
# perfectly correct linker script that simply was not re-run. Packing it
# yields a kernel that boots, passes its self-tests and then dies inside
# user_load_process.
"${XAIOS_PYTHON3:-python3}" "$ROOT_DIR/tools/check_user_elf_base.py" \
  "$INIT_BUILD_DIR" "$BUILD_DIR/libc/$TARGET_ARCH/runtime-test"

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
