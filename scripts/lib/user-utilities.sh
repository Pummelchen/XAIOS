# Sourced by scripts/build-image.sh; not a standalone script.
#
# The UTILITY_APPS loop: xutils.c and its four companions compiled once per
# utility name and linked into one ELF each. Runs in the caller's shell.

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
  app_file_obj="$INIT_BUILD_DIR/xutils-file-$app.o"
  app_text_obj="$INIT_BUILD_DIR/xutils-text-$app.o"
  app_archive_obj="$INIT_BUILD_DIR/xutils-archive-$app.o"
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
    -c "$ROOT_DIR/userspace/apps/xutils_archive.c" \
    -o "$app_archive_obj"
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
    -c "$ROOT_DIR/userspace/apps/xutils_file.c" \
    -o "$app_file_obj"
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
    -c "$ROOT_DIR/userspace/apps/xutils_text.c" \
    -o "$app_text_obj"
  "$LD_LLD" \
    -nostdlib \
    -T "$ROOT_DIR/userspace/init/linker.ld" \
    -o "$app_elf" \
    "$USER_START_OBJ" \
    "$USER_LIB_OBJ" \
    "$USER_CONTROL_OBJ" "$USER_CONTROL_PRIM_OBJ" "$USER_CONTROL_SYS_OBJ" "$USER_CONTROL_STORAGE_OBJ" "$USER_CONTROL_OPS_OBJ" "$USER_CONTROL_CONFIG_OBJ" "$USER_CONTROL_REQUEST_OBJ" "$USER_CONTROL_PARSE_FLAGS_OBJ" "$USER_CONTROL_PARSE_VALIDATE_OBJ" "$USER_CONTROL_DISPATCH_OBJ" \
    "$USER_INFLATE_OBJ" \
    "$app_archive_obj" \
    "$app_file_obj" \
    "$app_text_obj" \
    "$app_obj"
  set -- "$@" "/bin/$app=$app_elf"
done
