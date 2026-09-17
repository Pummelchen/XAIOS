# Sourced by scripts/build-image.sh; not a standalone script.
#
# The freestanding userspace runtime: /init, the service manager, the
# worker, and the shared objects (start, lib, control client and renderers,
# screen framework) every user ELF links against. Runs in the caller's
# shell.

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
  -c "$ROOT_DIR/userspace/lib/control_render_primitives.c" \
  -o "$USER_CONTROL_PRIM_OBJ"

# The system and status renderers, split out of the control client itself.
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
  -c "$ROOT_DIR/userspace/lib/control_render_system.c" \
  -o "$USER_CONTROL_SYS_OBJ"

# The storage-table and operation renderers, the next groups out of the client.
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
  -c "$ROOT_DIR/userspace/lib/control_render_storage.c" \
  -o "$USER_CONTROL_STORAGE_OBJ"

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
  -c "$ROOT_DIR/userspace/lib/control_render_ops.c" \
  -o "$USER_CONTROL_OPS_OBJ"

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
    -c "$ROOT_DIR/userspace/lib/control_render_config.c" \
    -o "$USER_CONTROL_CONFIG_OBJ"

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
    -c "$ROOT_DIR/userspace/lib/control_request.c" \
    -o "$USER_CONTROL_REQUEST_OBJ"

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
    -c "$ROOT_DIR/userspace/lib/control_parse_flags.c" \
    -o "$USER_CONTROL_PARSE_FLAGS_OBJ"

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
    -c "$ROOT_DIR/userspace/lib/control_parse_validate.c" \
    -o "$USER_CONTROL_PARSE_VALIDATE_OBJ"

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
    -c "$ROOT_DIR/userspace/lib/control_dispatch.c" \
    -o "$USER_CONTROL_DISPATCH_OBJ"

# The screen framework: the grid, the present that writes only what
# changed, and the key decoder. Linked into every program that draws a
# screen, and into sshd, which runs every alternate-screen program through it.
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
  -c "$ROOT_DIR/userspace/lib/xaios_screen.c" \
  -o "$USER_SCREEN_OBJ"
