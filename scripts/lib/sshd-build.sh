# Sourced by scripts/build-image.sh; not a standalone script.
#
# /bin/sshd and the /bin/ssh and /bin/scp child client: the sshd object
# loop, the in-tree ML-KEM and terminal programs, and the OpenBSD
# compatibility objects, each linked from its response file. Runs in the
# caller's shell.

printf '%s\n' "Building userspace /bin/sshd ELF..."
# The same escape hatch the kernel has in XAIOS_KERNEL_CFLAGS_EXTRA, for the
# same reason: a gate that has to compare two behaviours of this server wants
# both of them built from one tree, one workload and one instrument. B-45's
# gate uses it to build the authorized-key cache without its invalidation, to
# show what a cache keyed on nothing looks like. Unset in every ordinary build.
SSHD_CFLAGS_EXTRA="${XAIOS_SSHD_CFLAGS_EXTRA:-}"
if [ -n "$SSHD_CFLAGS_EXTRA" ]; then
  printf '%s\n' "sshd built with extra flags: $SSHD_CFLAGS_EXTRA"
fi
SSHD_RESPONSE_FILE="$INIT_BUILD_DIR/sshd-objects.rsp"
: > "$SSHD_RESPONSE_FILE"
for sshd_src in sshd.c sshd_audit.c sshd_rate_limit.c sshd_kex.c sshd_console_screen.c sshd_console_programs.c sshd_auth.c sshd_keys.c sshd_diagnostics.c sshd_console_ui.c sshd_config.c sshd_console_session.c ssh_crypto.c ssh_crypto_symmetric.c ssh_mlkem.c tweetnacl_subset.c ssh_protocol.c ssh_channel.c ssh_alt_screen.c ssh_channel_shell.c ssh_channel_stream.c ssh_client_proxy.c ssh_host_key.c ssh_connection.c sftp_server.c less_pager.c; do
  sshd_obj="$INIT_BUILD_DIR/sshd-${sshd_src%.c}.o"
  sshd_opt=""
  if [ "$sshd_src" = "sshd.c" ] || [ "$sshd_src" = "sshd_audit.c" ] ||
      [ "$sshd_src" = "sshd_rate_limit.c" ] || [ "$sshd_src" = "sshd_kex.c" ] || [ "$sshd_src" = "sshd_console_screen.c" ] || [ "$sshd_src" = "sshd_console_programs.c" ] || [ "$sshd_src" = "sshd_auth.c" ] || [ "$sshd_src" = "sshd_keys.c" ] || [ "$sshd_src" = "sshd_diagnostics.c" ] || [ "$sshd_src" = "sshd_console_ui.c" ] || [ "$sshd_src" = "sshd_config.c" ] || [ "$sshd_src" = "sshd_console_session.c" ]; then
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
    $SSHD_CFLAGS_EXTRA \
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
printf '"%s"\n' "$USER_SCREEN_OBJ" >> "$SSHD_RESPONSE_FILE"
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
  "$USER_CONTROL_OBJ" "$USER_CONTROL_PRIM_OBJ" "$USER_CONTROL_SYS_OBJ" "$USER_CONTROL_STORAGE_OBJ" "$USER_CONTROL_OPS_OBJ" "$USER_CONTROL_CONFIG_OBJ" "$USER_CONTROL_REQUEST_OBJ" \
  @"$SSHD_RESPONSE_FILE"
set -- "$@" "/bin/sshd=$INIT_BUILD_DIR/sshd.elf"
printf '%s\n' "Building userspace /bin/ssh child client ELF..."
SSH_CLIENT_RESPONSE_FILE="$INIT_BUILD_DIR/ssh-client-objects.rsp"
: > "$SSH_CLIENT_RESPONSE_FILE"
for ssh_client_src in ssh.c ssh_client.c ssh_sftp.c ssh_client_scp.c ssh_client_kex.c ssh_client_handshake.c ssh_client_auth.c ssh_client_command.c ssh_known_hosts.c ssh_crypto.c ssh_crypto_symmetric.c ssh_identity.c ssh_mlkem.c tweetnacl_subset.c ssh_protocol.c ssh_connection.c; do
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
