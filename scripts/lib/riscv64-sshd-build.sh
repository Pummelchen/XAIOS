# /bin/sshd, and the terminal applications it hosts. This is what turns a
# machine that boots into a machine anyone can reach: without it the boot
# stops at a setup prompt and there is nothing to log into.
printf '%s\n' "Building /bin/sshd..."
SSHD_OBJS=""
for sshd_src in sshd sshd_audit sshd_rate_limit sshd_kex sshd_console_screen sshd_console_programs sshd_auth sshd_keys sshd_diagnostics sshd_console_ui sshd_config sshd_console_session sshd_connection_support sshd_service sshd_connection ssh_crypto ssh_crypto_symmetric ssh_mlkem tweetnacl_subset ssh_protocol \
    ssh_channel ssh_alt_screen ssh_channel_shell ssh_channel_stream ssh_channel_table ssh_channel_request ssh_client_proxy ssh_host_key ssh_connection sftp_server sftp_server_file sftp_server_dir \
    less_pager; do
  sshd_opt=""
  case "$sshd_src" in
    sshd|sshd_audit|sshd_rate_limit|sshd_kex|sshd_console_screen|sshd_console_programs|sshd_auth|sshd_keys|sshd_diagnostics|sshd_console_ui|sshd_config|sshd_console_session|sshd_connection_support|sshd_service|sshd_connection) sshd_opt="-Os" ;;
    *) sshd_opt="" ;;
  esac
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
  "$BUILD_DIR/lib-hello.o" "$BUILD_DIR/control-hello.o" "$BUILD_DIR/net-hello.o" "$BUILD_DIR/session-hello.o" \
  "$BUILD_DIR/control-primitives-hello.o" \
  "$BUILD_DIR/control-system-hello.o" \
  "$BUILD_DIR/control-storage-hello.o" \
  "$BUILD_DIR/control-ops-hello.o" "$BUILD_DIR/control-config-hello.o" "$BUILD_DIR/control-request-hello.o" "$BUILD_DIR/control-parse-flags-hello.o" "$BUILD_DIR/control-parse-validate-hello.o" "$BUILD_DIR/control-dispatch-hello.o" \
  "$BUILD_DIR/screen-hello.o" $SSHD_OBJS
SSHD_ARGS="/bin/sshd=$BUILD_DIR/sshd.elf"
