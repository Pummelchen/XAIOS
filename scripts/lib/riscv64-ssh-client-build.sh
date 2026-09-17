# /bin/ssh and /bin/scp: the client sshd launches when a session dials out.
#
# This image had neither, so a RISC-V guest could be logged into and could
# log into nothing: the shell's `ssh` answered "outbound child launch failed:
# client app missing", which is a true statement about a missing file and
# reads like a broken network. Half a network stack, and the half the
# bidirectional interoperability suite is entirely about.
printf '%s\n' "Building /bin/ssh and /bin/scp..."
SSH_CLIENT_OBJS=""
for ssh_client_src in ssh ssh_client ssh_client_scp ssh_client_kex ssh_client_handshake ssh_client_auth ssh_client_command ssh_known_hosts ssh_crypto ssh_crypto_symmetric ssh_identity \
    ssh_mlkem tweetnacl_subset ssh_protocol ssh_connection ssh_sftp; do
  ssh_client_path="$ROOT_DIR/userspace/sshd/$ssh_client_src.c"
  [ "$ssh_client_src" = ssh ] && \
    ssh_client_path="$ROOT_DIR/userspace/apps/ssh.c"
  "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL \
    -std=c99 -ffreestanding -fno-stack-protector -fno-builtin -fno-pic \
    -fno-pie -Wall -Wextra -Werror \
    -DXAIOS_SSH_CLIENT_APP=1 \
    -DMLK_CONFIG_FILE='"mlkem_xaios_config.h"' \
    -I"$ROOT_DIR/userspace/include" -I"$ROOT_DIR/userspace/sshd" \
    -I"$ROOT_DIR/third_party/mlkem-native/mlkem" \
    -I"$ROOT_DIR/third_party/openbsd-compat" \
    -I"$ROOT_DIR/userspace/apps/terminal" \
    -c "$ssh_client_path" -o "$BUILD_DIR/ssh-client-$ssh_client_src.o"
  SSH_CLIENT_OBJS="$SSH_CLIENT_OBJS $BUILD_DIR/ssh-client-$ssh_client_src.o"
done
SSH_CLIENT_OBJS="$SSH_CLIENT_OBJS $BUILD_DIR/sshd-mlkem.o"
# bcrypt_pbkdf, for an encrypted private key. -Wno-unknown-attributes because
# the imported source carries annotations this compiler does not know.
for compat_src in blowfish bcrypt_pbkdf; do
  "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL \
    -std=c99 -ffreestanding -fno-stack-protector -fno-builtin -fno-pic \
    -fno-pie -Wall -Wextra -Werror -Wno-unknown-attributes \
    -I"$ROOT_DIR/userspace/include" -I"$ROOT_DIR/userspace/sshd" \
    -I"$ROOT_DIR/third_party/openbsd-compat" \
    -c "$ROOT_DIR/third_party/openbsd-compat/$compat_src.c" \
    -o "$BUILD_DIR/ssh-client-$compat_src.o"
  SSH_CLIENT_OBJS="$SSH_CLIENT_OBJS $BUILD_DIR/ssh-client-$compat_src.o"
done
"$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL \
  -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
  -c "$ROOT_DIR/userspace/lib/start.S" -o "$BUILD_DIR/start-ssh-client.o"
"$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL -std=c99 \
  -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
  -I"$ROOT_DIR/userspace/include" \
  -c "$ROOT_DIR/userspace/lib/xaios_user.c" -o "$BUILD_DIR/lib-ssh-client.o"
  "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL -std=c99 \
    -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
    -I"$ROOT_DIR/userspace/include" \
    -c "$ROOT_DIR/userspace/lib/xaios_user_net.c" -o "$BUILD_DIR/net-ssh-client.o"
  "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL -std=c99 \
    -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
    -I"$ROOT_DIR/userspace/include" \
    -c "$ROOT_DIR/userspace/lib/xaios_user_session.c" -o "$BUILD_DIR/session-ssh-client.o"
# shellcheck disable=SC2086
"$LD_LLD" -nostdlib -T "$ROOT_DIR/userspace/init/linker.ld" \
  -o "$BUILD_DIR/ssh.elf" "$BUILD_DIR/start-ssh-client.o" \
  "$BUILD_DIR/lib-ssh-client.o" "$BUILD_DIR/net-ssh-client.o" "$BUILD_DIR/session-ssh-client.o" $SSH_CLIENT_OBJS
# shellcheck disable=SC2086
"$LD_LLD" -nostdlib -T "$ROOT_DIR/userspace/init/linker.ld" \
  -o "$BUILD_DIR/scp.elf" "$BUILD_DIR/start-ssh-client.o" \
  "$BUILD_DIR/lib-ssh-client.o" "$BUILD_DIR/net-ssh-client.o" "$BUILD_DIR/session-ssh-client.o" $SSH_CLIENT_OBJS
SSHD_ARGS="$SSHD_ARGS /bin/ssh=$BUILD_DIR/ssh.elf"
SSHD_ARGS="$SSHD_ARGS /bin/scp=$BUILD_DIR/scp.elf"
