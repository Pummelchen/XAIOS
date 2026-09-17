APP_ARGS=""
for app in $USER_APPS; do
  printf '%s\n' "Building /bin/$app..."
  "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL \
    -std=c99 -ffreestanding -fno-stack-protector -fno-builtin -fno-pic \
    -fno-pie -Wall -Wextra -Werror -DXAIOS_BOOT_TEST_APPS="${XAIOS_BOOT_TEST_APPS:-1}" \
    $([ "$app" = clustertest ] && printf '%s' "$CLUSTER_APP_CFLAGS") \
    -I"$ROOT_DIR/userspace/include" -I"$ROOT_DIR/userspace/sshd" \
    -I"$ROOT_DIR/engine/include" \
    -c "$ROOT_DIR/userspace/apps/$app.c" -o "$BUILD_DIR/$app.o"
  "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL -ffreestanding \
    -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
    -c "$ROOT_DIR/userspace/lib/start.S" -o "$BUILD_DIR/start-$app.o"
  "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL -std=c99 \
    -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
    -I"$ROOT_DIR/userspace/include" \
    -c "$ROOT_DIR/userspace/lib/xaios_user.c" -o "$BUILD_DIR/lib-$app.o"
  "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL -std=c99 \
    -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
    -I"$ROOT_DIR/userspace/include" \
    -c "$ROOT_DIR/userspace/lib/xaios_user_net.c" -o "$BUILD_DIR/net-$app.o"
  "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL -std=c99 \
    -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
    -I"$ROOT_DIR/userspace/include" \
    -c "$ROOT_DIR/userspace/lib/xaios_user_session.c" -o "$BUILD_DIR/session-$app.o"
  # The control-plane client, which xaiosctl and the shell call into.
  "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL -std=c99 \
    -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
    -I"$ROOT_DIR/userspace/include" \
    -c "$ROOT_DIR/userspace/lib/xaios_control_client.c" \
    -o "$BUILD_DIR/control-$app.o"
  "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL -std=c99 \
    -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
    -I"$ROOT_DIR/userspace/include" \
    -c "$ROOT_DIR/userspace/lib/control_render_primitives.c" \
    -o "$BUILD_DIR/control-primitives-$app.o"
  "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL -std=c99 \
    -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
    -I"$ROOT_DIR/userspace/include" \
    -c "$ROOT_DIR/userspace/lib/control_render_system.c" \
    -o "$BUILD_DIR/control-system-$app.o"
  "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL -std=c99 \
    -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
    -I"$ROOT_DIR/userspace/include" \
    -c "$ROOT_DIR/userspace/lib/control_render_storage.c" \
    -o "$BUILD_DIR/control-storage-$app.o"
  "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL -std=c99 \
    -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
    -I"$ROOT_DIR/userspace/include" \
    -c "$ROOT_DIR/userspace/lib/control_render_ops.c" \
    -o "$BUILD_DIR/control-ops-$app.o"
  "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL -std=c99 \
    -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie -Os \
    -I"$ROOT_DIR/userspace/include" \
    -c "$ROOT_DIR/userspace/lib/control_render_config.c" \
    -o "$BUILD_DIR/control-config-$app.o"
  "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL -std=c99 \
    -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie -Os \
    -I"$ROOT_DIR/userspace/include" \
    -c "$ROOT_DIR/userspace/lib/control_request.c" \
    -o "$BUILD_DIR/control-request-$app.o"
  "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL -std=c99 \
    -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie -Os \
    -I"$ROOT_DIR/userspace/include" \
    -c "$ROOT_DIR/userspace/lib/control_parse_flags.c" \
    -o "$BUILD_DIR/control-parse-flags-$app.o"
  "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL -std=c99 \
    -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie -Os \
    -I"$ROOT_DIR/userspace/include" \
    -c "$ROOT_DIR/userspace/lib/control_parse_validate.c" \
    -o "$BUILD_DIR/control-parse-validate-$app.o"
  "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL -std=c99 \
    -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie -Os \
    -I"$ROOT_DIR/userspace/include" \
    -c "$ROOT_DIR/userspace/lib/control_dispatch.c" \
    -o "$BUILD_DIR/control-dispatch-$app.o"
  # The screen framework, for programs that draw a screen.
  "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL -std=c99 \
    -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie -Os \
    -I"$ROOT_DIR/userspace/include" \
    -c "$ROOT_DIR/userspace/lib/xaios_screen.c" -o "$BUILD_DIR/screen-$app.o"
    "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL -std=c99 \
      -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie -Os \
      -I"$ROOT_DIR/userspace/include" \
      -c "$ROOT_DIR/userspace/lib/xaios_screen_input.c" -o "$BUILD_DIR/screen-input-$app.o"
  # xaios-setup writes the credential records sshd reads, so it hashes them
  # with the same code sshd verifies them with -- two implementations of
  # PBKDF2 that disagree produce an account that cannot be logged into, and
  # the disagreement would only show at the login prompt.
  EXTRA_OBJS=""
  # The cluster framing and its hash, from engine/. clustertest links these
  # rather than calling into the kernel, so the wire format it seals with is
  # the same code the other end opens with -- which is the only reason two
  # machines agreeing means anything.
  if [ "$app" = "clustertest" ]; then
    for cluster_src in cluster sha256; do
      "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL \
        -std=c99 -ffreestanding -fno-stack-protector -fno-builtin -fno-pic \
        -fno-pie -I"$ROOT_DIR/engine/include" -I"$ROOT_DIR/engine/src" \
        -c "$ROOT_DIR/engine/src/$cluster_src.c" \
        -o "$BUILD_DIR/cluster-$cluster_src.o"
      EXTRA_OBJS="$EXTRA_OBJS $BUILD_DIR/cluster-$cluster_src.o"
    done
  fi
  if [ "$app" = "clustertest" ]; then
    for plane_src in clustertest_support clustertest_mesh; do
      "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL \
        -std=c99 -ffreestanding -fno-stack-protector -fno-builtin -fno-pic \
        -fno-pie -Wall -Wextra -Werror $CLUSTER_APP_CFLAGS \
        -I"$ROOT_DIR/userspace/include" -I"$ROOT_DIR/userspace/sshd" \
        -I"$ROOT_DIR/engine/include" \
        -c "$ROOT_DIR/userspace/apps/$plane_src.c" \
        -o "$BUILD_DIR/$plane_src.o"
      EXTRA_OBJS="$EXTRA_OBJS $BUILD_DIR/$plane_src.o"
    done
  fi
  if [ "$app" = "xaios-setup" ]; then
    # The split halves of the setup application, linked into it.
    for setup_module_src in xaios-setup-console xaios-setup-storage; do
      "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL \
        -std=c99 -ffreestanding -fno-stack-protector -fno-builtin -fno-pic \
        -fno-pie -Wall -Wextra -Werror \
        -I"$ROOT_DIR/userspace/include" -I"$ROOT_DIR/userspace/sshd" \
        -c "$ROOT_DIR/userspace/apps/$setup_module_src.c" \
        -o "$BUILD_DIR/$setup_module_src.o"
      EXTRA_OBJS="$EXTRA_OBJS $BUILD_DIR/$setup_module_src.o"
    done
    for setup_src in ssh_crypto ssh_crypto_symmetric tweetnacl_subset; do
      "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL \
        -std=c99 -ffreestanding -fno-stack-protector -fno-builtin -fno-pic \
        -fno-pie -Wall -Wextra -Werror \
        -I"$ROOT_DIR/userspace/include" -I"$ROOT_DIR/userspace/sshd" \
        -c "$ROOT_DIR/userspace/sshd/$setup_src.c" \
        -o "$BUILD_DIR/setup-$setup_src.o"
      EXTRA_OBJS="$EXTRA_OBJS $BUILD_DIR/setup-$setup_src.o"
    done
  fi
  if [ "$app" = "xtop" ]; then
    "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL \
      -std=c99 -ffreestanding -fno-stack-protector -fno-builtin -fno-pic \
      -fno-pie -Os -Wall -Wextra -Werror \
      -I"$ROOT_DIR/userspace/include" -I"$ROOT_DIR/userspace/sshd" \
      -I"$ROOT_DIR/engine/include" \
      -c "$ROOT_DIR/userspace/apps/xtop_serve.c" -o "$BUILD_DIR/xtop-serve.o"
    "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL \
      -std=c99 -ffreestanding -fno-stack-protector -fno-builtin -fno-pic \
      -fno-pie -Os -Wall -Wextra -Werror \
      -I"$ROOT_DIR/userspace/include" -I"$ROOT_DIR/userspace/sshd" \
      -I"$ROOT_DIR/engine/include" \
      -c "$ROOT_DIR/userspace/apps/xtop_render.c" -o "$BUILD_DIR/xtop-render.o"
    "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL \
      -std=c99 -ffreestanding -fno-stack-protector -fno-builtin -fno-pic \
      -fno-pie -Os -Wall -Wextra -Werror \
      -I"$ROOT_DIR/userspace/include" -I"$ROOT_DIR/userspace/sshd" \
      -I"$ROOT_DIR/engine/include" \
      -c "$ROOT_DIR/userspace/apps/xtop_glyph.c" -o "$BUILD_DIR/xtop-glyph.o"
    "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL \
      -std=c99 -ffreestanding -fno-stack-protector -fno-builtin -fno-pic \
      -fno-pie -Os -Wall -Wextra -Werror \
      -I"$ROOT_DIR/userspace/include" -I"$ROOT_DIR/userspace/sshd" \
      -I"$ROOT_DIR/engine/include" \
      -c "$ROOT_DIR/userspace/apps/xtop_draw.c" -o "$BUILD_DIR/xtop-draw.o"
    "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL \
      -std=c99 -ffreestanding -fno-stack-protector -fno-builtin -fno-pic \
      -fno-pie -Os -Wall -Wextra -Werror \
      -I"$ROOT_DIR/userspace/include" -I"$ROOT_DIR/userspace/sshd" \
      -I"$ROOT_DIR/engine/include" \
      -c "$ROOT_DIR/userspace/apps/xtop_snapshot.c" -o "$BUILD_DIR/xtop-snapshot.o"
    "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL \
      -std=c99 -ffreestanding -fno-stack-protector -fno-builtin -fno-pic \
      -fno-pie -Os -Wall -Wextra -Werror \
      -I"$ROOT_DIR/userspace/include" -I"$ROOT_DIR/userspace/sshd" \
      -I"$ROOT_DIR/engine/include" \
      -c "$ROOT_DIR/userspace/apps/xtop_report.c" -o "$BUILD_DIR/xtop-report.o"
    EXTRA_OBJS="$EXTRA_OBJS $BUILD_DIR/xtop-serve.o $BUILD_DIR/xtop-render.o $BUILD_DIR/xtop-glyph.o $BUILD_DIR/xtop-draw.o $BUILD_DIR/xtop-snapshot.o $BUILD_DIR/xtop-report.o"
  fi
  # shellcheck disable=SC2086
  "$LD_LLD" -nostdlib -T "$ROOT_DIR/userspace/init/linker.ld" \
    -o "$BUILD_DIR/$app.elf" "$BUILD_DIR/start-$app.o" "$BUILD_DIR/$app.o" \
    "$BUILD_DIR/lib-$app.o" "$BUILD_DIR/control-$app.o" "$BUILD_DIR/net-$app.o" "$BUILD_DIR/session-$app.o" \
    "$BUILD_DIR/control-primitives-$app.o" \
    "$BUILD_DIR/control-system-$app.o" \
    "$BUILD_DIR/control-storage-$app.o" \
    "$BUILD_DIR/control-ops-$app.o" "$BUILD_DIR/control-config-$app.o" "$BUILD_DIR/control-request-$app.o" "$BUILD_DIR/control-parse-flags-$app.o" "$BUILD_DIR/control-parse-validate-$app.o" "$BUILD_DIR/control-dispatch-$app.o" \
    "$BUILD_DIR/screen-$app.o" "$BUILD_DIR/screen-input-$app.o" $EXTRA_OBJS
  APP_ARGS="$APP_ARGS /bin/$app=$BUILD_DIR/$app.elf"
done
