# Sourced by scripts/build-image.sh; not a standalone script.
#
# The USER_APPS loop: one ELF per application, with the xtop, clustertest,
# xapt and xaios-setup special cases, appending each "/bin/<name>=<elf>" to
# the image argument list. Runs in the caller's shell, so `set --` here
# sets the parent's positional parameters.

set --
for app in $USER_APPS; do
  app_obj="$INIT_BUILD_DIR/$app.o"
  app_elf="$INIT_BUILD_DIR/$app.elf"
  xtop_serve_obj=""
  xtop_snapshot_obj=""
  xtop_report_obj=""
  xtop_render_obj=""
  xtop_glyph_obj=""
  xtop_draw_obj=""
  if [ "$app" = "xtop" ]; then
    xtop_serve_obj="$INIT_BUILD_DIR/xtop-serve.o"
    xtop_render_obj="$INIT_BUILD_DIR/xtop-render.o"
    xtop_glyph_obj="$INIT_BUILD_DIR/xtop-glyph.o"
    xtop_draw_obj="$INIT_BUILD_DIR/xtop-draw.o"
    xtop_snapshot_obj="$INIT_BUILD_DIR/xtop-snapshot.o"
    xtop_report_obj="$INIT_BUILD_DIR/xtop-report.o"
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
      -I"$ROOT_DIR/userspace/sshd" \
      -I"$ROOT_DIR/engine/include" \
      -c "$ROOT_DIR/userspace/apps/xtop_serve.c" \
      -o "$xtop_serve_obj"
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
      -I"$ROOT_DIR/userspace/sshd" \
      -I"$ROOT_DIR/engine/include" \
      -c "$ROOT_DIR/userspace/apps/xtop_render.c" \
      -o "$xtop_render_obj"
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
      -I"$ROOT_DIR/userspace/sshd" \
      -I"$ROOT_DIR/engine/include" \
      -c "$ROOT_DIR/userspace/apps/xtop_glyph.c" \
      -o "$xtop_glyph_obj"
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
      -I"$ROOT_DIR/userspace/sshd" \
      -I"$ROOT_DIR/engine/include" \
      -c "$ROOT_DIR/userspace/apps/xtop_draw.c" \
      -o "$xtop_draw_obj"
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
      -I"$ROOT_DIR/userspace/sshd" \
      -I"$ROOT_DIR/engine/include" \
      -c "$ROOT_DIR/userspace/apps/xtop_snapshot.c" \
      -o "$xtop_snapshot_obj"
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
      -I"$ROOT_DIR/userspace/sshd" \
      -I"$ROOT_DIR/engine/include" \
      -c "$ROOT_DIR/userspace/apps/xtop_report.c" \
      -o "$xtop_report_obj"
  fi
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
    -DXAIOS_BOOT_TEST_APPS="$BOOT_TEST_APPS" \
    $([ "$app" = clustertest ] && printf '%s' "$CLUSTER_APP_CFLAGS") \
    -I"$ROOT_DIR/userspace/include" \
    -I"$ROOT_DIR/userspace/sshd" \
    -I"$ROOT_DIR/engine/include" \
    -c "$ROOT_DIR/userspace/apps/$app.c" \
    -o "$app_obj"

  if [ "$app" = "clustertest" ]; then
    # The cluster framing lives in engine/ and has never been built for a
    # target before -- every test of it ran hosted, which is how it kept a
    # transport-shaped hole for as long as it did. It needs the engine headers
    # and its hash; memcpy and memset come from the userspace library, which
    # provides both under their standard names.
    CLUSTER_OBJ="$INIT_BUILD_DIR/cluster.o"
    CLUSTER_SHA_OBJ="$INIT_BUILD_DIR/cluster-sha256.o"
    for source in cluster sha256; do
      "$CLANG" --target="$TARGET_TRIPLE" $USER_ARCH_CFLAGS -std=c99 \
        -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
        -Wall -Wextra -Werror \
        -I"$ROOT_DIR/engine/include" -I"$ROOT_DIR/engine/src" \
        -I"$ROOT_DIR/userspace/include" \
        -c "$ROOT_DIR/engine/src/$source.c" \
        -o "$INIT_BUILD_DIR/cluster-$source.o"
    done
    CLUSTER_OBJ="$INIT_BUILD_DIR/cluster-cluster.o"
    CLUSTER_SHA_OBJ="$INIT_BUILD_DIR/cluster-sha256.o"
    # clustertest is split into translation units beside it for the file-size
    # budget; they are linked into the app, not built as apps of their own.
    CLUSTER_PLANE_OBJS=""
    for plane_src in clustertest_support clustertest_mesh; do
      "$CLANG" --target="$TARGET_TRIPLE" $USER_ARCH_CFLAGS -std=c99 \
        -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
        -Wall -Wextra -Werror $CLUSTER_APP_CFLAGS \
        -I"$ROOT_DIR/userspace/include" -I"$ROOT_DIR/userspace/sshd" \
        -I"$ROOT_DIR/engine/include" \
        -c "$ROOT_DIR/userspace/apps/$plane_src.c" \
        -o "$INIT_BUILD_DIR/$plane_src.o"
      CLUSTER_PLANE_OBJS="$CLUSTER_PLANE_OBJS $INIT_BUILD_DIR/$plane_src.o"
    done
  fi

  if [ "$app" = "xapt" ]; then
    XAPT_TLS_OBJ="$INIT_BUILD_DIR/xapt-tls.o"
    XAPT_BEARSSL="$BUILD_DIR/bearssl/$TARGET_ARCH/libbearssl-xapt.a"
    [ -f "$XAPT_BEARSSL" ] || "$ROOT_DIR/scripts/build-bearssl.sh" "$TARGET_ARCH"
    "$CLANG" --target="$TARGET_TRIPLE" $USER_ARCH_CFLAGS -std=c99 \
      -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
      -Os -Wall -Wextra -Werror \
      -isystem "$BUILD_DIR/libc/$TARGET_ARCH/sysroot/include" \
      -I"$ROOT_DIR/userspace/include" -I"$ROOT_DIR/userspace/apps" \
      -I"$ROOT_DIR/third_party/bearssl/inc" \
      -c "$ROOT_DIR/userspace/apps/xapt_tls.c" -o "$XAPT_TLS_OBJ"
    XAPT_TRUST_OBJ="$INIT_BUILD_DIR/xapt-trust-anchors.o"
    "$CLANG" --target="$TARGET_TRIPLE" $USER_ARCH_CFLAGS -std=c99 \
      -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
      -Os -Wall -Wextra -Werror \
      -isystem "$BUILD_DIR/libc/$TARGET_ARCH/sysroot/include" \
      -I"$ROOT_DIR/userspace/include" -I"$ROOT_DIR/userspace/apps" \
      -I"$ROOT_DIR/third_party/bearssl/inc" \
      -c "$ROOT_DIR/userspace/apps/xapt_trust_anchors.c" \
      -o "$XAPT_TRUST_OBJ"

    # xapt is split into translation units beside it for the file-size budget.
    XAPT_INTERNAL_OBJS=""
    for xapt_internal_src in xapt_catalog xapt_http; do
      "$CLANG" --target="$TARGET_TRIPLE" $USER_ARCH_CFLAGS -std=c99 \
        -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
        -Os -Wall -Wextra -Werror \
        -isystem "$BUILD_DIR/libc/$TARGET_ARCH/sysroot/include" \
        -I"$ROOT_DIR/userspace/include" -I"$ROOT_DIR/userspace/apps" \
        -I"$ROOT_DIR/third_party/bearssl/inc" \
        -c "$ROOT_DIR/userspace/apps/$xapt_internal_src.c" \
        -o "$INIT_BUILD_DIR/xapt-$xapt_internal_src.o"
      XAPT_INTERNAL_OBJS="$XAPT_INTERNAL_OBJS $INIT_BUILD_DIR/xapt-$xapt_internal_src.o"
    done
    "$LD_LLD" -nostdlib -T "$ROOT_DIR/userspace/init/linker.ld" \
      -o "$app_elf" "$USER_START_OBJ" "$USER_LIB_OBJ" "$USER_NET_OBJ" "$USER_SESSION_OBJ" \
      "$USER_CONTROL_OBJ" "$USER_CONTROL_PRIM_OBJ" "$USER_CONTROL_SYS_OBJ" "$USER_CONTROL_STORAGE_OBJ" "$USER_CONTROL_OPS_OBJ" "$USER_CONTROL_CONFIG_OBJ" "$USER_CONTROL_REQUEST_OBJ" "$USER_CONTROL_PARSE_FLAGS_OBJ" "$USER_CONTROL_PARSE_VALIDATE_OBJ" "$USER_CONTROL_DISPATCH_OBJ" "$app_obj" "$XAPT_TLS_OBJ" "$XAPT_TRUST_OBJ" $XAPT_INTERNAL_OBJS \
      "$XAPT_BEARSSL"
  elif [ "$app" = "xaios-setup" ]; then
    # Setup writes the credential records sshd reads, so it hashes them with
    # the same code sshd verifies them with. Two implementations of PBKDF2
    # that disagree produce an account that cannot be logged into, and the
    # disagreement would only show at the login prompt.
    SETUP_CRYPTO_OBJ="$INIT_BUILD_DIR/setup-ssh-crypto.o"
    SETUP_NACL_OBJ="$INIT_BUILD_DIR/setup-tweetnacl.o"
    for setup_src in ssh_crypto ssh_crypto_symmetric tweetnacl_subset; do
      "$CLANG" --target="$TARGET_TRIPLE" $USER_ARCH_CFLAGS -std=c99 \
        -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
        -Wall -Wextra -Werror \
        -I"$ROOT_DIR/userspace/include" -I"$ROOT_DIR/userspace/sshd" \
        -c "$ROOT_DIR/userspace/sshd/$setup_src.c" \
        -o "$INIT_BUILD_DIR/setup-$setup_src.o"
    done
    SETUP_CRYPTO_OBJ="$INIT_BUILD_DIR/setup-ssh_crypto.o"
    SETUP_CRYPTO_SYMMETRIC_OBJ="$INIT_BUILD_DIR/setup-ssh_crypto_symmetric.o"
    SETUP_NACL_OBJ="$INIT_BUILD_DIR/setup-tweetnacl_subset.o"
    "$LD_LLD" \
      -nostdlib \
      -T "$ROOT_DIR/userspace/init/linker.ld" \
      -o "$app_elf" \
      "$USER_START_OBJ" \
      "$USER_LIB_OBJ" "$USER_NET_OBJ" "$USER_SESSION_OBJ" \
      "$USER_CONTROL_OBJ" "$USER_CONTROL_PRIM_OBJ" "$USER_CONTROL_SYS_OBJ" "$USER_CONTROL_STORAGE_OBJ" "$USER_CONTROL_OPS_OBJ" "$USER_CONTROL_CONFIG_OBJ" "$USER_CONTROL_REQUEST_OBJ" "$USER_CONTROL_PARSE_FLAGS_OBJ" "$USER_CONTROL_PARSE_VALIDATE_OBJ" "$USER_CONTROL_DISPATCH_OBJ" \
      "$app_obj" \
      "$SETUP_CRYPTO_OBJ" \
      "$SETUP_CRYPTO_SYMMETRIC_OBJ" \
      "$SETUP_NACL_OBJ"
  elif [ "$app" = "xaiosctl" ] ||
      [ "$app" = "xtop" ]; then
    "$LD_LLD" \
      -nostdlib \
      -T "$ROOT_DIR/userspace/init/linker.ld" \
      -o "$app_elf" \
      "$USER_START_OBJ" \
      "$USER_LIB_OBJ" "$USER_NET_OBJ" "$USER_SESSION_OBJ" \
      "$USER_CONTROL_OBJ" "$USER_CONTROL_PRIM_OBJ" "$USER_CONTROL_SYS_OBJ" "$USER_CONTROL_STORAGE_OBJ" "$USER_CONTROL_OPS_OBJ" "$USER_CONTROL_CONFIG_OBJ" "$USER_CONTROL_REQUEST_OBJ" "$USER_CONTROL_PARSE_FLAGS_OBJ" "$USER_CONTROL_PARSE_VALIDATE_OBJ" "$USER_CONTROL_DISPATCH_OBJ" \
      "$USER_SCREEN_OBJ" \
      $xtop_serve_obj \
      $xtop_render_obj \
      $xtop_glyph_obj \
      $xtop_draw_obj \
      $xtop_snapshot_obj \
      $xtop_report_obj \
      "$app_obj"
  elif [ "$app" = "clustertest" ]; then
    "$LD_LLD" \
      -nostdlib \
      -T "$ROOT_DIR/userspace/init/linker.ld" \
      -o "$app_elf" \
      "$USER_START_OBJ" \
      "$USER_LIB_OBJ" "$USER_NET_OBJ" "$USER_SESSION_OBJ" \
      "$app_obj" \
      "$CLUSTER_OBJ" \
      $CLUSTER_PLANE_OBJS \
      "$CLUSTER_SHA_OBJ"
  else
    "$LD_LLD" \
      -nostdlib \
      -T "$ROOT_DIR/userspace/init/linker.ld" \
      -o "$app_elf" \
      "$USER_START_OBJ" \
      "$USER_LIB_OBJ" "$USER_NET_OBJ" "$USER_SESSION_OBJ" \
      "$app_obj"
  fi
  set -- "$@" "/bin/$app=$app_elf"
done
