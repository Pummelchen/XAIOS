# The file and archive utilities, which this image did not carry at all.
#
# They are one source compiled once per name -- XAIOS_UTILITY_NAME selects
# which applet the binary is -- exactly as the other builder does it, and
# nothing in them is architecture-specific. Their absence was invisible from
# inside: the boot-test shell answers `ls` and `cat` with built-ins, so a
# machine with none of these still looked like it had them until an external
# client asked for `stat` over SSH and got nothing. That is what porting the
# Debian client suite to this machine found.
UTILITY_APPS="ls mkdir touch cp mv rm rmdir stat cat head tail less grep find sed write tar cpio zip unzip ps df du"
"$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL -std=c99 \
  -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
  -Wall -Wextra -Werror -I"$ROOT_DIR/kernel/include" \
  -c "$ROOT_DIR/kernel/lib/inflate.c" -o "$BUILD_DIR/xutils-inflate.o"
for app in $UTILITY_APPS; do
  printf '%s\n' "Building /bin/$app utility..."
  "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL -std=c99 \
    -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
    -Wall -Wextra -Werror -DXAIOS_UTILITY_NAME=\"$app\" \
    -I"$ROOT_DIR/userspace/include" \
    -c "$ROOT_DIR/userspace/apps/xutils.c" -o "$BUILD_DIR/xutils-$app.o"
  "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL -std=c99 \
    -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
    -Wall -Wextra -Werror -DXAIOS_UTILITY_NAME=\"$app\" \
    -I"$ROOT_DIR/userspace/include" \
    -c "$ROOT_DIR/userspace/apps/xutils_archive.c" -o "$BUILD_DIR/xutils-archive-$app.o"
  "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL -std=c99 \
    -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
    -Wall -Wextra -Werror -DXAIOS_UTILITY_NAME=\"$app\" \
    -I"$ROOT_DIR/userspace/include" \
    -c "$ROOT_DIR/userspace/apps/xutils_file.c" -o "$BUILD_DIR/xutils-file-$app.o"
  "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL -std=c99 \
    -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
    -Wall -Wextra -Werror -DXAIOS_UTILITY_NAME=\"$app\" \
    -I"$ROOT_DIR/userspace/include" \
    -c "$ROOT_DIR/userspace/apps/xutils_text.c" -o "$BUILD_DIR/xutils-text-$app.o"
  "$LD_LLD" -nostdlib -T "$ROOT_DIR/userspace/init/linker.ld" \
    -o "$BUILD_DIR/$app.elf" "$BUILD_DIR/start-xaios-shell.o" \
    "$BUILD_DIR/lib-xaios-shell.o" "$BUILD_DIR/control-xaios-shell.o" "$BUILD_DIR/net-xaios-shell.o" "$BUILD_DIR/session-xaios-shell.o" \
    "$BUILD_DIR/control-primitives-xaios-shell.o" \
    "$BUILD_DIR/control-system-xaios-shell.o" \
    "$BUILD_DIR/control-storage-xaios-shell.o" \
    "$BUILD_DIR/control-ops-xaios-shell.o" "$BUILD_DIR/control-config-xaios-shell.o" "$BUILD_DIR/control-request-xaios-shell.o" "$BUILD_DIR/control-parse-flags-xaios-shell.o" "$BUILD_DIR/control-parse-validate-xaios-shell.o" "$BUILD_DIR/control-dispatch-xaios-shell.o" \
    "$BUILD_DIR/xutils-inflate.o" "$BUILD_DIR/xutils-archive-$app.o" \
    "$BUILD_DIR/xutils-file-$app.o" "$BUILD_DIR/xutils-text-$app.o" "$BUILD_DIR/xutils-$app.o"
  APP_ARGS="$APP_ARGS /bin/$app=$BUILD_DIR/$app.elf"
done
