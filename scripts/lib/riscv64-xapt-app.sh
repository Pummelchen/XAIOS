# xapt, which needs TLS and therefore BearSSL and the libc sysroot. Built
# separately from the loop above because it is the only application with
# dependencies outside the userspace tree.
XAPT_ARGS=""
XAPT_BEARSSL="$ROOT_DIR/build/bearssl/riscv64/libbearssl-xapt.a"
if [ -f "$XAPT_BEARSSL" ] &&
   [ -f "$ROOT_DIR/build/libc/riscv64/sysroot/lib/libc.a" ]; then
  printf '%s\n' "Building /bin/xapt..."
  for xapt_src in xapt xapt_catalog xapt_http xapt_tls xapt_trust_anchors; do
    "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL \
      -std=c99 -ffreestanding -fno-stack-protector -fno-builtin -fno-pic \
      -fno-pie -Os -Wall -Wextra -Werror \
      -isystem "$ROOT_DIR/build/libc/riscv64/sysroot/include" \
      -I"$ROOT_DIR/userspace/include" -I"$ROOT_DIR/userspace/apps" \
      -I"$ROOT_DIR/third_party/bearssl/inc" \
      -c "$ROOT_DIR/userspace/apps/$xapt_src.c" -o "$BUILD_DIR/$xapt_src.o"
  done
  "$CLANG" --target="$TARGET" -march=rv64gc -mabi=lp64d $CODE_MODEL \
    -ffreestanding -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
    -c "$ROOT_DIR/userspace/lib/start.S" -o "$BUILD_DIR/start-xapt.o"
  "$LD_LLD" -nostdlib -T "$ROOT_DIR/userspace/init/linker.ld" \
    -o "$BUILD_DIR/xapt.elf" "$BUILD_DIR/start-xapt.o" \
    "$BUILD_DIR/lib-hello.o" "$BUILD_DIR/control-hello.o" "$BUILD_DIR/net-hello.o" "$BUILD_DIR/session-hello.o" \
    "$BUILD_DIR/control-primitives-hello.o" \
    "$BUILD_DIR/control-system-hello.o" \
    "$BUILD_DIR/control-storage-hello.o" \
    "$BUILD_DIR/control-ops-hello.o" "$BUILD_DIR/control-config-hello.o" "$BUILD_DIR/control-request-hello.o" "$BUILD_DIR/control-parse-flags-hello.o" "$BUILD_DIR/control-parse-validate-hello.o" "$BUILD_DIR/control-dispatch-hello.o" \
    "$BUILD_DIR/xapt.o" "$BUILD_DIR/xapt_catalog.o" "$BUILD_DIR/xapt_http.o" \
    "$BUILD_DIR/xapt_tls.o" "$BUILD_DIR/xapt_trust_anchors.o" "$XAPT_BEARSSL"
  XAPT_ARGS="/bin/xapt=$BUILD_DIR/xapt.elf"
else
  printf '%s\n' "warning: no riscv64 BearSSL or libc; xapt omitted" >&2
fi
