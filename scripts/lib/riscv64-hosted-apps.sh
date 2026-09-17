# The hosted ISO C99 demonstration and the termination probes, built against
# the same picolibc sysroot the other architectures use. The kernel launches
# these when XAIOS_LIBC_TEST is set, which build-riscv64.sh now defaults on.
HOSTED_ARGS=""
LIBC_RUNTIME="$ROOT_DIR/build/libc/riscv64/runtime-test"
# See scripts/build-image.sh: the binaries, not the linker script. A stale
# user ELF here panics the kernel a full boot away from the mistake.
"${XAIOS_PYTHON3:-python3}" "$ROOT_DIR/tools/check_user_elf_base.py" \
  "$ROOT_DIR/build/riscv64-userspace" "$LIBC_RUNTIME"
if [ -f "$ROOT_DIR/build/libc/riscv64/sysroot/lib/libc.a" ] &&
   [ -f "$LIBC_RUNTIME/crt0.o" ]; then
  printf '%s\n' "Building hosted C99 /bin/helloworldc99..."
  "$ROOT_DIR/scripts/build-c99-app.sh" --arch riscv64 --main void \
    "$ROOT_DIR/userspace/apps/hosted/helloworldc99.c" \
    "$BUILD_DIR/helloworldc99.elf"
  HOSTED_ARGS="/bin/helloworldc99=$BUILD_DIR/helloworldc99.elf"
  for probe in c99-runtime-smoke:c99-runtime-smoke \
      c99-main-void:c99-main_void c99-exit-probe:c99-exit_probe \
      c99-abort-probe:c99-abort_probe \
      c99-thread-context:c99-thread-context; do
    guest=${probe%%:*}
    host=${probe#*:}
    HOSTED_ARGS="$HOSTED_ARGS /bin/$guest=$LIBC_RUNTIME/$host.elf"
  done
else
  printf '%s\n' "warning: no riscv64 libc; C99 applications omitted" >&2
fi
