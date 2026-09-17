# Sourced by scripts/build-image.sh; not a standalone script.
#
# The hosted C99 applications: builds the sysroot when it is missing, then
# packs HOSTED_USER_APPS and, under XAIOS_LIBC_TEST, the libc smoke probes.
# Runs in the caller's shell, so `set --` here sets the parent's
# positional parameters.

LIBC_SYSROOT="$BUILD_DIR/libc/$TARGET_ARCH/sysroot"
LIBC_RUNTIME="$BUILD_DIR/libc/$TARGET_ARCH/runtime-test"
LIBC_READY=1
for libc_artifact in \
    "$LIBC_SYSROOT/lib/libc.a" \
    "$LIBC_SYSROOT/lib/libm.a" \
    "$LIBC_SYSROOT/lib/libcompiler_rt_xaios.a" \
    "$LIBC_RUNTIME/crt0.o" \
    "$LIBC_RUNTIME/runtime_main_void.o" \
    "$LIBC_RUNTIME/os_adapter.o" \
    "$LIBC_RUNTIME/thread_context.o" \
    "$LIBC_RUNTIME/locking.o" \
    "$LIBC_RUNTIME/thread_api.o"; do
  if [ ! -f "$libc_artifact" ]; then
    LIBC_READY=0
  fi
done
if [ "$LIBC_READY" = 0 ]; then
  printf '%s\n' "Building hosted ISO C99 libc for $TARGET_ARCH..."
  XAIOS_LIBC_ARCHES="$TARGET_ARCH" "$ROOT_DIR/scripts/build-libc.sh"
fi
for app in $HOSTED_USER_APPS; do
  app_elf="$INIT_BUILD_DIR/$app.elf"
  printf '%s\n' "Building hosted C99 userspace /bin/$app ELF..."
  if [ "$app" = "wtqtest" ]; then
    # The WebTransport client is a hosted application too, but it is built with
    # the port beside it: the vendored runtime, the XAIOS socket seam, this
    # repository's BearSSL backend and the BearSSL archive (B-131).
    "$ROOT_DIR/scripts/build-wt-app.sh" --arch "$TARGET_ARCH" \
      "$ROOT_DIR/userspace/apps/hosted/$app.c" "$app_elf"
  else
    "$ROOT_DIR/scripts/build-c99-app.sh" --arch "$TARGET_ARCH" --main void \
      "$ROOT_DIR/userspace/apps/hosted/$app.c" "$app_elf"
  fi
  set -- "$@" "/bin/$app=$app_elf"
done

set -- "$@" "/etc/xapt.conf=$ROOT_DIR/userspace/init/xapt.conf"

if [ "$LIBC_TEST" = 1 ]; then
  LIBC_TEST_ELF="$BUILD_DIR/libc/$TARGET_ARCH/runtime-test/c99-runtime-smoke.elf"
  if [ ! -f "$LIBC_TEST_ELF" ]; then
    printf '%s\n' "error: hosted C99 test image missing: $LIBC_TEST_ELF" >&2
    printf '%s\n' "       Run XAIOS_LIBC_ARCHES=$TARGET_ARCH make libc first." >&2
    exit 1
  fi
  LIBC_MAIN_VOID_ELF="$BUILD_DIR/libc/$TARGET_ARCH/runtime-test/c99-main_void.elf"
  LIBC_EXIT_PROBE_ELF="$BUILD_DIR/libc/$TARGET_ARCH/runtime-test/c99-exit_probe.elf"
  LIBC_ABORT_PROBE_ELF="$BUILD_DIR/libc/$TARGET_ARCH/runtime-test/c99-abort_probe.elf"
  LIBC_THREAD_CONTEXT_ELF="$BUILD_DIR/libc/$TARGET_ARCH/runtime-test/c99-thread-context.elf"
  for libc_probe in "$LIBC_MAIN_VOID_ELF" "$LIBC_EXIT_PROBE_ELF" \
      "$LIBC_ABORT_PROBE_ELF" "$LIBC_THREAD_CONTEXT_ELF"; do
    if [ ! -f "$libc_probe" ]; then
      printf 'error: missing libc probe: %s\n' "$libc_probe" >&2
      exit 1
    fi
  done
  set -- "$@" "/bin/c99-runtime-smoke=$LIBC_TEST_ELF" \
    "/bin/c99-main-void=$LIBC_MAIN_VOID_ELF" \
    "/bin/c99-exit-probe=$LIBC_EXIT_PROBE_ELF" \
    "/bin/c99-abort-probe=$LIBC_ABORT_PROBE_ELF" \
    "/bin/c99-thread-context=$LIBC_THREAD_CONTEXT_ELF"
fi
