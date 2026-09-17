# Sourced by scripts/build-image.sh; not a standalone script.
#
# The kernel compiler and linker flags: the baseline KERNEL_CFLAGS, the
# per-architecture additions, every XAIOS_* feature switch, and the build
# identity (BUILD_REVISION, BUILD_NUMBER, BUILD_IDENTIFIER) that
# compile_kernel stamps into each object. Runs in the caller's shell, so
# the variables it sets are still set when the kernel is compiled.

printf '%s\n' "Building $TARGET_ARCH kernel ELF..."
KERNEL_CFLAGS="
  --target=$TARGET_TRIPLE
  -std=c99
  -ffreestanding
  -fno-stack-protector
  -fno-builtin
  -fno-pic
  -fno-pie
  -Os
  -Wall
  -Wextra
  -Werror
"
# Deny the compiler FP/SIMD registers in kernel code.
#
# Without this it emits q-register loads and stores for ordinary struct
# copies, including in the device drivers, which is wrong twice over. The
# kernel does not save FP/SIMD state across exceptions, so a handler that
# touches those registers can corrupt whatever owned them. And a SIMD access
# to device memory reports no instruction syndrome to a hypervisor, which is
# why booting under Apple's HVF aborted QEMU inside the xHCI and GIC MMIO
# paths: both objects carried SIMD stores the compiler chose on its own.
#
# The few files that use SIMD deliberately are built with compile_kernel_simd
# and manage the register state themselves.
KERNEL_NO_SIMD_CFLAGS=""
# Whether this kernel can be loaded anywhere, or must land where it was linked.
#
# AArch64 builds position-independent: it emits nothing but R_AARCH64_RELATIVE
# relocations, which the UEFI loader applies after choosing an address. That is
# what lets one image boot on machines whose memory starts in three different
# places and at any size -- a fixed 0x90000000 is simply absent on a QEMU guest
# with a gibibyte, and on Virtualization.framework until it has enough memory.
#
# x86_64 stays fixed-address. Its code model emits R_X86_64_32 relocations that
# cannot appear in a position-independent link at all, and it does not need to
# move: it already boots at every size tested. The loader accepts both, and
# applies no bias to a fixed-address kernel.
KERNEL_LDFLAGS=""
if [ "$TARGET_ARCH" = aarch64 ]; then
  KERNEL_CFLAGS="$KERNEL_CFLAGS -fpie"
  KERNEL_LDFLAGS="-pie -z notext --no-dynamic-linker"
  KERNEL_NO_SIMD_CFLAGS="-mgeneral-regs-only"
  # No -march bump here. Every atomic therefore compiles to a load-exclusive
  # and store-exclusive pair rather than an LSE LDADD or CAS. LSE is the better
  # instruction selection on paper -- one instruction instead of two, and no
  # retry loop -- but it needs ARMv8.1, and QEMU's default aarch64 CPU model is
  # ARMv8.0: LDADD does not decode there and the kernel takes an undefined
  # instruction before it finishes booting. That is the platform every gate
  # runs on, so the baseline stays at ARMv8.0. Raising it means giving QEMU an
  # explicit -cpu with LSE across every gate first.
fi
if [ "$TARGET_ARCH" = x86_64 ]; then
  KERNEL_CFLAGS="$KERNEL_CFLAGS -mno-red-zone -DXAIOS_X86_COMMON_RUNTIME=1"
fi
# The stress app soaks for fifteen seconds by default, so it runs only when
# asked for rather than in every test-apps boot.
case "${XAIOS_STRESS_TEST:-0}" in
  0) ;;
  1) KERNEL_CFLAGS="$KERNEL_CFLAGS -DXAIOS_STRESS_TEST=1" ;;
  *)
    printf '%s\n' "error: XAIOS_STRESS_TEST must be 0 or 1" >&2
    exit 2
    ;;
esac

# The cluster data plane test dials a peer, so it is built into the image only
# when something is going to answer. See kmain for what an unanswered dial
# costs a gate that counts packets.
case "${XAIOS_CLUSTER_TEST:-0}" in
  0) ;;
  1) KERNEL_CFLAGS="$KERNEL_CFLAGS -DXAIOS_CLUSTER_TEST=1" ;;
  *)
    printf '%s\n' "error: XAIOS_CLUSTER_TEST must be 0 or 1" >&2
    exit 1
    ;;
esac

# One log line per block write and per flush, so a gate can check that the
# ordering volatile-cache safety depends on is actually being issued. Behind a
# flag because an ordinary boot should not pay a klog per request.
case "${XAIOS_IO_TRACE:-0}" in
  0) ;;
  1) KERNEL_CFLAGS="$KERNEL_CFLAGS -DXAIOS_IO_TRACE=1" ;;
  *)
    printf '%s\n' "error: XAIOS_IO_TRACE must be 0 or 1" >&2
    exit 1
    ;;
esac

# Ingest a staged xaiFS package continuously so the crash gate has something
# to interrupt. Behind a flag because it never returns on its own.
case "${XAIOS_CRASH_WRITER:-0}" in
  0) ;;
  1) KERNEL_CFLAGS="$KERNEL_CFLAGS -DXAIOS_CRASH_WRITER=1" ;;
  *)
    printf '%s\n' "error: XAIOS_CRASH_WRITER must be 0 or 1" >&2
    exit 1
    ;;
esac

# Install onto the scratch disk at boot, unasked. Behind a flag because it
# writes a partition table and a filesystem onto whatever is in slot 5 with
# nobody confirming it -- correct for a gate that attaches a scratch disk,
# wrong for an image anyone boots on a machine of their own.
case "${XAIOS_INSTALL_SELF_TEST:-0}" in
  0) ;;
  1) KERNEL_CFLAGS="$KERNEL_CFLAGS -DXAIOS_INSTALL_SELF_TEST=1" ;;
  *)
    printf '%s\n' "error: XAIOS_INSTALL_SELF_TEST must be 0 or 1" >&2
    exit 1
    ;;
esac

# Storage throughput measurement. Behind a flag because it writes to a device
# and takes time, and an ordinary boot should do neither.
case "${XAIOS_STORAGE_BENCH:-0}" in
  0) ;;
  1) KERNEL_CFLAGS="$KERNEL_CFLAGS -DXAIOS_STORAGE_BENCH=1" ;;
  *)
    printf '%s\n' "error: XAIOS_STORAGE_BENCH must be 0 or 1" >&2
    exit 1
    ;;
esac

case "${XAIOS_FAULT_TEST:-}" in
  "") ;;
  page) KERNEL_CFLAGS="$KERNEL_CFLAGS -DXAIOS_FAULT_TEST_PAGE=1" ;;
  ro) KERNEL_CFLAGS="$KERNEL_CFLAGS -DXAIOS_FAULT_TEST_RO=1" ;;
  nx) KERNEL_CFLAGS="$KERNEL_CFLAGS -DXAIOS_FAULT_TEST_NX=1" ;;
  *)
    printf '%s\n' "error: unsupported XAIOS_FAULT_TEST=${XAIOS_FAULT_TEST}" >&2
    exit 2
    ;;
esac

case "${XAIOS_PANIC_SELFTEST:-}" in
  "") ;;
  1)
    KERNEL_CFLAGS="$KERNEL_CFLAGS -DXAIOS_PANIC_SELFTEST=1"
    ;;
  *)
    printf '%s\n' \
      "error: XAIOS_PANIC_SELFTEST must be unset or 1, got ${XAIOS_PANIC_SELFTEST}" >&2
    exit 2
    ;;
esac

case "${XAIOS_STORAGE_CRASH_POINT:-}" in
  "") ;;
  system-backup-flushed)
    KERNEL_CFLAGS="$KERNEL_CFLAGS -DXAIOS_STORAGE_CRASH_AFTER_SYSTEM_BACKUP=1"
    ;;
  system-primary-written)
    KERNEL_CFLAGS="$KERNEL_CFLAGS -DXAIOS_STORAGE_CRASH_AFTER_SYSTEM_PRIMARY=1"
    ;;
  *)
    printf '%s\n' \
      "error: unsupported XAIOS_STORAGE_CRASH_POINT=${XAIOS_STORAGE_CRASH_POINT}" >&2
    exit 2
    ;;
esac

if [ -n "${XAIOS_BUILD_REVISION_OVERRIDE:-}" ]; then
  if ! printf '%s' "$XAIOS_BUILD_REVISION_OVERRIDE" | grep -Eq '^[0-9a-f]{40}$'; then
    printf '%s\n' 'error: XAIOS_BUILD_REVISION_OVERRIDE must be 40 lowercase hex characters' >&2
    exit 2
  fi
  BUILD_REVISION="$XAIOS_BUILD_REVISION_OVERRIDE"
else
  BUILD_REVISION="$(git -C "$ROOT_DIR" rev-parse --verify HEAD 2>/dev/null || printf '%s' unknown)"
fi
# What this build is, single-sourced from BUILD_NUMBER at the repository root.
#
# XAIOS is identified by build number, not by a MAJOR.MINOR.PATCH version.
# There was one, 0.1.0, and it was invented rather than earned: nothing had
# been released, so the three numbers encoded no history and promised
# compatibility rules nobody had agreed. A build number says the one true
# thing -- which build this is -- and says it without implying the rest.
#
# The file is not called BUILD because this repository is developed on a
# case-insensitive filesystem, where that name is already the build directory.
BUILD_NUMBER="$(tr -d ' \n' < "$ROOT_DIR/BUILD_NUMBER" 2>/dev/null || printf '%s' 0)"
if ! printf '%s' "$BUILD_NUMBER" | grep -Eq '^[0-9]+$'; then
  printf '%s\n' "error: BUILD_NUMBER must be a whole number, found '$BUILD_NUMBER'" >&2
  exit 1
fi

BUILD_IDENTIFIER="xaios-admin-control"
if [ -n "${XAIOS_BUILD_REVISION_OVERRIDE:-}" ] ||
   ! git -C "$ROOT_DIR" diff-index --quiet HEAD -- 2>/dev/null ||
   [ -n "$(git -C "$ROOT_DIR" ls-files --others --exclude-standard 2>/dev/null)" ]; then
  BUILD_IDENTIFIER="${BUILD_IDENTIFIER}-dirty"
fi
KERNEL_CFLAGS="$KERNEL_CFLAGS $PASSWORD_AUTH_CFLAG -DXAIOS_BOOT_TEST_APPS=$BOOT_TEST_APPS -DXAIOS_BOOT_VERBOSE=$BOOT_VERBOSE -DXAIOS_WT_HANDSHAKE_TEST=${XAIOS_WT_HANDSHAKE_TEST:-0} -DXAIOS_FAILURE_TEST_APP=$FAILURE_TEST_APP -DXAIOS_LIBC_TEST=$LIBC_TEST -DXAIOS_BUILD_NUMBER=$BUILD_NUMBER"

# Extra flags for the kernel only, appended last so they win.
#
# This exists so a tunable can be rebuilt at a different setting and measured,
# rather than argued about: the storage benchmark reconstructs the old
# one-sector transfer path with -DVIRTIO_BLK_MAX_TRANSFER=512ULL and compares
# against the same tree. Nothing in CI sets it; a build with it set is not the
# build that ships.
if [ -n "${XAIOS_KERNEL_CFLAGS_EXTRA:-}" ]; then
  KERNEL_CFLAGS="$KERNEL_CFLAGS $XAIOS_KERNEL_CFLAGS_EXTRA"
  printf '%s\n' "Kernel built with extra flags: $XAIOS_KERNEL_CFLAGS_EXTRA"
fi
