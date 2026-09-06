#!/bin/sh
# Build the RISC-V rv64gc bring-up kernel for the QEMU `virt` board.
#
# Separate from build-image.sh rather than a third case inside it, and the
# reason is worth stating: that script builds a UEFI loader and a FAT boot
# image, because AArch64 and x86-64 are both booted by UEFI firmware. RISC-V
# on this board is not. OpenSBI hands control straight to an ELF at a fixed
# address, so there is no loader to build, no EFI executable, and no boot
# medium -- adding this to that script would mean threading "skip all of it"
# through every step of a pipeline whose whole subject is those steps.
#
# When this port grows a UEFI path it should move; while it does not have
# one, pretending it fits is the more confusing arrangement.
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
BUILD_DIR="$ROOT_DIR/build/kernel-riscv64"
KERNEL_ELF="$BUILD_DIR/kernel.elf"

CC="${XAIOS_RISCV64_CC:-clang}"
LD="${XAIOS_RISCV64_LD:-ld.lld}"

for tool in "$CC" "$LD"; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf '%s\n' "error: missing required tool: $tool" >&2
    exit 2
  fi
done

mkdir -p "$BUILD_DIR"

# -mno-relax because linker relaxation needs a global pointer this kernel does
# not set up; medany because the code has to run at 0x80200000 rather than in
# the low two gibibytes medlow assumes.
# Two flag sets, on purpose.
#
# Architecture code written for this port is held to -pedantic, because it is
# new and there is no reason to start it below the bar. Shared kernel code is
# not: it is compiled here with the same warnings AArch64 and x86-64 use, and
# imposing a stricter standard on it from this file would mean editing a
# hundred files that three architectures already agree on -- to satisfy a flag
# only one of them passes. The shared code's standard is the shared code's to
# set.
BASE_CFLAGS="-std=c99 -Wall -Wextra -Werror -ffreestanding \
-fno-stack-protector -mno-relax -march=rv64gc -mabi=lp64d -mcmodel=medany \
--target=riscv64-unknown-elf -I$ROOT_DIR/kernel/include \
-I$ROOT_DIR/engine/include -I$ROOT_DIR/engine/src \
-I$ROOT_DIR/userspace/include -I$ROOT_DIR/userspace/sshd \
-I$ROOT_DIR/third_party/bearssl/inc"
# The defines the shared kernel expects from a build. Verbose defaults on
# here, unlike the other architectures: this port has no login to reach yet,
# so the console log is the only way to see how far it got, and a silent boot
# would be indistinguishable from a hung one.
BOOT_VERBOSE="${XAIOS_BOOT_VERBOSE:-1}"
# The diagnostic applications default on here, unlike the other builders,
# because the RISC-V gates are boot-test gates. The hosted C99 probes follow
# that switch rather than defaulting on by themselves: two of them exit
# non-zero on purpose, and a release image that runs them at boot reports a
# brand-new machine as having two failed tasks. The release configuration --
# XAIOS_BOOT_TEST_APPS=0 -- is the other builders' `make image`, probes off.
BOOT_TEST_APPS="${XAIOS_BOOT_TEST_APPS:-1}"
LIBC_TEST="${XAIOS_LIBC_TEST:-$BOOT_TEST_APPS}"
FAILURE_TEST_APP="${XAIOS_FAILURE_TEST_APP:-0}"
# The two diagnostic builds the durability gates need. This builder did not
# offer them, so those gates could not run on this architecture at all -- not
# because the kernel could not do it, but because there was no way to ask.
# Validated rather than passed through: a typo that silently built without
# tracing would make a gate report a clean run it never watched.
IO_TRACE="${XAIOS_IO_TRACE:-0}"
CRASH_WRITER="${XAIOS_CRASH_WRITER:-0}"
case "$IO_TRACE" in
  0|1) ;;
  *) printf '%s\n' "error: XAIOS_IO_TRACE must be 0 or 1" >&2; exit 2 ;;
esac
case "$CRASH_WRITER" in
  0|1) ;;
  *) printf '%s\n' "error: XAIOS_CRASH_WRITER must be 0 or 1" >&2; exit 2 ;;
esac
# The controlled fault the fault matrix boots into. Shared kernel code picks
# the fault; what differs per architecture is only how the trap is reported,
# which is why the gate asserts a different class name here.
case "${XAIOS_FAULT_TEST:-}" in
  "") ;;
  page) BASE_CFLAGS="$BASE_CFLAGS -DXAIOS_FAULT_TEST_PAGE=1" ;;
  ro) BASE_CFLAGS="$BASE_CFLAGS -DXAIOS_FAULT_TEST_RO=1" ;;
  nx) BASE_CFLAGS="$BASE_CFLAGS -DXAIOS_FAULT_TEST_NX=1" ;;
  *)
    printf '%s\n' \
      "error: unsupported XAIOS_FAULT_TEST=${XAIOS_FAULT_TEST}" >&2
    exit 2 ;;
esac

# The stress and measurement applications. perfbench is the one that matters
# to a gate: it reports what an operation costs and asserts nothing, so it
# runs where the stress app runs and nowhere else.
STRESS_TEST="${XAIOS_STRESS_TEST:-0}"
case "$STRESS_TEST" in
  0|1) ;;
  *) printf '%s\n' "error: XAIOS_STRESS_TEST must be 0 or 1" >&2; exit 2 ;;
esac
BASE_CFLAGS="$BASE_CFLAGS -DXAIOS_STRESS_TEST=$STRESS_TEST"

# Whether this kernel installs itself onto the blank disk in front of it at
# boot. Behind a switch on every architecture for the same reason: an image
# that partitions a disk unasked has no business on anybody's machine.
case "${XAIOS_INSTALL_SELF_TEST:-0}" in
  0) ;;
  1) BASE_CFLAGS="$BASE_CFLAGS -DXAIOS_INSTALL_SELF_TEST=1" ;;
  *) printf '%s\n' "error: XAIOS_INSTALL_SELF_TEST must be 0 or 1" >&2
     exit 2 ;;
esac

# Whether this kernel launches the cluster data-plane test at boot. Behind a
# switch on every architecture for the same reason: the test dials a peer, and
# an unanswered dial costs a gate that counts packets.
case "${XAIOS_CLUSTER_TEST:-0}" in
  0) ;;
  1) BASE_CFLAGS="$BASE_CFLAGS -DXAIOS_CLUSTER_TEST=1" ;;
  *) printf '%s\n' "error: XAIOS_CLUSTER_TEST must be 0 or 1" >&2; exit 2 ;;
esac

# The self-measurement the storage benchmark reads. Same shared kernel code;
# this builder simply had no way to turn it on.
STORAGE_BENCH="${XAIOS_STORAGE_BENCH:-0}"
case "$STORAGE_BENCH" in
  0|1) ;;
  *) printf '%s\n' "error: XAIOS_STORAGE_BENCH must be 0 or 1" >&2; exit 2 ;;
esac
BASE_CFLAGS="$BASE_CFLAGS -DXAIOS_STORAGE_BENCH=$STORAGE_BENCH"

# The injected power-loss points the metadata durability gate crashes on.
# The code they compile in lives in kernel/runtime/system_slot.c, which this
# architecture links like the others; only the switch was missing.
case "${XAIOS_STORAGE_CRASH_POINT:-}" in
  "") ;;
  system-backup-flushed)
    BASE_CFLAGS="$BASE_CFLAGS -DXAIOS_STORAGE_CRASH_AFTER_SYSTEM_BACKUP=1" ;;
  system-primary-written)
    BASE_CFLAGS="$BASE_CFLAGS -DXAIOS_STORAGE_CRASH_AFTER_SYSTEM_PRIMARY=1" ;;
  *)
    printf '%s\n' \
      "error: unsupported XAIOS_STORAGE_CRASH_POINT=${XAIOS_STORAGE_CRASH_POINT}" >&2
    exit 2 ;;
esac
# Which build this is, and which commit it came from, exactly as the other
# builder derives them.
#
# The number was hardcoded here, and had been since this port was written: it
# said 4 while BUILD_NUMBER said 5, so a RISC-V machine reported a build it
# was not. The revision was not passed at all, so `version` on a RISC-V guest
# answered "unknown" where the other two answer a commit -- which is what
# porting the external client suite to this machine found.
BUILD_NUMBER="$(tr -d ' \n' < "$ROOT_DIR/BUILD_NUMBER" 2>/dev/null || printf '%s' 0)"
if ! printf '%s' "$BUILD_NUMBER" | grep -Eq '^[0-9]+$'; then
  printf '%s\n' \
    "error: BUILD_NUMBER must be a whole number, found '$BUILD_NUMBER'" >&2
  exit 1
fi
if [ -n "${XAIOS_BUILD_REVISION_OVERRIDE:-}" ]; then
  if ! printf '%s' "$XAIOS_BUILD_REVISION_OVERRIDE" |
       grep -Eq '^[0-9a-f]{40}$'; then
    printf '%s\n' \
      'error: XAIOS_BUILD_REVISION_OVERRIDE must be 40 lowercase hex characters' >&2
    exit 2
  fi
  BUILD_REVISION="$XAIOS_BUILD_REVISION_OVERRIDE"
else
  BUILD_REVISION="$(git -C "$ROOT_DIR" rev-parse --verify HEAD 2>/dev/null ||
    printf '%s' unknown)"
fi
# Development or release, which the version response discloses. Same values
# and same default as the other builder; the image builder validates it too,
# because the credential policy depends on it.
KERNEL_BUILD_MODE="${XAIOS_BUILD_MODE:-development}"
case "$KERNEL_BUILD_MODE" in
  development|release) ;;
  *)
    printf '%s\n' "error: XAIOS_BUILD_MODE must be development or release" >&2
    exit 2 ;;
esac
BUILD_IDENTIFIER="xaios-admin-control"
if [ -n "${XAIOS_BUILD_REVISION_OVERRIDE:-}" ] ||
   ! git -C "$ROOT_DIR" diff-index --quiet HEAD -- 2>/dev/null ||
   [ -n "$(git -C "$ROOT_DIR" ls-files --others --exclude-standard 2>/dev/null)" ]; then
  BUILD_IDENTIFIER="${BUILD_IDENTIFIER}-dirty"
fi
BASE_CFLAGS="$BASE_CFLAGS -DXAIOS_BOOT_VERBOSE=$BOOT_VERBOSE \
-DXAIOS_BOOT_TEST_APPS=$BOOT_TEST_APPS \
-DXAIOS_FAILURE_TEST_APP=$FAILURE_TEST_APP -DXAIOS_LIBC_TEST=$LIBC_TEST \
-DXAIOS_PASSWORD_AUTH_AVAILABLE=${XAIOS_PASSWORD_AUTH_AVAILABLE:-1} \
-DXAIOS_IO_TRACE=$IO_TRACE -DXAIOS_CRASH_WRITER=$CRASH_WRITER \
-DXAIOS_BUILD_IDENTIFIER=\"$BUILD_IDENTIFIER\" \
-DXAIOS_BUILD_MODE=\"$KERNEL_BUILD_MODE\" \
-DXAIOS_BUILD_REVISION=\"$BUILD_REVISION\" \
-DXAIOS_BUILD_NUMBER=$BUILD_NUMBER"
CFLAGS="$BASE_CFLAGS -pedantic"

OBJECTS=""
compile_shared() {
  source_path="$1"
  # Named from the path, not the basename.
  #
  # Two different sha256.c files exist -- kernel/runtime/ and engine/src/ --
  # and naming objects after the basename made the second silently overwrite
  # the first. The link then failed on duplicate symbols from what looked
  # like one file, which is a confusing way to be told the build is losing
  # objects.
  relative="${source_path#"$ROOT_DIR"/}"
  object_path="$BUILD_DIR/$(printf '%s' "$relative" | tr '/.' '__').o"
  # shellcheck disable=SC2086
  $CC $BASE_CFLAGS -c "$source_path" -o "$object_path"
  OBJECTS="$OBJECTS $object_path"
}

compile() {
  source_path="$1"
  object_path="$BUILD_DIR/$(basename "${source_path%.*}").o"
  # shellcheck disable=SC2086
  $CC $CFLAGS -c "$source_path" -o "$object_path"
  OBJECTS="$OBJECTS $object_path"
}

compile "$ROOT_DIR/kernel/arch/riscv64/entry.S"
compile "$ROOT_DIR/kernel/arch/riscv64/sbi.c"
compile "$ROOT_DIR/kernel/arch/riscv64/fdt.c"
compile "$ROOT_DIR/kernel/arch/riscv64/boot_info.c"
compile "$ROOT_DIR/kernel/arch/riscv64/mmu.c"
compile "$ROOT_DIR/kernel/arch/riscv64/smp.c"
compile "$ROOT_DIR/kernel/arch/riscv64/timer.c"
compile "$ROOT_DIR/kernel/arch/riscv64/cpu_features.c"
compile "$ROOT_DIR/kernel/arch/riscv64/exception.c"
compile "$ROOT_DIR/kernel/arch/riscv64/irq.c"
compile "$ROOT_DIR/kernel/arch/riscv64/platform.c"
compile "$ROOT_DIR/kernel/arch/riscv64/isa_self_test.c"
compile "$ROOT_DIR/kernel/arch/riscv64/boot.c"

# Every shared kernel source, not a chosen subset.
#
# The subset was how this started, and it stopped working the moment klog was
# used: shared code depends on shared code, and picking files one at a time
# turns into hand-resolving a dependency graph the linker resolves for free.
# All 102 of these compile for RISC-V, so the honest thing is to build them
# all and let what is still undefined be the actual architecture gap rather
# than a curated list of what has been tried.
# virtio_transport.c is compiled twice by the real build -- once as the MMIO
# backend and once, from a different file, as the PCI one -- with a dispatcher
# choosing between them. Globbing it plainly produced a third copy that
# collided with both. Built the same way here, because this board offers
# virtio on both transports exactly as AArch64 does.
for source in $(find "$ROOT_DIR/kernel" -name '*.c' ! -path '*/arch/*' \
    ! -name 'virtio_transport.c' ! -name 'virtio_transport_pci.c' | sort); do
  compile_shared "$source"
done
# Each backend needs its own define, and both need to stay out of the glob:
# compiled plainly they each provide the same MMIO accessors and collide with
# the other.
$CC $BASE_CFLAGS -DXAIOS_VIRTIO_MMIO_BACKEND=1 \
  -c "$ROOT_DIR/kernel/dev/virtio/virtio_transport.c" \
  -o "$BUILD_DIR/virtio_transport_mmio.o"
$CC $BASE_CFLAGS -DXAIOS_VIRTIO_PCI_BACKEND=1 \
  -c "$ROOT_DIR/kernel/dev/virtio/virtio_transport_pci.c" \
  -o "$BUILD_DIR/virtio_transport_pci.o"
OBJECTS="$OBJECTS $BUILD_DIR/virtio_transport_mmio.o \
  $BUILD_DIR/virtio_transport_pci.o"
# Only the engine sources the kernel actually needs symbols from. sha256 and
# model_v2 are reached through the kernel's own copies, and adding them here
# produced duplicates rather than more capability.
# The same non-kernel sources the AArch64 and x86-64 kernels link: the engine
# pieces the kernel calls into, the xaiFS reader and writer, and the crypto
# the update and SSH paths verify signatures with.
for source in "$ROOT_DIR/engine/src/architecture.c" \
    "$ROOT_DIR/engine/src/backend_scalar.c" \
    "$ROOT_DIR/engine/src/packed.c" \
    "$ROOT_DIR/engine/src/sha256.c" \
    "$ROOT_DIR/engine/src/sha256_accel.c" \
    "$ROOT_DIR/engine/src/backend_neon.c" \
    "$ROOT_DIR/engine/src/backend_avx2.c" \
    "$ROOT_DIR/engine/src/xai_fs.c" \
    "$ROOT_DIR/engine/src/xai_fs_writer.c" \
    "$ROOT_DIR/userspace/sshd/ssh_crypto.c" \
    "$ROOT_DIR/userspace/sshd/tweetnacl_subset.c"; do
  compile_shared "$source"
done

BEARSSL="$ROOT_DIR/build/bearssl/riscv64/libbearssl-xapt.a"
[ -f "$BEARSSL" ] || "$ROOT_DIR/scripts/build-bearssl.sh" riscv64

# shellcheck disable=SC2086
$LD -T "$ROOT_DIR/kernel/arch/riscv64/linker.ld" -o "$KERNEL_ELF" $OBJECTS \
  "$BEARSSL"

printf '%s\n' "Built RISC-V bring-up kernel: $KERNEL_ELF"
