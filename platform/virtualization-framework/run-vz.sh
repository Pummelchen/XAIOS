#!/bin/sh
# Boot XAIOS on Apple Virtualization.framework, by hand, without booting a
# stale kernel.
#
# The machine is handed several images: a boot disk carrying the ESP, and the
# data volumes -- test, persistent, model, storage-admin, and the two system
# slots. Only the boot disk is rebuilt by build-vz-disk.sh. The volumes are
# copies, and a copy made before the last build is a copy of the previous
# kernel; boot with one attached and the loader can bring up that kernel
# instead of the one just built. It prints the same banner and the same
# version, so nothing in the log says the code under test is not running.
#
# That cost a long debugging session: a change was built, verified present in
# the boot disk, and did not appear in the boot log, because a system volume
# four builds old was supplying the kernel. The gates never hit this -- both
# vz-gate and vz-stress-gate recopy every volume before each run -- so this
# script does the same thing for boots started by hand.
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
BUILD="$ROOT_DIR/build"
VZ="$BUILD/vz"

[ -x "$VZ/xaios-vz" ] || {
  printf 'missing: %s\nbuild and sign the harness first\n' "$VZ/xaios-vz" >&2
  exit 1
}

"$ROOT_DIR/platform/virtualization-framework/build-vz-disk.sh" >/dev/null
cp "$VZ/xaios-vz-disk.img" "$VZ/run-disk.img"

# Same list, same order, as the gates use.
cp "$BUILD/xaios-virtio-test.img"  "$VZ/vz-test.img"
cp "$BUILD/xaios-persistent.img"   "$VZ/vz-persistent.img"
cp "$BUILD/xaios-xaifs.img" "$VZ/vz-model.img"
cp "$BUILD/xaios-system.img"       "$VZ/vz-system.img"
cp "$BUILD/xaios-system.img"       "$VZ/vz-system2.img"
# Not built by the image build; created empty once and kept.
[ -f "$VZ/vz-storage-admin.img" ] || \
  dd if=/dev/zero of="$VZ/vz-storage-admin.img" bs=512 count=16384 status=none

# Memory is the caller's choice again. This used to refuse anything under
# 3584 MiB, because below that the guest produced no output whatever -- B-06.
# The cause was the same fixed kernel link address as B-05: the kernel was
# built to load at 0x90000000 and this platform has no memory there until it
# has enough of it. The kernel relocates now, so the floor is gone.
VZ_MEMORY_MIB="${XAIOS_VZ_MEMORY_MIB:-4096}"

exec "$VZ/xaios-vz" "$VZ/run-disk.img" "$VZ/vz-test.img" \
  "$VZ/vz-persistent.img" "$VZ/vz-model.img" "$VZ/vz-storage-admin.img" \
  "$VZ/vz-system.img" "$VZ/vz-system2.img" \
  --memory-mib "$VZ_MEMORY_MIB" --cpus "${XAIOS_VZ_CPUS:-4}" "$@"
