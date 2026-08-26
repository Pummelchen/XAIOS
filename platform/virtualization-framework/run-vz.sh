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
cp "$BUILD/xaios-model-volume.img" "$VZ/vz-model.img"
cp "$BUILD/xaios-system.img"       "$VZ/vz-system.img"
cp "$BUILD/xaios-system.img"       "$VZ/vz-system2.img"
# Not built by the image build; created empty once and kept.
[ -f "$VZ/vz-storage-admin.img" ] || \
  dd if=/dev/zero of="$VZ/vz-storage-admin.img" bs=512 count=16384 status=none

# Below roughly 3.5 GiB this platform boots to nothing at all: the harness
# starts, the guest produces no serial output whatever, and there is no error
# to read. Measured, not guessed -- 3584 MiB boots, 3328 MiB does not, and the
# RAM arithmetic does not explain the difference (see B-06). Refuse the range
# rather than hand someone a black screen, because a silent guest is the
# hardest thing to diagnose in front of an audience, and set XAIOS_VZ_MEMORY_MIB
# deliberately if you are investigating that floor.
VZ_MEMORY_MIB="${XAIOS_VZ_MEMORY_MIB:-4096}"
if [ "$VZ_MEMORY_MIB" -lt 3584 ] && [ "${XAIOS_VZ_ALLOW_LOW_MEMORY:-0}" != "1" ]; then
  printf '%s\n' \
    "error: ${VZ_MEMORY_MIB} MiB is below the 3584 MiB this platform is known to boot at." \
    "       Virtualization.framework starts and the guest prints nothing at all below" \
    "       that; it is tracked as B-06 and is not a fault in your invocation." \
    "       Set XAIOS_VZ_ALLOW_LOW_MEMORY=1 to try it anyway." >&2
  exit 1
fi

exec "$VZ/xaios-vz" "$VZ/run-disk.img" "$VZ/vz-test.img" \
  "$VZ/vz-persistent.img" "$VZ/vz-model.img" "$VZ/vz-storage-admin.img" \
  "$VZ/vz-system.img" "$VZ/vz-system2.img" \
  --memory-mib "$VZ_MEMORY_MIB" --cpus "${XAIOS_VZ_CPUS:-4}" "$@"
