#!/bin/sh
# The RISC-V release image, booted on the Linux CI runs on.
#
# The shipped RISC-V ISO boots on macOS -- build 6 was cut with this gate green
# -- and fails on the runner with none of its three markers. That is the same
# divide as every other defect in this stretch: invisible here, immediate
# there. This reproduces it locally instead of one push at a time.
#
# Unlike the boot-media gates, this one goes through UEFI: the image carries
# BOOTRISCV64.EFI and the firmware comes from qemu-efi-riscv64.
set -u
cd /work
git config --global --add safe.directory /work 2>/dev/null
if [ ! -d .git ]; then
  git init -q .
  git config --global user.email parity@local
  git config --global user.name parity
  git add -A >/dev/null 2>&1
  git commit -qm "linux parity" >/dev/null 2>&1
fi
[ -n "${XAIOS_PICOLIBC_REVISION_OVERRIDE:-}" ] || {
  echo "set XAIOS_PICOLIBC_REVISION_OVERRIDE" >&2; exit 2; }
export XAIOS_PICOLIBC_REVISION_OVERRIDE

echo "=== host ==="
echo "  qemu-system-riscv64: $(qemu-system-riscv64 --version | head -1)"
echo "  EDK2 RISC-V firmware: $(ls /usr/share/qemu-efi-riscv64/ 2>/dev/null | tr '\n' ' ')"

echo "=== building the RISC-V release image ==="
make release-image-riscv64 > /tmp/img.log 2>&1 \
  || { echo "image build failed"; tail -15 /tmp/img.log; exit 1; }
tail -3 /tmp/img.log

echo "=== booting it ==="
XAIOS_RELEASE_ONLY=qemu-riscv64 XAIOS_RELEASE_QEMU_TIMEOUT=600 \
  python3 ./tests/scripts/release-image-gate.py > /tmp/gate.log 2>&1
echo "release-image-gate (qemu-riscv64 only): exit=$?"
tail -20 /tmp/gate.log | cut -c1-150

echo "=== what the guest actually printed ==="
for f in build/release-qemu-riscv64.log; do
  [ -f "$f" ] && { echo "--- $f ---"; tail -40 "$f" | cut -c1-150; }
done
