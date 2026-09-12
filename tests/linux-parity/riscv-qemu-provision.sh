#!/bin/sh
# The RISC-V Bring-up job's new provisioning step, inside the parity image.
#
# noble ships QEMU 8.2.2, which models five of the twelve CPU tiers the
# contract lists, so CI builds a newer one. That build has only ever run on a
# Mac. Every defect that kept CI red for nine days was invisible there and
# immediate here, and a from-source QEMU build -- configure probing for
# libraries, a linker, a pkg-config -- is exactly the shape of thing that
# differs between the two. So it runs here before it runs on a runner.
#
# This is slow on a cold cache: it clones QEMU and compiles one target.
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

echo "=== the emulator noble actually ships ==="
qemu-system-riscv64 --version | head -1
echo "  models: $(qemu-system-riscv64 -cpu help 2>/dev/null | \
  sed 's/^[[:space:]]*//; s/[[:space:]].*$//' | grep -cv '^Available')"

echo "=== provisioning ==="
XAIOS_QEMU_RISCV64_ROOT=/tmp/xaios-qemu-riscv64 \
  ./tests/scripts/provision-qemu-riscv64.sh || {
    echo "provision failed"; exit 1; }

pin=$(sed -n 's/^QEMU_COMMIT="\${XAIOS_QEMU_RISCV64_COMMIT:-\([0-9a-f]*\)}"/\1/p' \
      tests/scripts/provision-qemu-riscv64.sh | head -1)
QEMU_SYSTEM_RISCV64=/tmp/xaios-qemu-riscv64/$pin/build/qemu-system-riscv64
export QEMU_SYSTEM_RISCV64
echo "  provisioned: $("$QEMU_SYSTEM_RISCV64" --version | head -1)"

echo "=== building XAIOS ==="
XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64.sh > /tmp/1.log 2>&1 \
  || { echo "build failed"; tail -8 /tmp/1.log; exit 1; }
XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-image.sh > /tmp/2.log 2>&1 \
  || { echo "image failed"; tail -8 /tmp/2.log; exit 1; }
echo "  built"

echo "=== tier matrix against the provisioned emulator ==="
python3 ./tests/scripts/qemu-cpu-matrix.py --arch riscv64 > /tmp/4.log 2>&1
echo "qemu-cpu-matrix --arch riscv64: exit=$?"
tail -25 /tmp/4.log | cut -c1-150
