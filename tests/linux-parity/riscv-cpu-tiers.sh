#!/bin/sh
# The RISC-V Bring-up job's CPU-tier step, inside the parity image. This is the
# step that began failing once B-61 let the earlier ones through; it had never
# run before.
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

echo "=== clang $(clang --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1) ==="
XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64.sh > /tmp/1.log 2>&1 \
  || { echo "build failed"; tail -8 /tmp/1.log; exit 1; }
XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-image.sh > /tmp/2.log 2>&1 \
  || { echo "image failed"; tail -8 /tmp/2.log; exit 1; }
echo "  built"
python3 ./tests/scripts/qemu-cpu-matrix.py --arch riscv64 > /tmp/4.log 2>&1
echo "qemu-cpu-matrix --arch riscv64: exit=$?"
tail -20 /tmp/4.log | cut -c1-150
