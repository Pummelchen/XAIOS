#!/bin/sh
# What the AIA board costs where nothing is accelerated.
#
# B-73: qemu-nvme-gate's riscv64-aia row spent its whole 1440-second deadline on
# the runner and reached 50% of a boot. Plain riscv64 passes on the same runner,
# and the whole four-row gate takes 107 seconds on the Mac, so the cost is the
# AIA interrupt controller under interpretation rather than RISC-V as such.
#
# This row is the AIA board's only coverage anywhere in CI, so the question is
# how much time it needs and not whether to keep it. Unlike the x86-64 rows,
# this one can be measured here: it is RISC-V only, and this container has no
# acceleration for RISC-V any more than the runner does.
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
echo "  arch: $(uname -m)  cpus: $(nproc)"
echo "  $(qemu-system-riscv64 --version | head -1)"

echo "=== building ==="
./scripts/build-riscv64.sh > /tmp/b1.log 2>&1 || { tail -8 /tmp/b1.log; exit 1; }
./scripts/build-riscv64-image.sh > /tmp/b2.log 2>&1 || { tail -8 /tmp/b2.log; exit 1; }
echo "  built"

# Each row separately, so the AIA board's cost is its own number and not a
# share of a total. The gate's per-row deadline is generous here on purpose:
# the point is to find what it needs, not to reproduce it failing.
for row in riscv64 riscv64-aia; do
  echo "=== $row ==="
  start=$(date +%s)
  XAIOS_QEMU_NVME_TIMEOUT=1200 python3 ./tests/scripts/qemu-nvme-gate.py --arch "$row" \
    > "/tmp/$row.log" 2>&1
  echo "  exit=$? elapsed=$(( $(date +%s) - start ))s"
  tail -3 "/tmp/$row.log" | cut -c1-150
done
