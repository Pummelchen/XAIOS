#!/bin/sh
# How long qemu-nvme-gate actually takes where nothing is accelerated.
#
# B-72: the gate's budget in qemu-core-os-rc is 300s, tripled on CI, and it now
# uses all 900 of them. That is a consequence of B-68 -- its RISC-V legs used to
# fail in under a second on a missing filesystem and now boot for real -- so the
# budget was set when a third of the work never happened.
#
# The number that replaces it should be measured. On the Mac this gate takes
# 105-107 seconds, but one of its four guests runs on hardware virtualisation
# there and none of them do on the runner, so that figure cannot be scaled into
# a useful answer. Here nothing is accelerated, which is the runner's condition
# if not its exact speed.
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
for a in aarch64 x86_64 riscv64; do
  printf '  %s: %s\n' "$a" "$(qemu-system-$a --version 2>/dev/null | head -1)"
done

echo "=== building what the gate needs (not counted in the measurement) ==="
make image-qemu-test image-x86_64-qemu-test riscv64 > /tmp/build.log 2>&1 \
  || { echo "build failed"; tail -12 /tmp/build.log; exit 1; }
echo "  built"

echo "=== the gate itself ==="
start=$(date +%s)
python3 ./tests/scripts/qemu-nvme-gate.py > /tmp/nvme.log 2>&1
status=$?
echo "qemu-nvme-gate: exit=$status elapsed=$(( $(date +%s) - start ))s"
tail -6 /tmp/nvme.log | cut -c1-160
