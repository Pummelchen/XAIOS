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

# This gate boots an x86-64 guest, so it needs an x86-64 userland, and an arm64
# container cannot build one -- picolibc's configure asks gcc for -m64 and an
# arm64 gcc has never heard of it. Saying so here is the difference between a
# refusal and four minutes ending in a linker error nobody reads.
#
# XAIOS_PARITY_PLATFORM=linux/amd64 gets an x86-64 container, and on an Apple
# Silicon Mac that is emulated: it would build, and every timing it produced
# would be slower than a real x86-64 runner and would predict nothing. So this
# refuses there too, and says which machine could answer.
if [ "$(uname -m)" != x86_64 ]; then
  printf '%s\n' \
    "nvme-budget: INCONCLUSIVE, and the fault is this container's, not the" \
    "  gate's: this is $(uname -m) and qemu-nvme-gate needs an x86-64 guest," \
    "  whose userland cannot be built here (picolibc asks gcc for -m64)." \
    "  XAIOS_PARITY_PLATFORM=linux/amd64 would build it under emulation and" \
    "  time something slower than any real runner, which is worse than no" \
    "  number. A budget for CI has to be measured on an x86-64 Linux host." >&2
  exit 1
fi
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
