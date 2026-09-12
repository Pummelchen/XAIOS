#!/bin/sh
# The three qemu-core-os-rc sub-gates that fail on the runner, one at a time.
#
# B-68: the aggregate reports nvme exiting 2, fragmentation exiting 124 -- a
# timeout -- and memory_matrix exiting 2. Its two named markers each cover all
# three architectures at once ("passed on aarch64 4 msix, x86_64 4 msix,
# riscv64 1 polled"), so one architecture failing takes the marker with it and
# the aggregate cannot say which. Running them separately here is the cheapest
# way to find out what the aggregate cannot tell us.
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

echo "=== emulators ==="
for a in aarch64 x86_64 riscv64; do
  echo "  qemu-system-$a: $(command -v qemu-system-$a || echo ABSENT)"
done

for target in qemu-nvme-gate qemu-outbound-fragmentation-gate qemu-memory-matrix; do
  echo "=== $target ==="
  start=$(date +%s)
  make "$target" > "/tmp/$target.log" 2>&1
  status=$?
  echo "  exit=$status after $(( $(date +%s) - start ))s"
  # The tail, then anything that looks like a verdict anywhere in the log.
  tail -12 "/tmp/$target.log" | cut -c1-150
  echo "  --- lines naming an architecture or a refusal ---"
  grep -naiE "riscv|aarch64|x86_64|refus|denied|not found|no such" \
    "/tmp/$target.log" | tail -12 | cut -c1-150
done
