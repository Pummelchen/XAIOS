#!/bin/sh
# The hosted C99 libc gate's RISC-V leg, inside the parity image.
#
# B-66: qemu-libc-gate.py iterates three architectures and the job running it
# installed emulators for two. The RISC-V leg started a runner that exited 127
# saying the emulator was not found, and the gate reported a list of markers
# the guest had not printed -- about a guest that was never started.
#
# The fix is a package name, and the question a package name always raises is
# whether it is the right one and whether it is enough. This runs the leg on
# the Linux CI runs on, with exactly the emulator package the job installs and
# no UEFI firmware, which is what the gate's default boot mode should need.
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

echo "=== emulator and firmware present ==="
echo "  qemu-system-riscv64: $(command -v qemu-system-riscv64 || echo ABSENT)"
echo "  qemu-efi-riscv64 files: $(ls /usr/share/qemu-efi-riscv64 2>/dev/null | wc -l) (expected 0: this leg should not need UEFI)"

echo "=== running the RISC-V leg ==="
python3 ./tests/scripts/qemu-libc-gate.py --arch riscv64 > /tmp/libc.log 2>&1
echo "qemu-libc-gate --arch riscv64: exit=$?"
tail -25 /tmp/libc.log | cut -c1-150
