#!/bin/sh
# The RISC-V Bring-up job, inside the parity image. Piped to `sh -s` rather than
# mounted: Docker Desktop does not share /private/tmp, and a -v of a path it
# cannot see silently creates a directory instead of failing.
set -u
cd /work

# The archive excludes .git, and the build stamps a commit into the image, so a
# repository is made here. Which hash it is does not matter to anything below.
git config --global --add safe.directory /work 2>/dev/null
if [ ! -d .git ]; then
  git init -q .
  git config --global user.email parity@local
  git config --global user.name parity
  git add -A >/dev/null 2>&1
  git commit -qm "linux parity" >/dev/null 2>&1
fi

# picolibc's files are present but its submodule metadata is not, and the pin
# check has an override for exactly that case.
if [ -z "${XAIOS_PICOLIBC_REVISION_OVERRIDE:-}" ]; then
  echo "set XAIOS_PICOLIBC_REVISION_OVERRIDE to the pin in scripts/build-libc.sh" >&2
  exit 2
fi
export XAIOS_PICOLIBC_REVISION_OVERRIDE

echo "=== clang $(clang --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1), $(qemu-system-riscv64 --version | head -1) ==="
XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64.sh > /tmp/1.log 2>&1 \
  || { echo "build-riscv64 failed"; tail -12 /tmp/1.log; exit 1; }
XAIOS_BOOT_TEST_APPS=1 ./scripts/build-riscv64-image.sh > /tmp/2.log 2>&1 \
  || { echo "build-riscv64-image failed"; tail -12 /tmp/2.log; exit 1; }

# B-61: a section class the linker script does not name is placed wherever the
# linker chooses, and on RISC-V that broke every hosted C99 application.
echo "orphan small-data sections in the hosted applications:"
for a in build/riscv64-userspace/*.elf; do
  n=$(llvm-readelf --sections "$a" 2>/dev/null | grep -cE "\.sdata|\.sbss")
  [ "$n" != "0" ] && printf '  %-34s %s\n' "$(basename "$a")" "$n"
done
echo "  (nothing listed means none)"

python3 ./tests/scripts/qemu-smoke.py --arch riscv64 > /tmp/3.log 2>&1
status=$?
echo "qemu-smoke --arch riscv64: exit=$status"
grep -a -E "exited status=|assertion failed|QEMU smoke boot reached all" /tmp/3.log | tail -6 | cut -c1-140
exit $status
