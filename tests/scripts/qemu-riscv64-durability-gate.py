#!/usr/bin/env python3
"""Does RISC-V keep what it was told to keep, across a reboot and across a kill?

The other three gates all start from a clean machine and stop when it is up.
Nothing in them would notice a filesystem that writes but never reads back, or
one that survives an orderly shutdown and not an abrupt one -- which is the
failure that matters, because machines lose power and rarely ask first.

Four boots against one set of volumes:

  1. fresh volumes            the kernel finds no prior state and writes some
  2. same volumes             it finds that state and loads it
  3. same volumes, killed     no shutdown, no flush, no warning
  4. same volumes             it still boots, and the filesystem reports no
                              checksum errors -- recovery, not luck

Boot 3 is the point of the whole thing. Killing the guest after it is up means
the volumes are cut off mid-life rather than at a convenient moment, and boot 4
is where a filesystem that only survives clean shutdowns says so.
"""
import os
import sys
import tempfile
from pathlib import Path

import riscv64_gate_lib as rvgate
from qemu_gate_lib import BUILD, ROOT

LOG_DIR = BUILD / "riscv64-durability"

READY = rvgate.READY
BOOT_TIMEOUT = int(os.environ.get("XAIOS_RISCV64_TIMEOUT", "700"))

# The kernel says which of the two it found, and the two statements are
# mutually exclusive: a gate that accepted either would pass on a machine
# whose disk was never read.
FIRST_BOOT = [
    "persistence: no existing disk state sector=3000",
    "persistence: disk write sector=3000 version=1 records=5",
    '"persistence_boot_loads":0',
]
LATER_BOOT = [
    "persistence: existing disk state loaded records=5",
    '"persistence_boot_loads":1',
]
ALWAYS = [READY, "xaios login:", '"xaiboot_fs_checksum_errors":0']


def check(log: Path, required, label: str) -> list:
    return rvgate.problems(rvgate.read(log), required, label=label)


def main() -> int:
    if not rvgate.available():
        print("qemu-system-riscv64 is not installed; skipping", file=sys.stderr)
        return 0
    for missing in rvgate.prerequisites():
        print(f"missing: {missing}", file=sys.stderr)
        return 2
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    problems = []
    with tempfile.TemporaryDirectory() as scratch:
        state = Path(scratch)
        stages = [
            ("first", FIRST_BOOT + ALWAYS, False),
            ("second", LATER_BOOT + ALWAYS, False),
            ("killed", LATER_BOOT, True),
            ("recovered", LATER_BOOT + ALWAYS, False),
        ]
        for label, required, kill in stages:
            log = LOG_DIR / f"{label}.log"
            reached = rvgate.boot(log, state, timeout=BOOT_TIMEOUT,
                                 kill_when_ready=kill)
            if not reached:
                problems.append(f"{label}: never reported {READY!r}")
            problems += check(log, required, label)
            print(f"  {label:<10} {'ok' if not problems else 'see below'}")
            if problems:
                break

    if problems:
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print(f"logs in {LOG_DIR.relative_to(ROOT)}", file=sys.stderr)
        return 1

    print("qemu-riscv64-durability-gate: state survived a reboot and an "
          "abrupt kill, with no checksum errors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
