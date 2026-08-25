#!/usr/bin/env python3
"""Reject platform assumptions in the code that ships inside the OS.

XAIOS behaves the same everywhere it boots: firmware supplies capabilities, not
identity, and never behaviour. See docs/PLATFORM-NEUTRALITY.md for why this is
a rule -- it has cost this project a boot failure that was recorded as "XAIOS
does not boot" for a long time, when the real fault was a hard-coded QEMU
serial port advertised to a machine that had none.

Two things are checked, both narrow enough to be actionable:

1. A platform-branded constant may not be the initial value of a variable that
   discovery later fills in. Such a default works on the platform it was taken
   from and fails silently everywhere else.
2. User-visible strings may not name a hypervisor. What the boot display, the
   prompts and the shell say is XAIOS's, and reads identically everywhere.

Harnesses, run scripts, gates and firmware profiles are exempt by design: their
whole purpose is to drive or assert one specific platform.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# What ships inside the operating system.
GUARDED_ROOTS = ("kernel", "boot", "userspace")
SOURCE_SUFFIXES = {".c", ".h", ".S", ".s"}

PLATFORM_NAMES = ("QEMU", "VMWARE", "FUSION", "VIRTUALBOX", "HYPERV", "PARALLELS")

# A platform-branded macro standing as the initial value of mutable state.
ASSUMED_DEFAULT = re.compile(
    r"^\s*static\s+[A-Za-z_][A-Za-z0-9_ *]*\s+(g_[A-Za-z0-9_]+)\s*=\s*"
    r"((?:" + "|".join(PLATFORM_NAMES) + r")_[A-Z0-9_]+)\s*;"
)

# A hypervisor named inside a string that reaches a person.
BRANDED_STRING = re.compile(
    r'"[^"]*\b(qemu|vmware|fusion|virtualbox|hyper-v|parallels)\b[^"]*"',
    re.IGNORECASE,
)


def guarded_sources() -> list[Path]:
    found: list[Path] = []
    for root in GUARDED_ROOTS:
        base = ROOT / root
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if path.suffix in SOURCE_SUFFIXES and path.is_file():
                found.append(path)
    return found


def main() -> int:
    findings: list[str] = []
    scanned = 0

    for path in guarded_sources():
        scanned += 1
        relative = path.relative_to(ROOT)
        for number, line in enumerate(
            path.read_text(errors="replace").splitlines(), start=1
        ):
            stripped = line.lstrip()
            # Comments explain history; they assume nothing.
            if stripped.startswith(("*", "/*", "//")):
                continue

            assumed = ASSUMED_DEFAULT.match(line)
            if assumed:
                findings.append(
                    f"{relative}:{number}: {assumed.group(1)} defaults to "
                    f"{assumed.group(2)}, which assumes a platform. Leave it "
                    f"zero and let discovery fill it in."
                )

            branded = BRANDED_STRING.search(line)
            if branded:
                findings.append(
                    f"{relative}:{number}: a user-visible string names "
                    f"{branded.group(1)!r}. Name the capability, not the "
                    f"hypervisor."
                )

    if findings:
        print("platform-neutrality: assumptions found")
        for finding in findings:
            print(f"  - {finding}")
        print("  see docs/PLATFORM-NEUTRALITY.md")
        return 1

    print(
        f"platform-neutrality: {scanned} kernel, boot and userspace sources "
        f"assume no platform"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
