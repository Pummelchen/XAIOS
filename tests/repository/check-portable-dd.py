#!/usr/bin/env python3
"""`dd bs=1m` works on a Mac and fails on Linux, and CI is Linux.

BSD `dd` takes lowercase size suffixes -- `bs=1m`, `count=4k`. GNU `dd` does
not: it stops with `dd: invalid number: '1m'`. Every script here is written and
run on a Mac first, so the difference is invisible until something runs on the
Linux runner, and then it is invisible again because the failure surfaces
somewhere else entirely.

That is not hypothetical. `scripts/build-riscv64-boot-media.sh` created its boot
medium with `bs=1m`, so on CI it failed before writing anything -- and what the
log showed was `qemu-libc-gate` reporting a guest that had not booted, because
the gate that called it could only say that the image build had returned
non-zero. Every RISC-V leg of that job had been failing that way.

Uppercase suffixes work on both, and a plain byte count needs no suffix at all
and cannot be ambiguous. This requires one of those two.

A lowercase suffix is allowed where the very next lines retry with an uppercase
one: `write-usb.sh` does that deliberately, because it runs on whichever machine
the person holding the USB stick has, and trying the BSD spelling first is how
it stays readable on a Mac.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SEARCH = ("scripts", "platform", "tools", "tests")
SUFFIXED = re.compile(r"\b(bs|count|seek|skip)=([0-9]+)([kmgKMG])\b")


def main() -> int:
    failures: list[str] = []
    checked = 0
    for directory in SEARCH:
        base = ROOT / directory
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.sh")):
            lines = path.read_text(encoding="utf-8").split("\n")
            checked += 1
            for number, line in enumerate(lines, 1):
                code = line.split("#", 1)[0]
                if "dd " not in code:
                    continue
                for found in SUFFIXED.finditer(code):
                    if found.group(3).isupper():
                        continue
                    # A retry with the uppercase spelling in the next two lines
                    # is the deliberate portable pattern, not a mistake.
                    window = "\n".join(lines[number - 1:number + 2])
                    if re.search(r"=[0-9]+[KMG]\b", window):
                        continue
                    failures.append(
                        f"{path.relative_to(ROOT)}:{number} uses "
                        f"{found.group(0)}; GNU dd rejects lowercase suffixes, "
                        f"so this works on a Mac and fails on Linux CI")

    if failures:
        print("portable-dd: failed")
        for failure in failures:
            print(f"  - {failure}")
        print("  Use an uppercase suffix, or a plain byte count such as "
              "bs=1048576.")
        return 1
    print(f"portable-dd: {checked} shell scripts use no BSD-only dd suffix "
          f"outside a guarded retry")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
