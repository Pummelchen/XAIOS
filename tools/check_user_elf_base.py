#!/usr/bin/env python3
"""Refuse to pack a user binary linked somewhere the kernel will not map it.

The user window is one constant, `XAIOS_USER_BASE` in kernel/include/xaios/vmm.h,
and three things have to agree about it: the kernel's page tables, the two
userspace linker scripts, and every ELF actually built from them. The first two
are checked by the ABI contract from the sources. The third was checked by
nothing, and the sources are not enough on their own -- an ELF is a build
artefact, and a stale one disagrees with a linker script that is perfectly
correct.

That gap is not theoretical. Moving the window from 511 GiB to 255 rebuilt all
fifty ordinary user binaries and left the six hosted libc runtime tests behind,
because those are produced by a separate script that the image builders only
consume from. The image packed happily. What it produced was a kernel that
booted, passed eighty-seven self-tests, ran twenty processes at the new base,
and then died on a cyan screen inside `user_load_process` -- roughly the least
convenient place for a build mistake to surface, and a full boot away from the
thing that was actually wrong.

Comparing what was built against the constant costs a few milliseconds and
turns that into a build failure naming the file.
"""

from __future__ import annotations

import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HEADER = ROOT / "kernel/include/xaios/vmm.h"
BASE = re.compile(r"#define\s+XAIOS_USER_BASE\s+UINT64_C\((0x[0-9a-fA-F]+)\)")


def user_base() -> int:
    match = BASE.search(HEADER.read_text(encoding="utf-8"))
    if match is None:
        raise SystemExit(f"check-user-elf-base: no XAIOS_USER_BASE in {HEADER}")
    return int(match.group(1), 16)


def entry_point(path: Path) -> int | None:
    """The ELF entry address, read directly rather than through a toolchain.

    Only 64-bit little-endian ELF is produced here, and e_entry sits at offset
    24. Reading it with struct keeps this runnable during a build that has not
    put llvm-readelf on PATH yet -- a check that is skipped because a tool is
    missing is the same as no check.
    """
    with path.open("rb") as handle:
        header = handle.read(32)
    if len(header) < 32 or header[:4] != b"\x7fELF" or header[4] != 2:
        return None
    return struct.unpack_from("<Q", header, 24)[0]


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: check_user_elf_base.py <directory-or-elf>...",
              file=sys.stderr)
        return 2
    expected = user_base()
    checked = 0
    failures: list[str] = []
    for argument in argv[1:]:
        path = Path(argument)
        candidates = (sorted(path.rglob("*.elf")) if path.is_dir()
                      else [path] if path.is_file() else [])
        for candidate in candidates:
            entry = entry_point(candidate)
            if entry is None:
                continue
            checked += 1
            if entry != expected:
                failures.append(
                    f"{candidate.relative_to(ROOT) if candidate.is_relative_to(ROOT) else candidate}"
                    f" links at 0x{entry:x}, but XAIOS_USER_BASE is "
                    f"0x{expected:x}")
    if failures:
        print("check-user-elf-base: user binaries disagree with the kernel's "
              "user window", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        print("  rebuild them; a stale binary here panics the kernel at boot "
              "rather than failing the build", file=sys.stderr)
        return 1
    if checked == 0:
        # Loud rather than a quiet pass: being handed nothing to check almost
        # always means the paths moved, and a check that reports success on an
        # empty set is worse than no check.
        print("check-user-elf-base: no user ELFs found in "
              f"{' '.join(argv[1:])}", file=sys.stderr)
        return 1
    print(f"check-user-elf-base: {checked} user binaries link at "
          f"0x{expected:x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
