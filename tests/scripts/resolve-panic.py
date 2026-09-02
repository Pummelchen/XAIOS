#!/usr/bin/env python3
"""Turn a pasted XAIOS panic into function names.

Paste a panic on stdin:

    tests/scripts/resolve-panic.py < panic.txt
    pbpaste | tests/scripts/resolve-panic.py --kernel build/kernel/kernel.elf

The panic prints raw addresses because the kernel is position-independent:
the loader puts it wherever the machine has room, so the same build lands
somewhere different every boot. Two things have to happen to read them, and
neither is obvious enough to expect an operator to get right at three in the
morning with a machine down:

  * the address has to be moved into the ELF's own numbering. It is
    `runtime - load_base + link_base`, not `runtime - load_base`. The bare
    subtraction gives an offset from the start of the image, and kernel.elf
    is linked at 0x90000000, so the result resolves to nothing.

  * it has to be resolved against the symbol table, not with llvm-symbolizer.
    The kernel is built without DWARF, so the symbolizer answers "??" no
    matter how correct the address is.

Both of those were discovered by causing a panic and following the printed
instruction, which did not work. This script is what that instruction now
points at.
"""
from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_KERNEL = ROOT / "build" / "kernel" / "kernel.elf"

FRAME = re.compile(r"^\s*#(\d+)\s+(0x[0-9a-f]+)\s*$", re.MULTILINE)
LOAD_BASE = re.compile(r"load base\s+(0x[0-9a-f]+)")
# Anything further than this past a symbol is not inside it; the frame is in
# firmware, in userspace, or is a stale stack word rather than a return address.
MAX_FUNCTION_SPAN = 0x4000


def symbols(kernel: Path) -> list[tuple[int, str]]:
    tool = shutil.which("llvm-nm") or shutil.which("nm")
    if not tool:
        raise SystemExit("neither llvm-nm nor nm is on PATH")
    result = subprocess.run([tool, "-n", "--defined-only", str(kernel)],
                            text=True, capture_output=True, timeout=120)
    if result.returncode != 0:
        raise SystemExit(f"could not read symbols from {kernel}:\n{result.stderr}")
    found = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] in "tTwW":
            found.append((int(parts[0], 16), parts[2]))
    if not found:
        raise SystemExit(f"{kernel} has no text symbols to resolve against")
    found.sort()
    return found


def link_base(table: list[tuple[int, str]]) -> int:
    for address, name in table:
        if name == "__kernel_start":
            return address
    # Falling back to the lowest text symbol is close enough to be useful and
    # is reported, rather than silently assumed.
    print(f"note: no __kernel_start symbol; assuming link base "
          f"0x{table[0][0]:x} from the lowest text symbol", file=sys.stderr)
    return table[0][0]


def resolve(vma: int, table: list[tuple[int, str]]) -> str | None:
    best = None
    for address, name in table:
        if address <= vma:
            best = (address, name)
        else:
            break
    if best is None or vma - best[0] >= MAX_FUNCTION_SPAN:
        return None
    return f"{best[1]}+0x{vma - best[0]:x}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--kernel", type=Path, default=DEFAULT_KERNEL,
                        help=f"kernel ELF to resolve against (default {DEFAULT_KERNEL})")
    parser.add_argument("--load-base", type=lambda v: int(v, 16), default=None,
                        help="override the load base, if the panic did not print one")
    arguments = parser.parse_args()

    text = sys.stdin.read()
    if not text.strip():
        raise SystemExit("nothing on stdin; paste a panic")
    if not arguments.kernel.is_file():
        raise SystemExit(f"no kernel ELF at {arguments.kernel} -- pass --kernel. "
                         "It must be the build the panicking machine was running; "
                         "a different build resolves to confident nonsense.")

    base = arguments.load_base
    if base is None:
        match = LOAD_BASE.search(text)
        if not match:
            raise SystemExit("this panic has no load base line, and without it the "
                             "addresses cannot be placed. Pass --load-base if you "
                             "know it from elsewhere.")
        base = int(match.group(1), 16)

    frames = [(int(number), int(address, 16))
              for number, address in FRAME.findall(text)]
    if not frames:
        raise SystemExit("no backtrace frames found in that text")

    table = symbols(arguments.kernel)
    linked = link_base(table)

    print(f"load base 0x{base:x}, kernel.elf linked at 0x{linked:x}, "
          f"{len(frames)} frames")
    resolved = 0
    for number, address in frames:
        vma = address - base + linked
        name = resolve(vma, table) if address >= base else None
        if name:
            resolved += 1
            print(f"  #{number:<2} 0x{address:x} -> 0x{vma:x}  {name}")
        else:
            print(f"  #{number:<2} 0x{address:x} -> 0x{vma:x}  "
                  f"(not in kernel text: firmware, userspace, or not a "
                  f"return address)")
    print(f"{resolved} of {len(frames)} frames are in kernel text")
    return 0 if resolved else 1


if __name__ == "__main__":
    raise SystemExit(main())
