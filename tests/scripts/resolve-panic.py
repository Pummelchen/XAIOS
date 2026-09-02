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


def elf_machine(kernel: Path) -> str:
    tool = shutil.which("llvm-readelf") or shutil.which("readelf")
    if not tool:
        return ""
    result = subprocess.run([tool, "-h", str(kernel)], text=True,
                            capture_output=True, timeout=60)
    for line in result.stdout.splitlines():
        if line.strip().startswith("Machine:"):
            value = line.split(":", 1)[1].strip()
            if "AArch64" in value:
                return "aarch64"
            if "X86-64" in value or "x86-64" in value:
                return "x86_64"
            return value
    return ""


def panic_machine(text: str) -> str:
    """Which architecture produced this panic, read off its register dump."""
    if "ELR_EL1" in text or "CurrentEL" in text:
        return "aarch64"
    if "RFLAGS" in text or "RIP      =" in text:
        return "x86_64"
    return ""


def resolve(vma: int, table: list[tuple[int, str]]) -> str | None:
    best = None
    for address, name in table:
        if address <= vma:
            best = (address, name)
        else:
            break
    if best is None or vma - best[0] >= MAX_FUNCTION_SPAN:
        return None
    if vma < table[0][0] or vma > table[-1][0] + MAX_FUNCTION_SPAN:
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

    # Refuse a kernel that cannot be the one that panicked.
    #
    # Checked because the negative control caught this script resolving an
    # AArch64 panic against the x86_64 kernel and reporting, with no hedging
    # whatsoever, "boot_ui_update+0x63". Names arrive whether or not they
    # mean anything: every address lands somewhere in some symbol table, so
    # a wrong build does not fail, it lies. For a bug whose entire remaining
    # evidence is a backtrace, that is worse than returning nothing.
    #
    # Architecture is the one mismatch detectable from a panic alone -- the
    # kernel embeds no build identifier, so a same-architecture build from a
    # different commit still resolves to confident nonsense. Hence the
    # warning as well as the check.
    from_panic = panic_machine(text)
    from_elf = elf_machine(arguments.kernel)
    if from_panic and from_elf and from_panic != from_elf:
        raise SystemExit(
            f"this panic came from {from_panic} but {arguments.kernel} is "
            f"{from_elf}. Every address resolves to some symbol in some "
            f"table, so continuing would print names that look right and are "
            f"not. Pass --kernel for the build that panicked.")

    table = symbols(arguments.kernel)
    linked = link_base(table)
    print("note: nothing in a panic identifies which build produced it, so "
          "check that this kernel.elf is the one that was running -- a "
          "different build of the same architecture resolves to plausible "
          "nonsense.", file=sys.stderr)

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
