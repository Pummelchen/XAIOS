#!/usr/bin/env python3
"""The panic dump must print each register under the name of the one it holds.

`kernel/core/panic.c` captures registers into an array and prints them by index,
so two lists have to agree: the order the capture stores them in, and the order
the renderer names them. They are written in different functions, in different
languages' idioms -- one is a block of assembly, the other is an array of
strings -- and nothing made them agree.

They did not. The RISC-V capture stores the registers by ABI name in ABI order
(ra, sp, gp, tp, t0-t2, s0-s1, a0-a7), while the renderer fell through to the
AArch64 branch, which prints `r[0..30]` as `x0`..`x30` and `r[31]` as `SP`.
Every line named a different register than the value under it, ten of them were
printed from memory the capture never wrote, and the `SP` line printed whatever
happened to be on the stack. It cost two rounds of diagnosis before anyone
noticed, because a fault report is believed: the hunt went after "a stack
pointer of zero" that was in fact the `gp` register (B-111).

This is the check that would have caught it the day the port's capture was
written, and it is here rather than in a comment because a comment does not
fail a build.

It reads the source rather than running the kernel: the property is about two
lists agreeing, and the machine that would show it by panicking is expensive and
deliberately made to fault. It checks three things for each architecture that
captures registers:

  * the capture stores as many registers as the renderer names;
  * the two are in the same order, ABI name for ABI name;
  * the capture's offsets are 0, 8, 16, ... in order, so a mis-typed offset
    cannot quietly put one register's value under another's name.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "kernel" / "core" / "panic.c"
# The renderer moved to its own translation unit in the file-size split; the
# check reads the same function, from the file that now defines it.
RENDER_SOURCE = ROOT / "kernel" / "core" / "panic_render.c"

# x86-64 names its registers in Microsoft's order and AArch64 prints x0..x31;
# both are their own vocabulary and are read from the same two places. Only the
# architectures that store into the shared array are checked, so an
# architecture that prints a fixed list of its own is left alone.


def function_body(text: str, signature: str) -> str:
    """The body of the function whose signature starts with `signature`."""
    start = text.index(signature)
    end = text.index("\n}\n", start)
    return text[start:end]


def riscv_branch(body: str) -> str | None:
    """The `#elif defined(__riscv)` section of a body, up to the next branch."""
    marker = "#elif defined(__riscv)"
    if marker not in body:
        return None
    start = body.index(marker) + len(marker)
    for terminator in ("#elif defined(", "#else", "#endif"):
        index = body.find(terminator, start)
        if index != -1:
            return body[start:index]
    return body[start:]


def captured_registers(branch: str) -> list[tuple[str, int]]:
    """`(name, offset)` pairs in the order the capture stores them."""
    return [(name, int(offset))
            for name, offset in re.findall(r'"sd\s+([a-z][a-z0-9]*),\s*(\d+)\(%0\)',
                                           branch)]


def printed_names(branch: str) -> list[str]:
    """The names the renderer prints, in order."""
    match = re.search(r"names\[\]\s*=\s*\{(.*?)\};", branch, re.S)
    if match is None:
        return []
    return [name.strip() for name in re.findall(r'"([^"]*)"', match.group(1))]


def main() -> int:
    text = SOURCE.read_text(encoding="utf-8")
    capture = function_body(text, "static void capture_gp_regs")
    render = function_body(RENDER_SOURCE.read_text(encoding="utf-8"), "void panic_render_gp_regs")

    capture_branch = riscv_branch(capture)
    render_branch = riscv_branch(render)
    if capture_branch is None or render_branch is None:
        print("panic-registers: kernel/core/panic.c has no RISC-V register "
              "capture or renderer to compare", file=sys.stderr)
        return 1

    stored = captured_registers(capture_branch)
    named = printed_names(render_branch)

    failures = []
    if not stored:
        failures.append("the RISC-V capture stores nothing this check can read")
    if not named:
        failures.append("the RISC-V renderer names nothing this check can read")
    if stored and named and len(stored) != len(named):
        failures.append(
            f"the capture stores {len(stored)} registers and the renderer names "
            f"{len(named)}; the extra lines are printed from memory the capture "
            f"never wrote")

    expected_offsets = [index * 8 for index in range(len(stored))]
    actual_offsets = [offset for _, offset in stored]
    if actual_offsets != expected_offsets:
        failures.append(
            f"the capture's offsets are {actual_offsets} where 0, 8, 16, ... "
            f"were expected, so at least one value is stored under another "
            f"register's name")

    for index, ((stored_name, _), named_name) in enumerate(zip(stored, named)):
        if stored_name != named_name:
            failures.append(
                f"position {index} holds {stored_name} and is printed as "
                f"{named_name}")

    if failures:
        print("panic-registers: the RISC-V panic register block would misname "
              "its own registers", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        print("  kernel/core/panic.c: capture_gp_regs and render_gp_regs must "
              "agree register for register, in order", file=sys.stderr)
        return 1

    print(f"panic-registers: riscv64 capture and renderer agree on "
          f"{len(stored)} registers, in order, at 8-byte offsets")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
