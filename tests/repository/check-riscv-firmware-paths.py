#!/usr/bin/env python3
"""The RISC-V firmware search list exists twice, so the two must agree.

B-67: `platform/qemu/run-qemu-riscv64.sh` defaulted to one Homebrew path and
nothing else. Every UEFI boot on Linux failed before QEMU started, and the
release image gate reported all three of its markers absent -- which reads
exactly like a kernel that did not boot, when nothing had booted at all. The
AArch64 and x86-64 runners had searched a list since they were written, which
is why they passed on the runner and this did not.

The list now lives in two places because the runner is shell and the gates
that drive QEMU themselves are Python, and neither can import the other. A
list copied across that boundary is precisely how the two came to disagree in
the first place -- the gates offered `/usr/share/qemu/edk2-riscv-code.fd`,
which is not where Debian puts it either, so they skipped rather than failed.
A gate that skips is not a gate that passed.

So this reads both and requires them to match, the same job
`check-ssh-wire-bound.py` does for two numbers that cannot share a header.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "platform" / "qemu" / "run-qemu-riscv64.sh"
LIBRARY = ROOT / "tests" / "scripts" / "qemu_gate_lib.py"


def shell_lists() -> dict[str, list[str]]:
    """The two `set --` candidate lists inside find_riscv_firmware."""
    text = RUNNER.read_text(encoding="utf-8")
    function = re.search(r"find_riscv_firmware\(\) \{(.*?)\n\}", text, re.S)
    if not function:
        raise SystemExit(
            "check-riscv-firmware-paths: find_riscv_firmware() not found in "
            f"{RUNNER.relative_to(ROOT)}. This check keeps two lists in step "
            "and cannot do that if one has moved or been renamed; passing "
            "quietly would be worse than stopping.")
    found: dict[str, list[str]] = {}
    for kind in ("code", "vars"):
        arm = re.search(rf"\n    {kind}\)(.*?)      ;;", function.group(1), re.S)
        if not arm:
            raise SystemExit(
                f"check-riscv-firmware-paths: no '{kind})' arm in "
                "find_riscv_firmware()")
        found[kind] = re.findall(r"(/\S+\.fd)\b", arm.group(1))
    return found


def python_lists() -> dict[str, list[str]]:
    text = LIBRARY.read_text(encoding="utf-8")
    found: dict[str, list[str]] = {}
    for kind in ("code", "vars"):
        name = f"RISCV_FIRMWARE_{kind.upper()}"
        block = re.search(rf"^{name} = \((.*?)^\)", text, re.S | re.M)
        if not block:
            raise SystemExit(
                f"check-riscv-firmware-paths: {name} not found in "
                f"{LIBRARY.relative_to(ROOT)}")
        found[kind] = re.findall(r'"(/[^"]+\.fd)"', block.group(1))
    return found


def main() -> int:
    shell = shell_lists()
    python = python_lists()

    failures: list[str] = []
    for kind in ("code", "vars"):
        if shell[kind] != python[kind]:
            only_shell = [p for p in shell[kind] if p not in python[kind]]
            only_python = [p for p in python[kind] if p not in shell[kind]]
            detail = []
            if only_shell:
                detail.append(f"only the runner knows {only_shell}")
            if only_python:
                detail.append(f"only the gates know {only_python}")
            if not detail:
                detail.append("same paths, different order, and the order is "
                              "the search order")
            failures.append(
                f"the {kind} list differs between "
                f"{RUNNER.relative_to(ROOT)} and "
                f"{LIBRARY.relative_to(ROOT)}: " + "; ".join(detail))
        if not shell[kind]:
            failures.append(f"the {kind} list is empty, so nothing is searched")

    # A list that names only Homebrew is the defect this exists to prevent, and
    # it would otherwise pass here as long as both copies agreed about it.
    for kind in ("code", "vars"):
        if not any(p.startswith("/usr/") for p in shell[kind]):
            failures.append(
                f"the {kind} list names no /usr path, so this searches only "
                f"macOS locations and every UEFI boot on Linux fails before "
                f"QEMU starts -- which is B-67 exactly")

    if failures:
        print("check-riscv-firmware-paths: failed")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(f"riscv-firmware-paths: runner and gates search the same "
          f"{len(shell['code'])} code and {len(shell['vars'])} vars locations, "
          f"macOS and Linux among them")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
