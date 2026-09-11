#!/usr/bin/env python3
"""The kernel's fault-test marker and the scripts that look for it must agree.

`make qemu-fault-matrix` builds three kernels that halt on purpose, each into
the same `build/kernel*/kernel.elf` that every packaging script reads, and
restores a normal image when it finishes. That restoration is a courtesy, not a
guarantee -- interrupt it, crash it, or run a packaging script beside it, and
the tree holds a kernel that halts on purpose under the name that means "the
kernel". A netboot binary was built exactly that way, looked like a release
binary in every respect a person can check, and was found only by booting it
and watching it stop at `exceptions: triggering controlled NX execute fault`.

So the kernel now writes a marker into its own bytes when it is one of those
builds, and `build-arch-image.sh` and `build-netboot-image.sh` refuse any
kernel carrying it. That is three copies of one string in three files, and a
string copied three ways is how the two halves of a check come to disagree
without anything failing: rename it in the kernel alone and both scripts go on
searching happily for something that is no longer there, finding nothing, and
passing every fault kernel they are given.

A grep that can no longer match is a gate that cannot fail. This makes that
case fail here instead.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
KMAIN = ROOT / "kernel" / "core" / "kmain.c"
SCRIPTS = (ROOT / "scripts" / "build-arch-image.sh",
           ROOT / "scripts" / "build-netboot-image.sh")


def kernel_marker() -> str:
    text = KMAIN.read_text(encoding="utf-8")
    found = re.search(
        r'#define\s+XAIOS_FAULT_TEST_BUILD_MARKER\s*\\\s*\n\s*"([^"]+)"', text)
    if not found:
        raise SystemExit(
            "check-fault-test-marker: XAIOS_FAULT_TEST_BUILD_MARKER is not "
            "defined in kernel/core/kmain.c. The packaging scripts search a "
            "kernel binary for that string; if it has moved or been renamed "
            "they will search for it forever and never find it, which reads "
            "exactly like a clean kernel.")
    return found.group(1)


def main() -> int:
    marker = kernel_marker()

    # It must actually be emitted, not merely defined. A #define nothing uses
    # leaves no string in the binary at all.
    if f'klog("%s\\n", XAIOS_FAULT_TEST_BUILD_MARKER)' not in \
            KMAIN.read_text(encoding="utf-8"):
        print("check-fault-test-marker: the marker is defined but never "
              "emitted, so no fault kernel would carry it")
        return 1

    failures: list[str] = []
    for script in SCRIPTS:
        text = script.read_text(encoding="utf-8")
        if marker not in text:
            failures.append(
                f"{script.relative_to(ROOT)} does not contain the marker the "
                f"kernel writes. It would search a fault kernel for a string "
                f"that is not in it, find nothing, and package it")

    if failures:
        print("check-fault-test-marker: failed")
        for failure in failures:
            print(f"  - {failure}")
        print(f'  the kernel writes: "{marker}"')
        return 1

    print(f"fault-test-marker: {len(SCRIPTS)} packaging scripts refuse a "
          f"kernel carrying the marker kmain.c writes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
