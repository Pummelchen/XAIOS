#!/usr/bin/env python3
"""Keep resolved CodeQL security boundaries from regressing."""

from __future__ import annotations

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    failures: list[str] = []

    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    if not re.search(
        r"(?m)^permissions:\n  contents: read\n\njobs:$", workflow
    ):
        failures.append("CI workflow must declare top-level read-only contents access")

    loopback_scripts = (
        "tests/scripts/qemu-local-console-gate.py",
        "tests/scripts/qemu-docker-network-suite.py",
        "tests/scripts/qemu-freebsd-bidirectional-suite.py",
    )
    for relative in loopback_scripts:
        source = (ROOT / relative).read_text(encoding="utf-8")
        if 'sock.bind(("0.0.0.0", 0))' in source:
            failures.append(f"{relative} reserves ephemeral ports on every interface")
        if 'sock.bind(("127.0.0.1", 0))' not in source:
            failures.append(f"{relative} does not reserve ephemeral ports on loopback")

    console_gate = (ROOT / loopback_scripts[0]).read_text(encoding="utf-8")
    if '" ".join(command)' in console_gate:
        failures.append("local-console gate logs unsanitized command arguments")

    readiness = (ROOT / "tests/scripts/qemu-readiness-gate.py").read_text(
        encoding="utf-8"
    )
    if 'print(f"  - {failure}")' in readiness:
        failures.append("readiness gate logs unsanitized validation values")

    xaiboot_fs = (ROOT / "kernel/fs/xaiboot_fs.c").read_text(encoding="utf-8")
    narrow_loop = (
        "for (uint16_t i = 0; i < g_active_data_sectors && found < count; ++i)"
    )
    if narrow_loop in xaiboot_fs:
        failures.append("xaibootFS block scan uses a narrowing loop index")
    # The invariant these guard is that a block number never silently loses
    # bits on its way onto a volume that records sixteen of them. It used to
    # live in the allocator, which numbered blocks directly; v6 records extents
    # and 32-bit starts, so the only place a block is narrowed is the
    # conversion written when an older volume's metadata is stored. Two checks
    # moved rather than removed: dropping them because the code moved would
    # leave the truncation they exist to prevent unguarded.
    if "if (block > UINT16_MAX) return UINT32_MAX;" not in xaiboot_fs:
        failures.append(
            "xaibootFS does not refuse a block that will not fit a 16-bit "
            "volume's metadata"
        )
    if "blocks[written++] = (uint16_t)block;" not in xaiboot_fs:
        failures.append("xaibootFS block-index conversion is not explicit")

    if failures:
        print("code-scanning-contract: failed")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print(
        "code-scanning-contract: passed workflow=read-only "
        "port-reservation=loopback diagnostics=bounded integer-width=safe"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
