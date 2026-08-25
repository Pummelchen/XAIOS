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

    mutable_fs = (ROOT / "kernel/fs/mutable_fs.c").read_text(encoding="utf-8")
    narrow_loop = (
        "for (uint16_t i = 0; i < g_active_data_sectors && found < count; ++i)"
    )
    if narrow_loop in mutable_fs:
        failures.append("mutable filesystem block scan uses a narrowing loop index")
    if "g_active_data_sectors > (uint32_t)UINT16_MAX + 1U" not in mutable_fs:
        failures.append("mutable filesystem does not guard its 16-bit block format")
    if "blocks[found++] = (uint16_t)i;" not in mutable_fs:
        failures.append("mutable filesystem block-index conversion is not explicit")

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
