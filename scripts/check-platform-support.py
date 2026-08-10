#!/usr/bin/env python3
"""Validate the authoritative 20-item platform recommendation status."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STATUS_PATH = ROOT / "docs/PLATFORM-SUPPORT.json"
SYNC_DOCUMENTS = (
    "README.md",
    "PROJECT-TRACKER.md",
    "HARDWARE-READINESS.md",
    "docs/HARDWARE-BACKENDS.md",
    "docs/DISTRIBUTED-AI-SERVER-PLAN.md",
    "wiki/Architecture.md",
    "wiki/Current-Limitations.md",
    "wiki/Home.md",
    "wiki/Platform-Support.md",
)
ALLOWED_STATUSES = {
    "ci-tested",
    "implemented-awaiting-ci",
    "qemu-tested",
    "macos-tested",
    "physical-gate",
    "scope-defined",
    "interface-only",
    "partial",
    "pending",
    "parser-tested",
    "hosted-tested",
    "interface-tested",
    "synchronized",
    "pending-push",
}
REQUIRED_MARKERS = {
    "README.md": (
        "FP/SIMD interrupt context",
        "MADT CPU",
        "PCI VirtIO block/network",
        "QEMU service parity with AArch64",
    ),
    "PROJECT-TRACKER.md": (
        "all MADT-discovered x86 APs",
        "ring-3 `int 0x80`",
        "x86_64 QEMU OS parity",
    ),
    "HARDWARE-READINESS.md": (
        "AP trampoline",
        "XSAVE/XRSTOR",
        "full x86 QEMU service image",
    ),
    "wiki/Home.md": (
        "MADT-discovered application processors",
        "QEMU service parity with AArch64",
    ),
}


def main() -> int:
    failures: list[str] = []
    status = json.loads(STATUS_PATH.read_text(encoding="utf-8"))
    if status.get("schema") != "xaios.platform-support.v1":
        failures.append("platform support schema mismatch")
    recommendations = status.get("recommendations", [])
    ids = [entry.get("id") for entry in recommendations]
    if ids != list(range(1, 21)):
        failures.append("recommendation IDs must be exactly 1 through 20")
    for entry in recommendations:
        if entry.get("status") not in ALLOWED_STATUSES:
            failures.append(
                f"recommendation {entry.get('id')} has unknown status "
                f"{entry.get('status')!r}"
            )
        if not entry.get("name") or not entry.get("evidence"):
            failures.append(
                f"recommendation {entry.get('id')} lacks name or evidence"
            )

    for relative in SYNC_DOCUMENTS:
        path = ROOT / relative
        if not path.is_file():
            failures.append(f"missing synchronized document: {relative}")
            continue
        text = path.read_text(encoding="utf-8")
        if "PLATFORM-SUPPORT" not in text:
            failures.append(
                f"{relative}: missing authoritative platform-status link"
            )
        for marker in REQUIRED_MARKERS.get(relative, ()):
            if marker not in text:
                failures.append(f"{relative}: missing status marker: {marker}")

    wiki_status = (ROOT / "wiki/Platform-Support.md").read_text(encoding="utf-8")
    for entry in recommendations:
        row = f"| {entry['id']} | {entry['name']} | `{entry['status']}` |"
        if row not in wiki_status:
            failures.append(
                "wiki/Platform-Support.md: missing authoritative row: " + row
            )

    if failures:
        print("platform-support: failed")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("platform-support: 20 recommendations and synchronized documents agree")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
