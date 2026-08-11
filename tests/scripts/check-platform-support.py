#!/usr/bin/env python3
"""Validate the platform registry against the single human project tracker."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "docs/PLATFORM-SUPPORT.json"
ALLOWED = ("DONE", "TESTING", "IN PROGRESS", "NOT STARTED", "BLOCKED", "FAILED")


def main() -> int:
    failures: list[str] = []
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    if registry.get("schema") != "xaios.platform_registry.v2":
        failures.append("platform registry schema mismatch")
    recommendations = registry.get("recommendations", [])
    if [entry.get("id") for entry in recommendations] != list(range(1, 21)):
        failures.append("platform recommendation IDs must be exactly 1 through 20")
    relative = registry.get("canonical_tracker")
    tracker = ROOT / relative if isinstance(relative, str) else ROOT / "missing"
    text = tracker.read_text(encoding="utf-8") if tracker.is_file() else ""
    if not text:
        failures.append("canonical platform tracker is missing")
    for entry in recommendations:
        prefix = f"| P-{entry['id']:02d} | {entry['name']} | `"
        rows = [line for line in text.splitlines() if line.startswith(prefix)]
        if len(rows) != 1:
            failures.append(f"tracker must contain one row for P-{entry['id']:02d}")
        elif not any(f"`{status}`" in rows[0] for status in ALLOWED):
            failures.append(f"P-{entry['id']:02d} uses an unknown progress status")
    if failures:
        print("platform-support: failed")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("platform-support: 20 recommendations have one canonical tracked status")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
