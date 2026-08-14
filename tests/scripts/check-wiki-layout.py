#!/usr/bin/env python3
"""Validate the curated operator Wiki and its single project tracker."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WIKI = ROOT / "wiki"

EXPECTED_PAGES = {
    "Administration.md",
    "Applications.md",
    "Architecture.md",
    "Boot-and-Console.md",
    "C99-Libc.md",
    "Commands.md",
    "Current-Limitations.md",
    "FAQ.md",
    "Firmware-Profiles.md",
    "Filesystem-and-Storage.md",
    "Getting-Started.md",
    "Hardware-Support.md",
    "Home.md",
    "Networking-and-SSH.md",
    "Operations-and-Recovery.md",
    "Project-Tracker.md",
    "Security-Model.md",
    "Testing-XAIOS.md",
    "Unix-Compatibility.md",
    "VMware-Fusion.md",
    "Xapt-Package-Updates.md",
    "_Footer.md",
    "_Sidebar.md",
}

REMOVED_TRACKER_FILES = {
    "PROJECT-TRACKER.md",
    "SPEC-PLAN.md",
    "README_CRASHTEST.md",
    "docs/DISTRIBUTED-AI-SERVER-PLAN.md",
    "docs/QWEN-K3-IMPLEMENTATION-ROADMAP.md",
    "docs/STORAGE-IMPLEMENTATION-PLAN.md",
}


def main() -> int:
    failures: list[str] = []
    actual = {path.name for path in WIKI.glob("*.md")}
    missing = sorted(EXPECTED_PAGES - actual)
    extra = sorted(actual - EXPECTED_PAGES)
    if missing:
        failures.append("missing curated Wiki pages: " + ", ".join(missing))
    if extra:
        failures.append("unexpected Wiki pages: " + ", ".join(extra))

    planning_names = [
        name
        for name in actual
        if any(word in name.lower() for word in ("tracker", "roadmap", "milestone", "plan"))
    ]
    if planning_names != ["Project-Tracker.md"]:
        failures.append(
            "Project-Tracker.md must be the only planning page; found: "
            + ", ".join(sorted(planning_names))
        )

    for relative in sorted(REMOVED_TRACKER_FILES):
        if (ROOT / relative).exists():
            failures.append(f"obsolete tracker file remains: {relative}")

    for path in sorted(WIKI.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(r"\[\[([^\]]+)\]\]", text):
            value = match.group(1)
            target = value.split("|", 1)[-1].split("#", 1)[0].strip()
            if not target:
                continue
            filename = target.replace(" ", "-") + ".md"
            if filename not in actual:
                failures.append(f"{path.name}: broken Wiki link to {target}")

    if failures:
        print("wiki-layout: failed")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(
        f"wiki-layout: {len(actual)} curated pages, one tracker, and all Wiki links valid"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
