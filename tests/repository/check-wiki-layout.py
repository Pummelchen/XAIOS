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
    "RISC-V.md",
    "Home.md",
    "Networking-and-SSH.md",
    "Operations-and-Recovery.md",
    "Project-Tracker.md",
    "Security-Model.md",
    "Screen-Framework.md",
    "Testing-XAIOS.md",
    "Unix-Compatibility.md",
    "Virtualization-Framework.md",
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



def ragged_tables() -> list[str]:
    """Table rows whose cells do not line up with the header's.

    A `|` inside a cell ends that cell. Markdown has no way to tell a separator
    from a pipe somebody meant as content, so `[[Operations and
    Recovery|Operations-and-Recovery]]` in a table cell silently becomes two
    cells, and every column after it shifts left by one. So does the pipe in
    `` `service list|status|start` `` -- backticks group nothing as far as the
    table parser is concerned.

    Nine rows across four pages were doing this, including a row in the project
    tracker and one in the Fusion table, and nothing said so: the file is valid
    Markdown, every link resolves, and the damage is only visible to someone
    reading the rendered page and noticing a column is empty. The fix in every
    case is to write the pipe as `\\|`.

    The header, or the first row when a table has no separator, sets the width.
    """
    failures = []
    for page in sorted(WIKI.glob("*.md")):
        width = None
        for number, line in enumerate(page.read_text(encoding="utf-8").split("\n"), 1):
            if not line.startswith("|"):
                width = None
                continue
            cells = len(re.split(r"(?<!\\)\|", line)) - 2
            if re.fullmatch(r"\|[\s\-:|]+\|", line) or width is None:
                width = cells
                continue
            if cells != width:
                failures.append(
                    f"{page.name}:{number} has {cells} cells where the table "
                    f"has {width}; an unescaped | inside a cell splits it")
    return failures


def main() -> int:
    failures: list[str] = []
    actual = {path.name for path in WIKI.glob("*.md")}
    missing = sorted(EXPECTED_PAGES - actual)
    extra = sorted(actual - EXPECTED_PAGES)
    if missing:
        failures.append("missing curated Wiki pages: " + ", ".join(missing))
    if extra:
        failures.append("unexpected Wiki pages: " + ", ".join(extra))
    failures.extend(ragged_tables())

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
