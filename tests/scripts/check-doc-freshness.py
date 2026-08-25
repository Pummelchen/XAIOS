#!/usr/bin/env python3
"""Catch documentation that has quietly aged out of being true.

Structure can be enforced by shape: a directory either exists or it does not.
Prose cannot, and in one session three separate claims in this repository were
found to have expired without anyone noticing -- a page saying a target had no
automated gate months after two were added, a review date on a page rewritten
since, and an evidence commit quoted as current from a hundred commits back.
Each was correct when written. That is the whole problem: nothing re-reads a
sentence once it is committed.

Two things are checked.

**Evidence commits.** A commit hash in the documentation is either ours or
upstream's. An upstream pin -- Picolibc, LLVM, QEMU, a model revision -- is
supposed to be old; being fixed is the point. One of *our* commits presented as
current evidence is a different claim, and it decays every time the tree moves.
Such a reference must either be recent or say plainly that it is behind, and
saying so is enough: a stale result that admits it is stale is honest, and the
reader can act on it.

**Review dates.** A page carrying `Last reviewed: <date>` that git shows was
modified after that date is claiming a review that did not happen.
"""

from __future__ import annotations

import re
import subprocess
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SURFACES = ("wiki", "docs")

# How far one of our own commits may fall behind before a currency claim about
# it stops being credible.
MAX_COMMITS_BEHIND = 50

HASH = re.compile(r"`([0-9a-f]{7,40})`")
REVIEWED = re.compile(r"Last reviewed:\s*(\d{4}-\d{2}-\d{2})")

# Phrases that turn a currency claim into a historical one. A page that says a
# result is behind the tree is not making a false statement about today.
ACKNOWLEDGED = (
    "behind the current tree",
    "must be re-run",
    "was captured",
    "no longer current",
    "historical",
    "predates",
)


def run(*arguments: str) -> str:
    return subprocess.run(
        arguments, cwd=ROOT, capture_output=True, text=True
    ).stdout.strip()


def in_our_history(commit: str) -> bool:
    result = subprocess.run(
        ["git", "cat-file", "-e", f"{commit}^{{commit}}"],
        cwd=ROOT, capture_output=True,
    )
    return result.returncode == 0


def main() -> int:
    failures: list[str] = []
    upstream_pins = 0
    checked = 0

    for surface in SURFACES:
        base = ROOT / surface
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.md")):
            relative = path.relative_to(ROOT)
            text = path.read_text(errors="replace")
            lowered = text.lower()
            acknowledged = any(phrase in lowered for phrase in ACKNOWLEDGED)

            for commit in HASH.findall(text):
                checked += 1
                if not in_our_history(commit):
                    # An upstream pin. Old on purpose.
                    upstream_pins += 1
                    continue
                behind = run("git", "rev-list", "--count", f"{commit}..HEAD")
                distance = int(behind) if behind.isdigit() else 0
                if distance > MAX_COMMITS_BEHIND and not acknowledged:
                    failures.append(
                        f"{relative}: cites {commit[:8]}, {distance} commits "
                        f"behind HEAD, and does not say so. Re-run the evidence "
                        f"or state that it is behind the current tree."
                    )

            reviewed = REVIEWED.search(text)
            if reviewed:
                claimed = reviewed.group(1)
                changed = run(
                    "git", "log", "-1", "--format=%ad", "--date=short", "--", str(relative)
                )
                if changed and changed > claimed:
                    failures.append(
                        f"{relative}: claims review on {claimed} but was "
                        f"modified on {changed}."
                    )
                elif claimed > date.today().isoformat():
                    failures.append(
                        f"{relative}: claims review on {claimed}, which is in "
                        f"the future."
                    )

    if failures:
        print("doc-freshness: claims that have expired")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print(
        f"doc-freshness: {checked} commit references checked "
        f"({upstream_pins} upstream pins, old by design), review dates current"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
