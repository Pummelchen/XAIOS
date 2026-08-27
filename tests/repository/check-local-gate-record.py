#!/usr/bin/env python3
"""Refuse to release code the hypervisors have not run.

CI verifies everything a Linux runner can reach, on every push. It cannot
reach VMware Fusion or Apple Virtualization.framework, so two of the four
environments XAIOS claims to support are checked only when somebody runs
make local-gates. Nothing made that a requirement, which meant a release
could be cut having been tested on half the platforms it names.

This makes it a requirement at the point where it matters. It does not make
CI able to run a hypervisor -- nothing can -- it makes shipping without that
evidence a thing you have to deliberately override rather than a thing you
can do by forgetting.

The record has to name HEAD exactly. Not an ancestor: a change that looks
harmless in a diff is precisely the kind that has broken a hypervisor here
before, and "close enough" is how a record stops meaning anything. Run the
gates again; they take about five minutes.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RECORD = ROOT / "build" / "local-gates.json"


def git(*arguments: str) -> str:
    return subprocess.run(["git", *arguments], cwd=str(ROOT), check=False,
                          capture_output=True, text=True).stdout.strip()


def main() -> int:
    head = git("rev-parse", "HEAD")
    problems = []

    if not RECORD.is_file():
        print("local-gate-record: no record of the hypervisor gates")
        print(f"  {RECORD.relative_to(ROOT)} does not exist.")
        print("  Run: make local-gates")
        return 1

    try:
        record = json.loads(RECORD.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        print(f"local-gate-record: {RECORD.relative_to(ROOT)} is unreadable: {error}")
        return 1

    if record.get("commit") != head:
        problems.append(
            f"records {str(record.get('commit'))[:12]}, but HEAD is {head[:12]}")
    if not record.get("tree_clean", False):
        problems.append("was recorded against a working tree with uncommitted "
                        "changes, so it describes code that is not in any commit")
    if not record.get("complete", False):
        problems.append("covers only one gate; a release needs all of them")
    if not record.get("passed", False):
        failed = [g["gate"] for g in record.get("gates", []) if not g.get("passed")]
        problems.append(f"records a failure: {', '.join(failed) or 'unknown gate'}")

    if problems:
        print("local-gate-record: this commit has not been verified on the "
              "hypervisors")
        for problem in problems:
            print(f"  - the record {problem}")
        print("  Run: make local-gates")
        return 1

    gates = ", ".join(g["gate"] for g in record.get("gates", []))
    print(f"local-gate-record: {head[:12]} verified on the hypervisors "
          f"({gates}) at {record.get('recorded_utc')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
