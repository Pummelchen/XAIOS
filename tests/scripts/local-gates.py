#!/usr/bin/env python3
"""Run every gate that CI cannot, and leave a record of having done it.

Four gates need macOS on Apple Silicon: two hypervisors that do not exist on a
Linux runner, and the half of the unified-image gate that drives them. CI runs
everything else on every push, which means the automated half of this project
is continuously verified and the local half is verified whenever somebody
remembers.

That asymmetry is the thing this closes. Not by making CI able to run them --
it cannot -- but by making the question "was this commit checked on the
hypervisors, and when?" one with a written answer instead of a recollection.
The record names the commit, says whether the tree was clean, and is refused
if it is not: a result recorded against a dirty tree describes code that
exists nowhere and is worse than no record at all.

This is not qualification evidence. It is a hypervisor, not hardware.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
RECORD = BUILD / "local-gates.json"

# Ordered cheapest first, so an obvious breakage is reported in three minutes
# rather than forty. Each entry is (name, make target, budget in seconds).
GATES = (
    ("vmware-fusion-smoke", "vmware-fusion-smoke", 1800),
    ("vz-gate", "vz-gate", 1800),
    ("unified-image-gate", "unified-image-gate", 3600),
    ("vz-stress-gate", "vz-stress-gate", 3600),
)


# VMware Fusion writes its guest console to one file inside the VM bundle, and
# every gate that drives Fusion writes to the same one. Run them in sequence
# and each overwrites the last, so a failure in the first gate is unreadable by
# the time the run finishes -- which is exactly what happened to an
# intermittent assertion here: it failed, four later runs passed, and there was
# nothing left to say what it had been. Keep each gate's console beside its
# output.
FUSION_SERIAL = BUILD / "vmware-fusion" / "XAIOS.vmwarevm" / "fusion-serial.log"


def preserve_serial(name: str) -> None:
    if not FUSION_SERIAL.is_file():
        return
    try:
        shutil.copy(FUSION_SERIAL, BUILD / f"local-gate-{name}-console.log")
    except OSError:
        pass


def git(*arguments: str) -> str:
    return subprocess.run(["git", *arguments], cwd=str(ROOT), check=False,
                          capture_output=True, text=True).stdout.strip()


def main() -> int:
    if sys.platform != "darwin":
        print("local-gates: these gates need macOS; CI covers everything else")
        return 1

    commit = git("rev-parse", "HEAD")
    dirty = git("status", "--porcelain") != ""
    only = os.environ.get("XAIOS_LOCAL_GATES_ONLY")
    allow_dirty = os.environ.get("XAIOS_LOCAL_GATES_ALLOW_DIRTY") == "1"

    if dirty and not allow_dirty:
        print("local-gates: the working tree has uncommitted changes.")
        print("  A result recorded against a dirty tree names a commit whose")
        print("  code is not what was tested. Commit or stash first, or set")
        print("  XAIOS_LOCAL_GATES_ALLOW_DIRTY=1 to record it as untrustworthy.")
        return 1

    selected = [g for g in GATES if only is None or g[0] == only]
    if not selected:
        print(f"local-gates: no gate named {only}")
        return 1

    print(f"local-gates: {len(selected)} gates against {commit[:12]}"
          f"{' (DIRTY TREE)' if dirty else ''}")
    results = []
    for name, target, budget in selected:
        started = time.monotonic()
        print(f"  .... {name}")
        completed = subprocess.run(["make", target], cwd=str(ROOT),
                                   capture_output=True, text=True,
                                   timeout=budget)
        elapsed = round(time.monotonic() - started, 1)
        passed = completed.returncode == 0
        log = BUILD / f"local-gate-{name}.log"
        log.write_text(completed.stdout + completed.stderr, encoding="utf-8")
        preserve_serial(name)
        results.append({"gate": name, "passed": passed,
                        "exit_code": completed.returncode,
                        "seconds": elapsed, "log": str(log)})
        print(f"  {'ok  ' if passed else 'FAIL'} {name} ({elapsed}s)"
              f"{'' if passed else f' -- see {log.relative_to(ROOT)}'}")

    passed = all(r["passed"] for r in results)
    # The record is written whether or not it passed. A failing run is a fact
    # about this commit and worth keeping; only a dirty tree is refused.
    RECORD.write_text(json.dumps({
        "commit": commit,
        "commit_subject": git("log", "-1", "--pretty=%s"),
        "tree_clean": not dirty,
        "recorded_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host": f"{os.uname().sysname} {os.uname().machine}",
        "qualification_evidence": False,
        "complete": only is None,
        "gates": results,
        "passed": passed,
    }, indent=2) + "\n", encoding="utf-8")
    print(f"local-gates: record written to {RECORD}")

    if not passed:
        failed = [r["gate"] for r in results if not r["passed"]]
        print(f"local-gates: failed -- {', '.join(failed)}")
        return 1
    scope = "all local gates" if only is None else only
    print(f"local-gates: {scope} passed against {commit[:12]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
