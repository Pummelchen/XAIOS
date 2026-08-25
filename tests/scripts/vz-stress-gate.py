#!/usr/bin/env python3
"""Soak XAIOS on every core the host has and check the invariants held.

Repeats a full boot with /bin/smpstress, which runs threads pinned across the
cores until a deadline and then checks two things that admit no tolerance: a
contended counter must equal the sum of tallies each thread kept privately,
and a word owned by one thread must hold exactly that thread's count whatever
shares its cache line. Both are the failure modes this port has actually had
-- an atomic that aborted where exclusives were unsupported, and a stale cache
line written back over a neighbour's memory.

Repetition is the point. Every defect this found showed up on some runs and
not others, so a single green boot means very little here.

Like vz-gate this is local: it needs macOS on Apple Silicon and a signed
harness, so it is not part of CI and its result is not qualification evidence.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
VZ = BUILD / "vz"
REPORT = BUILD / "vz-stress-gate.json"
RUNS = int(os.environ.get("XAIOS_VZ_STRESS_RUNS", "4"))
CPUS = os.environ.get("XAIOS_VZ_STRESS_CPUS", "8")
BOOT_TIMEOUT_S = int(os.environ.get("XAIOS_VZ_STRESS_TIMEOUT", "420"))

VOLUMES = (
    ("vz-test.img", "xaios-virtio-test.img"),
    ("vz-persistent.img", "xaios-persistent.img"),
    ("vz-model.img", "xaios-model-volume.img"),
    ("vz-storage-admin.img", None),
    ("vz-system.img", "xaios-system.img"),
    ("vz-system2.img", "xaios-system.img"),
)

REQUIRED = (
    ("stress app ran", re.compile(r"/bin/smpstress: sustained multi-core load")),
    ("threads spread over the cores",
     re.compile(r"/bin/smpstress: started=([1-9]\d*)")),
    ("contended counter and neighbour words exact",
     re.compile(r"/bin/smpstress: contended counter and neighbour words exact")),
    ("create/join churn deterministic",
     re.compile(r"/bin/smpstress: create/join churn deterministic")),
    ("stress app completed", re.compile(r"/bin/smpstress: complete")),
)

FORBIDDEN = (
    ("kernel panic", re.compile(r"CYAN SCREEN OF DEATH")),
    ("assertion failure", re.compile(r"ERROR: assertion failed")),
    ("lost updates", re.compile(r"/bin/smpstress: contended counter lost updates")),
    ("neighbour corrupted",
     re.compile(r"/bin/smpstress: neighbouring word corrupted")),
)

INCREMENTS = re.compile(r"/bin/smpstress: threads=\d+ increments=(\d+)")


def fail(message: str) -> int:
    print(f"vz-stress-gate: {message}")
    return 1


def prepare() -> str | None:
    if not (VZ / "xaios-vz").is_file():
        return "harness missing; build and sign platform/virtualization-framework/xaios_vz.swift first"
    subprocess.run([str(ROOT / "platform/virtualization-framework/build-vz-disk.sh")], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    shutil.copy(VZ / "xaios-vz-disk.img", VZ / "run-disk.img")
    for target, source in VOLUMES:
        destination = VZ / target
        if source is None:
            if not destination.is_file():
                destination.write_bytes(b"\0" * (16384 * 512))
            continue
        shutil.copy(BUILD / source, destination)
    return None


def run_once(index: int) -> tuple[str, bool]:
    log = VZ / f"vz-stress-{index:02d}.log"
    shutil.copy(VZ / "xaios-vz-disk.img", VZ / "run-disk.img")
    command = [str(VZ / "xaios-vz"), str(VZ / "run-disk.img")]
    command += [str(VZ / target) for target, _ in VOLUMES]
    command += ["--memory-mib", "4096", "--cpus", CPUS]
    settled = False
    with log.open("wb") as handle:
        process = subprocess.Popen(command, stdout=handle,
                                   stderr=subprocess.STDOUT,
                                   stdin=subprocess.DEVNULL)
        deadline = time.monotonic() + BOOT_TIMEOUT_S
        try:
            while time.monotonic() < deadline:
                text = log.read_bytes().decode("utf-8", "replace")
                if "/bin/smpstress: complete" in text or \
                        "CYAN SCREEN OF DEATH" in text:
                    settled = True
                    break
                if process.poll() is not None:
                    break
                time.sleep(2.0)
        finally:
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
    # The framework holds an exclusive lock on every image until the process is
    # gone, so the next run cannot attach until this one has finished dying.
    while subprocess.run(["pgrep", "-f", "xaios-vz build/vz/run-disk.img"],
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL).returncode == 0:
        time.sleep(1.0)
    return log.read_bytes().decode("utf-8", "replace"), settled


def main() -> int:
    if sys.platform != "darwin":
        return fail("this gate runs only on macOS")
    problem = prepare()
    if problem is not None:
        return fail(problem)

    runs = []
    for index in range(1, RUNS + 1):
        text, settled = run_once(index)
        checks = [{"name": name, "passed": bool(pattern.search(text))}
                  for name, pattern in REQUIRED]
        faults = [{"name": name, "seen": bool(pattern.search(text))}
                  for name, pattern in FORBIDDEN]
        found = INCREMENTS.search(text)
        passed = all(c["passed"] for c in checks) and \
            not any(f["seen"] for f in faults)
        runs.append({
            "run": index,
            "settled_before_timeout": settled,
            "increments": int(found.group(1)) if found else 0,
            "checks": checks,
            "faults": faults,
            "passed": passed,
        })
        state = "ok  " if passed else "FAIL"
        detail = f"increments={runs[-1]['increments']}"
        seen = [f["name"] for f in faults if f["seen"]]
        missed = [c["name"] for c in checks if not c["passed"]]
        if seen:
            detail += f" faults={','.join(seen)}"
        if missed:
            detail += f" missing={','.join(missed)}"
        print(f"  {state} run {index}/{RUNS} cpus={CPUS} {detail}")

    passed = all(run["passed"] for run in runs)
    REPORT.write_text(json.dumps({
        "target": "apple-virtualization-framework-aarch64",
        "qualification_evidence": False,
        "cpus": CPUS,
        "runs": runs,
        "passed": passed,
    }, indent=2) + "\n", encoding="utf-8")
    print(f"vz-stress-gate: report written to {REPORT}")
    if not passed:
        return fail(f"{sum(1 for r in runs if not r['passed'])} of {RUNS} runs failed")
    total = sum(run["increments"] for run in runs)
    print(f"vz-stress-gate: passed {RUNS} runs, {total} contended increments")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
