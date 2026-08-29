#!/usr/bin/env python3
"""Measure what an operation costs in instructions, and notice when it changes.

Every performance number this project has is a count of events -- syscalls
made, pages free, gates passed -- or a wall-clock time measured on whatever
machine happened to run it. Neither says what an operation costs, and the
second is not comparable between two runs, let alone two people.

QEMU's -icount makes the virtual clock advance one nanosecond per guest
instruction. Under it the timings /bin/perfbench already reports stop being
times and become instruction counts: deterministic, independent of the host,
and reproducible by anyone with the same image. Two runs here differed by 16
parts in ten million on the wall figure and not at all on the per-operation
one.

What this gate is for is regression detection, not a performance claim. A
syscall that costs 494 instructions today and 900 tomorrow has had something
added to it, and that is worth knowing on the commit that did it rather than
on a benchmark machine months later. The numbers are also a baseline to
compare against when there is finally hardware to compare with.

It is not qualification evidence and it is not a benchmark under
docs/BENCHMARK-CONTRACT.md: an emulator counting its own instructions is not a
processor executing them.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
REPORT = BUILD / "qemu-instruction-cost.json"
BASELINE = ROOT / "tests" / "fixtures" / "instruction-cost-baseline.json"
TIMEOUT_S = int(os.environ.get("XAIOS_ICOUNT_TIMEOUT", "900"))

# Under -icount shift=0 the guest's clock counts instructions, so perfbench's
# "ns_per_op" is instructions per operation.
# Single-threaded work only. One vCPU executing a fixed sequence of
# instructions produces the same count every time, which is what makes a
# baseline meaningful; these three were byte-identical across two runs of the
# same image.
MEASUREMENTS = (
    ("syscall_1_thread",
     re.compile(r"/bin/perfbench: syscall threads=1 ops=\d+ ns_per_op=(\d+)")),
    ("socket_bind_close_1_thread",
     re.compile(r"/bin/perfbench: socket_bind_close threads=1 ops=\d+ "
                r"ns_per_op=(\d+)")),
    ("thread_create_join",
     re.compile(r"/bin/perfbench: thread_create_join ops=\d+ ns_per_op=(\d+)")),
)

# Reported, never pinned.
#
# The four-thread figure is the slowest thread's elapsed virtual time divided
# by the operations one thread did. Under -icount the virtual clock advances
# for every vCPU, so that number describes how the four interleaved, not what
# an operation costs -- and interleaving is not reproducible. Two runs of the
# same image, with nothing changed between them, gave 1842 and 1131: a 38.6%
# move that a pinned baseline would have reported as a regression on every
# other run, for ever.
#
# It is worth printing because serialisation is worth watching. It is not
# worth failing on, and the distinction is the whole reason this gate exists.
OBSERVED = (
    ("syscall_4_threads",
     re.compile(r"/bin/perfbench: syscall threads=4 ops=\d+ ns_per_op=(\d+)")),
)

# How far a measurement may move before this fails. Wide enough that a
# scheduling difference or one more branch does not cry wolf, narrow enough
# that doubling the cost of a syscall cannot pass.
TOLERANCE = float(os.environ.get("XAIOS_ICOUNT_TOLERANCE", "0.25"))


def measure() -> dict[str, int]:
    log = BUILD / "qemu-instruction-cost.log"
    environment = {**os.environ,
                   "XAIOS_QEMU_EXTRA_ARGS": "-icount shift=0,sleep=off"}
    with log.open("wb") as handle:
        # stdin is left alone and the process gets its own session, which is
        # what the other QEMU gates do. Handing /dev/null to a machine started
        # with -serial mon:stdio gives its monitor an immediate end of input,
        # and the boot stalls partway through the network bring-up every time
        # -- reliably enough to look like an instrumentation bug in the guest.
        process = subprocess.Popen(
            [str(ROOT / "platform/qemu/run-qemu-aarch64.sh")],
            stdout=handle, stderr=subprocess.STDOUT,
            env=environment, cwd=str(ROOT), start_new_session=True)
        deadline = time.monotonic() + TIMEOUT_S
        try:
            while time.monotonic() < deadline:
                time.sleep(5)
                text = log.read_bytes().decode("utf-8", "replace")
                if "/bin/perfbench: complete" in text:
                    break
                if process.poll() is not None:
                    break
        finally:
            process.terminate()
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()

    text = log.read_bytes().decode("utf-8", "replace")
    found = {}
    for name, pattern in MEASUREMENTS + OBSERVED:
        match = pattern.search(text)
        if match:
            found[name] = int(match.group(1))
    return found


def main() -> int:
    measured = measure()
    missing = [n for n, _ in MEASUREMENTS if n not in measured]
    if missing:
        print("qemu-instruction-cost: the boot did not report "
              f"{', '.join(missing)}")
        print(f"  see {(BUILD / 'qemu-instruction-cost.log').relative_to(ROOT)}")
        return 1

    pinned = {name: measured[name] for name, _ in MEASUREMENTS
              if name in measured}
    observed = {name: measured[name] for name, _ in OBSERVED
                if name in measured}

    if not BASELINE.is_file():
        BASELINE.parent.mkdir(parents=True, exist_ok=True)
        BASELINE.write_text(json.dumps(
            {"instructions_per_operation": pinned}, indent=2) + "\n",
            encoding="utf-8")
        print(f"qemu-instruction-cost: no baseline; recorded one at "
              f"{BASELINE.relative_to(ROOT)}")
        for name, value in pinned.items():
            print(f"  {name}: {value}")
        for name, value in observed.items():
            print(f"  {name}: {value} (reported, not pinned: not reproducible "
                  f"under -icount)")
        return 0

    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    expected = baseline["instructions_per_operation"]
    regressions = []
    for name, value in pinned.items():
        if name not in expected:
            continue
        reference = expected[name]
        drift = (value - reference) / reference if reference else 0.0
        arrow = "same" if abs(drift) < 0.005 else f"{drift:+.1%}"
        print(f"  {name}: {value} (baseline {reference}, {arrow})")
        if abs(drift) > TOLERANCE:
            regressions.append(
                f"{name} moved {drift:+.1%}, from {reference} to {value}")

    for name, value in observed.items():
        print(f"  {name}: {value} (reported, not pinned: not reproducible "
              f"under -icount)")

    REPORT.write_text(json.dumps({
        "target": "qemu-aarch64-icount",
        "qualification_evidence": False,
        "instructions_per_operation": pinned,
        "observed_not_pinned": observed,
        "baseline": expected,
        "tolerance": TOLERANCE,
        "passed": not regressions,
    }, indent=2) + "\n", encoding="utf-8")

    if regressions:
        print("qemu-instruction-cost: cost moved beyond tolerance")
        for regression in regressions:
            print(f"  - {regression}")
        print("  If the change is intended, update "
              f"{BASELINE.relative_to(ROOT)} in the same commit that causes it,")
        print("  so the new cost is a decision someone made rather than a "
              "number that drifted.")
        return 1
    print("qemu-instruction-cost: every operation costs what it did")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
