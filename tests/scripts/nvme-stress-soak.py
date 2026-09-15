#!/usr/bin/env python3
"""Wait for B-100 rather than argue about it.

`B-100` is the NVMe self-test's stress phase returning `XAIOS_ERR_IO` on a
starved guest: roughly two runs in ninety behind the row, which is rare enough
that one run tells you nothing and common enough that a long enough loop will
catch it. This harness is the loop. It holds the host under `--load` busy loops
and boots one of `qemu-nvme-gate`'s rows `--runs` times, keeping every console
and reporting the margin each boot measured.

It is a reproduction harness rather than a gate, and it reports like one: it
exits non-zero when any run failed -- a reproduction is reported as one, and a
gate failure with no `nvme:` line behind it as the other mode -- and zero when
the row survived every run. What it is looking for is `nvme: self-test
failed`, which the driver now follows with the step and, in the stress phase,
the exit it took -- the six the phase was thought to have and the three an audit
then found. A run that fails *without* that line is the other failure mode the
row names: a healthy guest that never reached its markers inside the gate's
deadline, which is load sensitivity in the harness and not this defect, so it is
counted apart.

Each run is the gate itself, invoked for one row, so the reproduction is also
the gate failing -- there is no second definition of the boot to drift from the
first. The images must already be built; `make qemu-nvme-gate` or the target
that calls this harness does that.

    python3 tests/scripts/nvme-stress-soak.py --row riscv64-aia --runs 20
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time

BUILD = Path("build")
GATE = Path("tests/scripts/qemu-nvme-gate.py")
ROWS = ("aarch64", "x86_64", "riscv64", "riscv64-aia")
FAILURE = "nvme: self-test failed"
# The driver now recovers from a dropped completion by re-arming the
# controller and retrying, so the defect can appear in a boot that still
# passes its gate. The soak keeps looking for the failure *and* for the
# recovery, because the recovery is the same event seen from the other
# side: a device that answered a command the host never submitted.
RECOVERY = "restarting the controller and retrying once"
MARGIN = re.compile(
    r"slowest=(?P<slowest>\d+) ns of \d+ budget batches=\d+ "
    r"batch_slowest=(?P<batch>\d+) ns singles=\d+ "
    r"single_slowest=(?P<single>\d+) ns"
)


def start_load(count: int) -> list[subprocess.Popen[bytes]]:
    """One busy loop per core, in its own session so it can be killed as one."""
    processes = []
    for _ in range(count):
        processes.append(
            subprocess.Popen(
                ["/usr/bin/yes"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        )
    return processes


def stop_load(processes: list[subprocess.Popen[bytes]]) -> None:
    for process in processes:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
    for process in processes:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def run_row(row: str, timeout: int) -> tuple[int, str]:
    """Run the gate for one row, stopping it as soon as the failure appears.

    The gate waits for markers that a failed self-test never prints, so a run
    that reproduces spends its whole deadline doing it -- the 1573-second
    failure `B-100` records, and the reason the first soak's reproduction cost
    eight minutes. The line this harness is looking for appears within seconds
    of the boot, so the run is stopped when it does and the console kept.
    """
    log = BUILD / f"qemu-nvme-gate-{row}.log"
    if log.exists():
        log.unlink()
    process = subprocess.Popen(
        [sys.executable, str(GATE), "--arch", row],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    deadline = time.monotonic() + timeout
    expired = False
    try:
        while process.poll() is None:
            if time.monotonic() >= deadline:
                expired = True
                break
            time.sleep(0.5)
            if log.exists():
                seen = log.read_text(errors="replace")
                if FAILURE in seen or RECOVERY in seen:
                    break
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
            # The gate's runner is in a session of its own, so killing the gate
            # does not kill the guest.
            kill_stray(row)
    if expired:
        raise subprocess.TimeoutExpired(str(GATE), timeout)
    text = log.read_text(errors="replace") if log.exists() else ""
    status = process.returncode if process.returncode is not None else 124
    return status, text


def kill_stray(row: str) -> None:
    """Kill a runner's QEMU that outlived the run.

    The gate starts its runner in a session of its own, so a gate killed from
    outside -- which is what this harness's backstop timeout does -- leaves the
    guest behind. One stray guest holding the row's disk would make every later
    run a measurement of the wrong machine, so it is named and killed rather
    than left to be found later.
    """
    listing = subprocess.run(
        ["ps", "-eo", "pid,command"], capture_output=True, text=True
    ).stdout
    for line in listing.splitlines():
        if "qemu-system" not in line or f"xaios-nvme-gate-{row}" not in line:
            continue
        fields = line.split(None, 1)
        if fields and fields[0].isdigit():
            print(f"nvme-stress-soak: killing stray pid={fields[0]}", flush=True)
            try:
                os.kill(int(fields[0]), signal.SIGKILL)
            except ProcessLookupError:
                pass


def interrupt(signum: int, frame: object) -> None:
    """Turn a signal into an exception so the load loops are stopped.

    They are in sessions of their own -- that is what makes them killable as a
    group -- so a harness that dies without stopping them leaves eight busy
    loops behind with nothing to stop them. The `finally` in `main` is the only
    place that happens, and it does not run on a default SIGTERM.
    """
    raise SystemExit(128 + signum)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--row", default="riscv64-aia", choices=ROWS)
    parser.add_argument("--runs", type=int, default=20)
    parser.add_argument("--load", type=int, default=8,
                        help="busy loops held for the whole soak; 0 measures idle")
    parser.add_argument("--timeout", type=int, default=900,
                        help="seconds allowed for one run of the row")
    arguments = parser.parse_args()

    if not GATE.exists():
        print(f"nvme-stress-soak: {GATE} not found; run from the repository root",
              file=sys.stderr)
        return 2
    if arguments.runs < 1:
        print("nvme-stress-soak: --runs must be at least 1", file=sys.stderr)
        return 2

    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGINT, interrupt)
    load = start_load(arguments.load)
    print(
        f"nvme-stress-soak: row={arguments.row} runs={arguments.runs} "
        f"load={arguments.load} loops pids={[p.pid for p in load]}",
        flush=True,
    )
    reproductions = 0
    other_failures = 0
    attempted = 0
    margins: list[tuple[int, int]] = []
    try:
        for run in range(1, arguments.runs + 1):
            attempted = run
            started = time.time()
            try:
                status, text = run_row(arguments.row, arguments.timeout)
            except subprocess.TimeoutExpired:
                kill_stray(arguments.row)
                status, text = 124, ""
            seconds = time.time() - started
            match = MARGIN.search(text)
            margin = (
                f"batch={match.group('batch')} single={match.group('single')}"
                if match is not None
                else "margin=none"
            )
            if match is not None:
                margins.append((int(match.group("batch")), int(match.group("single"))))
            if FAILURE in text or RECOVERY in text:
                reproductions += 1
                stamp = time.strftime("%Y%m%d-%H%M%S")
                kept = BUILD / f"nvme-stress-soak-{arguments.row}-{stamp}.log"
                shutil.copyfile(BUILD / f"qemu-nvme-gate-{arguments.row}.log", kept)
                kind = "REPRODUCED" if FAILURE in text else "RECOVERED"
                print(f"run {run}: {kind} after {seconds:.0f}s; console={kept}",
                      flush=True)
                for line in text.splitlines():
                    if (FAILURE in line or RECOVERY in line
                            or "restarting the controller" in line
                            or "nvme: io wait timed out" in line
                            or "nvme: io completion rejected" in line
                            or "nvme: stress" in line):
                        print(f"    {line.strip()}", flush=True)
                break
            if status != 0:
                other_failures += 1
                print(f"run {run}: failed without a self-test failure "
                      f"(exit={status}, {seconds:.0f}s) -- the other failure mode",
                      flush=True)
            else:
                print(f"run {run}: passed in {seconds:.0f}s {margin}", flush=True)
    finally:
        stop_load(load)

    print(
        f"nvme-stress-soak: runs={attempted} of {arguments.runs} "
        f"reproductions={reproductions} other_failures={other_failures}",
        flush=True,
    )
    if margins:
        batch = [entry[0] for entry in margins]
        single = [entry[1] for entry in margins]
        print(
            f"nvme-stress-soak: batch_slowest min={min(batch)} max={max(batch)} ns, "
            f"single_slowest min={min(single)} max={max(single)} ns, "
            f"budget=5000000000 ns",
            flush=True,
        )
    return 1 if reproductions or other_failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
