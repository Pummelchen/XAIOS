#!/usr/bin/env python3
"""Check that the flushes volatile-cache safety depends on are actually issued.

The crash gate proves that killing a machine mid-write leaves nothing broken.
It proves it against an emulator that never loses a write it has acknowledged,
so it says nothing about a device with a volatile write cache -- one that
reports a write complete, holds it in RAM, and loses it when the power goes.

What makes xaiFS safe on such a device is ordering. A commit writes a new
catalog at an unused offset, *flushes*, then writes the other superblock slot,
and *flushes* again. If the first flush went missing, a device could persist
the superblock before the catalog it points at, and a reader after a power cut
would follow a valid-looking superblock to a catalog that was never written.
The emulator would never show it, and no gate would notice.

So the driver is built to say what it did -- one line per block write, one per
flush, in order -- and this reads the log back and checks the property those
proofs rest on: between the last write to the catalog region and the write that
flips a superblock, there is a flush. Every time, without exception.

This is not a claim about how a real disk behaves. It is a claim that the
ordering the argument depends on is being issued, which is the half that lives
in this code and can rot here.
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path
import shutil
import sys
from qemu_gate_lib import (arch_from_argv, qemu_boot_environment,
                           qemu_runner)

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
REPORT = BUILD / "qemu-write-ordering-gate.json"
LOG = BUILD / "qemu-write-ordering.log"  # rebound per arch in main
FIXTURE = BUILD / "xaios-crash-fixture.img"
WORKING = BUILD / "write-ordering-volume.img"
TIMEOUT_S = int(os.environ.get("XAIOS_WRITE_ORDERING_TIMEOUT", "600"))
# How many commits to watch before deciding there is enough evidence.
COMMITS = int(os.environ.get("XAIOS_WRITE_ORDERING_COMMITS", "6"))

TRACE = re.compile(
    rb"io-trace: seq=(\d+) op=(write|flush) sector=(\d+) bytes=(\d+)")
COMMITTED = re.compile(rb"crash-writer: committed chunk=(\d+)")
STARTED = re.compile(rb"crash-writer: ingest started")

SECTOR_BYTES = 512
SUPERBLOCK_BYTES = 4096
# The two superblock slots live at the very front of the volume, one 4096-byte
# block each. A write landing in either is the flip that publishes a commit.
SUPERBLOCK_SECTORS = frozenset(
    range((2 * SUPERBLOCK_BYTES) // SECTOR_BYTES))


def fail(message: str) -> int:
    print(f"write-ordering-gate: {message}")
    return 1


def state_dir(arch: str) -> Path:
    """RISC-V keeps its disks in a directory. Fresh each run: this gate
    reads what a volume holds after a boot, and one carrying the last
    run's answer would let a broken write pass."""
    return BUILD / f"write-ordering-{arch}-state"


def run_guest(arch: str) -> bytes:
    if not FIXTURE.is_file():
        raise SystemExit(
            f"no crash fixture at {FIXTURE}; run "
            f"tests/xai_fs/create_crash_fixture.py first")
    WORKING.unlink(missing_ok=True)
    WORKING.write_bytes(FIXTURE.read_bytes())

    environment = dict(os.environ)
    environment["XAIOS_XAI_FS_IMAGE"] = str(WORKING)
    # No host port forwarding: this gate does not use SSH, and claiming a
    # fixed port makes one stale emulator anywhere turn the run into a boot
    # that never happened.
    # serial_to_stdout matters here: this gate reads the boot from the
    # process it started, and one runner writes its console to a file
    # instead. Without it the log is empty and every assertion below reports
    # a kernel that never traced anything, which is not what happened.
    environment = qemu_boot_environment(
        arch, environment, state_dir=state_dir(arch), hostfwd_port="none",
        serial_to_stdout=True)
    LOG.unlink(missing_ok=True)
    with LOG.open("wb") as sink:
        process = subprocess.Popen(
            [str(ROOT / qemu_runner(arch).lstrip("./"))],
            cwd=ROOT, env=environment, stdout=sink,
            stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            start_new_session=True)
    try:
        deadline = time.monotonic() + TIMEOUT_S
        started_deadline = time.monotonic() + TIMEOUT_S / 2.0
        while process.poll() is None and time.monotonic() < deadline:
            text = LOG.read_bytes()
            if len(COMMITTED.findall(text)) >= COMMITS:
                break
            if not STARTED.search(text) and time.monotonic() > started_deadline:
                break
            time.sleep(0.05)
    finally:
        if process.poll() is None:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            process.wait(timeout=30)
    return LOG.read_bytes()


def main() -> int:
    arch = arch_from_argv(sys.argv[1:])
    global LOG, WORKING
    if arch != "aarch64":
        LOG = BUILD / f"qemu-write-ordering-{arch}.log"
        WORKING = BUILD / f"write-ordering-volume-{arch}.img"
    shutil.rmtree(state_dir(arch), ignore_errors=True)
    state_dir(arch).mkdir(parents=True, exist_ok=True)
    text = run_guest(arch)
    events = [
        {
            "seq": int(match.group(1)),
            "op": match.group(2).decode(),
            "sector": int(match.group(3)),
            "bytes": int(match.group(4)),
        }
        for match in TRACE.finditer(text)
    ]
    commits = len(COMMITTED.findall(text))

    failures = []
    if not events:
        failures.append(
            "the driver emitted no io-trace lines; the kernel must be built "
            "with XAIOS_IO_TRACE=1, which is what `make "
            "qemu-write-ordering-gate` does")
    if commits == 0:
        failures.append(
            "the guest never committed a chunk, so there was no commit "
            "ordering to check; build with XAIOS_CRASH_WRITER=1")

    # The property. Walk the trace; every write to a superblock slot must have
    # a flush between it and whatever was written before it. A superblock is
    # what publishes a commit, and publishing before flushing what it points at
    # is precisely the reordering a volatile cache is free to perform.
    superblock_writes = 0
    unflushed_publishes = []
    flushed_since_write = True
    for event in events:
        if event["op"] == "flush":
            flushed_since_write = True
            continue
        if event["sector"] in SUPERBLOCK_SECTORS:
            superblock_writes += 1
            if not flushed_since_write:
                unflushed_publishes.append(event["seq"])
            # The flip itself is a write, and what follows it needs its own
            # flush before the next publish.
            flushed_since_write = False
            continue
        flushed_since_write = False

    if unflushed_publishes:
        failures.append(
            f"{len(unflushed_publishes)} superblock write(s) were issued with "
            f"no flush since the previous write, at sequence numbers "
            f"{unflushed_publishes[:8]}; a device with a volatile cache is "
            f"free to persist the superblock before the catalog it points at")
    if not failures and superblock_writes == 0:
        failures.append(
            "no superblock write appeared in the trace, so the ordering "
            "property was never exercised")

    report = {
        "schema": "xaios.write-ordering.v1",
        "commits_observed": commits,
        "trace_events": len(events),
        "writes": sum(1 for event in events if event["op"] == "write"),
        "flushes": sum(1 for event in events if event["op"] == "flush"),
        "superblock_writes": superblock_writes,
        "unflushed_publishes": unflushed_publishes,
        "failures": failures,
        "passed": not failures,
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    WORKING.unlink(missing_ok=True)

    print(f"write-ordering-gate: commits={commits} events={len(events)} "
          f"writes={report['writes']} flushes={report['flushes']} "
          f"superblock_writes={superblock_writes} "
          f"unflushed_publishes={len(unflushed_publishes)}")
    if failures:
        for message in failures:
            print(f"write-ordering-gate: FAIL {message}")
        return 1
    print(f"write-ordering-gate: passed, every publish had a flush before it "
          f"report={REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
