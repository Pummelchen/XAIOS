#!/usr/bin/env python3
"""Device mechanics for the power-loss gate.

The gate is `qemu-power-loss-gate.py`. This module holds the half that talks to
the emulator and to the host filesystem checker: the markers both sides search
a console for, the block range that publishes one commit, the fsck wrapper, the
boot that is killed even though the guest is still ingesting, and the count of
the commits a device had already promised to keep at a given point in its own
recording. It was split out so the gate, which builds the cases, replays them
and writes the report, stays under the repository's 500-line limit. The moved
code is verbatim; the gate imports these names, so the command line, the output
and the exit codes are unchanged.

It is imported and is not itself a program: `python3
tests/scripts/qemu-power-loss-gate.py` remains the only entry point.
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

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
# The gates here import qemu_gate_lib by name, which works when one is run as a
# script because its directory is sys.path[0]; stating it keeps the import
# working when this module is reached some other way.
sys.path.insert(0, str(ROOT / "tests" / "scripts"))
sys.path.insert(0, str(TOOLS))

from qemu_gate_lib import (arch_from_argv, qemu_boot_environment,  # noqa: E402
                           qemu_runner, smoke_timeout)

ARCH = arch_from_argv(sys.argv)
BOOT_TIMEOUT_S = float(smoke_timeout(
    ARCH, int(os.environ.get("XAIOS_POWER_LOSS_BOOT_TIMEOUT", "300"))))

STARTED = re.compile(rb"crash-writer: ingest started")
COMMITTED = re.compile(rb"crash-writer: committed chunk=(\d+)")
MOUNTED = re.compile(rb"xaifs: mounted \S+ device=\S+ generation=(\d+)")
MOUNT_SKIPPED = re.compile(rb"xaifs: mount skipped status=(-?\d+)")
# Both superblock slots, 4096 bytes each, at the very front of the volume. A
# write landing in either is the flip that publishes one commit, which is what
# lets the floor below be counted rather than guessed.
SUPERBLOCK_REGION_BYTES = 2 * 4096


def fsck(image: Path) -> dict:
    """The volume as something that did not write it sees it.

    The same host tool the crash gate uses, and for the same reason: a check
    written against the writer's assumptions can agree with the writer about
    something they are both wrong about.
    """
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(TOOLS) + os.pathsep + environment.get(
        "PYTHONPATH", "")
    result = subprocess.run(
        [sys.executable, str(TOOLS / "xaios_xai_fs.py"), "fsck",
         "--verify-data", str(image)],
        cwd=ROOT, env=environment, capture_output=True, text=True, check=False)
    # A nonzero exit means "this volume is not clean", which is an answer.
    # Only output that is not a report at all is the tool having failed.
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"status": "tool_failed",
                "errors": [result.stderr.strip() or result.stdout.strip()]}


def boot(volume: Path, console: Path, *, record_to: Path | None,
         stop_after_commits: int) -> bytes:
    """Boot the machine on `volume` and kill it once it has committed enough.

    No host port forwarding: this gate never uses SSH, and claiming a fixed
    port means one stale emulator anywhere on the machine turns the run into a
    boot that never happened -- reported, unhelpfully, as a guest that never
    committed anything. serial_to_stdout because the console is read out of
    the pipe this redirects; one runner writes it to a file of its own by
    default and would leave the pipe empty.
    """
    console.unlink(missing_ok=True)
    environment = dict(os.environ)
    environment["XAIOS_XAI_FS_IMAGE"] = str(volume)
    if record_to is not None:
        # QEMU's file driver opens, it does not create. An empty file is
        # enough; blklogwrites writes its superblock over the front.
        record_to.write_bytes(b"")
        environment["XAIOS_XAI_FS_WRITE_LOG"] = str(record_to)
    environment = qemu_boot_environment(ARCH, environment, hostfwd_port="none",
                                        serial_to_stdout=True)
    with console.open("wb") as sink:
        process = subprocess.Popen(
            [qemu_runner(ARCH)], cwd=ROOT, env=environment, stdout=sink,
            stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            start_new_session=True)
    try:
        deadline = time.monotonic() + BOOT_TIMEOUT_S
        # If the ingest never starts, the kernel was built without the crash
        # writer and no amount of waiting produces a commit. Say so in seconds
        # rather than burning the whole boot timeout.
        started_deadline = time.monotonic() + BOOT_TIMEOUT_S / 2.0
        while process.poll() is None:
            text = console.read_bytes()
            if len(COMMITTED.findall(text)) >= stop_after_commits:
                break
            if not STARTED.search(text) and time.monotonic() > started_deadline:
                break
            if time.monotonic() > deadline:
                break
            time.sleep(0.05)
        if process.poll() is None:
            # The whole process group, and SIGKILL: a shutdown the emulator
            # can see is not a power cut, and a graceful exit would flush the
            # log and close the image, which is the opposite of the point.
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            process.wait(timeout=30)
    finally:
        if process.poll() is None:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            process.wait(timeout=30)
    return console.read_bytes()


def commits_durable_before(entries, boundary: int) -> int:
    """How many commits had definitely reached the platter by `boundary`.

    One superblock write publishes one commit and moves the generation on by
    one, and the commit's third flush follows that write immediately. So a
    superblock write earlier in the log than the last durable point is a
    commit the device had promised to keep, and the volume must come back with
    at least that many.
    """
    return sum(1 for entry in entries
               if entry.is_write and entry.offset < SUPERBLOCK_REGION_BYTES
               and entry.index < boundary)
