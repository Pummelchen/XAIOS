#!/usr/bin/env python3
"""Which QEMU block backend actually loses a write it has already acknowledged?

`qemu-power-loss-gate` records the guest's I/O and replays it, rather than
asking QEMU to lose writes, and every comment explaining why rests on one
measurement. This is that measurement, so it can be repeated rather than
remembered -- and so that if a future QEMU changes the answer, someone can
find out in thirty seconds instead of arguing from a comment.

The method: `qemu-io` drives the same block layer a virtio-blk device drives.
Write a pattern, wait for qemu-io to report the write complete -- that report
is the acknowledgement the guest would have received -- then SIGKILL the
process group, which is exactly what the crash and power-loss gates do to the
emulator. Then read the file back from the host, the way a machine rebooting
after the cut would.

The answer, on QEMU 11.1.1 on this host:

    raw   cache=writeback  survived_kill=True
    raw   cache=unsafe     survived_kill=True
    qcow2 cache=writeback  survived_kill=False
    qcow2 cache=unsafe     survived_kill=False

raw survives either way, because the write reached the host through pwrite and
the host's page cache outlives the process; `cache=unsafe` only makes flushes
no-ops, which changes what a *host* power failure costs and changes nothing
about what a killed process loses. qcow2 does lose the write, and is useless
as a model of a device: what it loses is an L2 table entry in QEMU's own
metadata cache, so it drops writes that allocate a cluster and keeps writes
that land in a cluster already mapped. An overwrite -- which is what a
superblock flip is -- always survives. Which acknowledged writes vanish would
be decided by the image format's allocation state rather than by where the
guest put its flushes.

This prints and does not assert. Every outcome here is a fact about QEMU
rather than about XAIOS: raw beginning to lose writes on a kill would be a
change in the emulator and arguably an improvement, and failing a build over
it would be failing over good news. What it is for is keeping the claim
checkable.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PATTERN = 0xAB
# A megabyte in, so the write is nowhere near an image header, and in a region
# no format has allocated yet -- which is the case qcow2 treats differently.
OFFSET = 1 << 20
LENGTH = 64 * 1024
IMAGE_BYTES = 64 << 20


def acknowledged_then_killed(image: Path, image_format: str,
                             cache: str) -> str:
    """Write, wait for the acknowledgement, then kill. Returns what it said."""
    process = subprocess.Popen(
        ["qemu-io", "-f", image_format, f"--cache={cache}", str(image)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True, start_new_session=True)
    process.stdin.write(f"write -P 0x{PATTERN:02x} {OFFSET} {LENGTH}\n")
    process.stdin.flush()
    acknowledgement = ""
    while "wrote" not in acknowledgement:
        line = process.stdout.readline()
        if not line:
            break
        acknowledgement += line
    # A moment for anything asynchronous behind the acknowledgement to settle.
    # It should not matter -- the point of an acknowledgement is that it does
    # not -- and waiting makes the result a stronger statement rather than a
    # weaker one.
    time.sleep(0.3)
    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    process.wait(timeout=30)
    return acknowledgement.strip()


def survived(image: Path, image_format: str) -> bool:
    if image_format == "raw":
        with image.open("rb") as stream:
            stream.seek(OFFSET)
            return stream.read(LENGTH) == bytes([PATTERN]) * LENGTH
    # A qcow2 image has to be read through the format, and through a fresh
    # process: the one that wrote it is gone, which is the whole point.
    result = subprocess.run(
        ["qemu-io", "-f", image_format, "--cache=none", "-r", "-c",
         f"read -P 0x{PATTERN:02x} {OFFSET} {LENGTH}", str(image)],
        capture_output=True, text=True, check=False)
    blob = result.stdout + result.stderr
    return result.returncode == 0 and "Pattern verification failed" not in blob


def main() -> int:
    if shutil.which("qemu-io") is None:
        print("write-cache-probe: qemu-io is not on PATH; nothing measured")
        return 0
    with tempfile.TemporaryDirectory(prefix="xaios-write-cache-") as scratch:
        root = Path(scratch)
        for image_format in ("raw", "qcow2"):
            for cache in ("writeback", "unsafe"):
                image = root / f"{image_format}-{cache}.img"
                if image_format == "raw":
                    with image.open("wb") as stream:
                        stream.truncate(IMAGE_BYTES)
                else:
                    subprocess.run(
                        ["qemu-img", "create", "-f", image_format, str(image),
                         str(IMAGE_BYTES)],
                        check=True, capture_output=True)
                said = acknowledged_then_killed(image, image_format, cache)
                print(f"write-cache-probe: {image_format:5s} cache={cache:9s} "
                      f"ack={said!r} "
                      f"survived_kill={survived(image, image_format)}")
    print("write-cache-probe: see tools/xaios_write_log.py for what this "
          "means and what qemu-power-loss-gate does instead")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
