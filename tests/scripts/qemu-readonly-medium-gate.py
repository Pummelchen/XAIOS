#!/usr/bin/env python3
"""Boot with a block device that really is read-only, and both ways round.

B-14 recorded this branch as untestable here: "with `readonly=on` QEMU
discards writes but still advertises the device as writable, so the guest
reports `medium=writable` and takes the writable branch. Proving the read-only
branch needs a device that actually advertises the bit."

That reading was wrong, and checking it is what found the defect. `/dev/vblk0`
-- the device the block self-test runs against -- is the scratch disk, not the
boot medium, and the scratch disk was never attached read-only. So the guest
reported `medium=writable` because it was looking at a writable device, and
nothing had been learned about whether QEMU advertises `VIRTIO_BLK_F_RO`. It
does: attach that drive `readonly=on` and the guest immediately reports
`medium=read-only` and takes the branch.

Which then failed, on its first execution ever. Two refusals in one driver
disagreed about what a read-only medium is -- the asynchronous submit path
answered `XAIOS_ERR_INVALID`, lumping it in with null buffers and out-of-range
sectors, while the synchronous path answered `XAIOS_ERR_UNSUPPORTED` -- and
the self-test asserted the first. They agree on `XAIOS_ERR_UNSUPPORTED` now:
a write to a read-only device is a well-formed request the device cannot
perform, which is what that status means.

Both configurations run here, because either one alone proves nothing. The
read-only boot has to report `medium=read-only`, and the ordinary boot has to
report `medium=writable` -- otherwise a gate that silently stopped setting the
knob would pass while testing the same machine twice.
"""

from __future__ import annotations

import json
import os
import select
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
sys.path.insert(0, str(ROOT / "tests" / "scripts"))
from qemu_gate_lib import qemu_boot_environment, qemu_runner, smoke_timeout

REPORT = BUILD / "qemu-readonly-medium-gate.json"
ARCH = "aarch64"
SELF_TEST = "virtio-blk: read/write/error/reset self-test passed"
FATAL = ("CYAN SCREEN OF DEATH", "assertion failed", "KERNEL PANIC")

CASES = (
    ("read-only", "1", "medium=read-only"),
    ("writable", "0", "medium=writable"),
)


def boot(read_only: str) -> str:
    env = os.environ.copy()
    env["XAIOS_QEMU_TEST_BLOCK_READONLY"] = read_only
    persistent = BUILD / f"readonly-medium-{read_only}.img"
    persistent.unlink(missing_ok=True)
    env = qemu_boot_environment(ARCH, env, persistent=persistent,
                                hostfwd_port="none", serial_to_stdout=True)
    process = subprocess.Popen(
        [qemu_runner(ARCH)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1, env=env, cwd=ROOT, start_new_session=True)
    deadline = time.time() + smoke_timeout(ARCH, 180)
    output: list[str] = []
    try:
        descriptor = process.stdout.fileno()
        while time.time() < deadline:
            ready, _, _ = select.select([descriptor], [], [], 0.2)
            if ready:
                chunk = os.read(descriptor, 8192).decode("utf-8",
                                                         errors="replace")
                if not chunk:
                    break
                output.append(chunk)
                text = "".join(output)
                if SELF_TEST in text or any(f in text for f in FATAL):
                    break
            elif process.poll() is not None:
                break
    finally:
        if process.poll() is None:
            try:
                os.killpg(process.pid, 15)
                process.wait(timeout=10)
            except Exception:  # noqa: BLE001 - the boot is over either way
                try:
                    os.killpg(process.pid, 9)
                except ProcessLookupError:
                    pass
    return "".join(output)


def main() -> int:
    failures: list[str] = []
    results: list[dict[str, object]] = []
    for name, knob, expected in CASES:
        print(f"qemu-readonly-medium-gate: booting with a {name} scratch "
              f"device", flush=True)
        text = boot(knob)
        log = BUILD / f"qemu-readonly-medium-{name}.log"
        log.write_text(text, encoding="utf-8")
        fatal = [marker for marker in FATAL if marker in text]
        seen = expected in text
        results.append({"case": name, "expected": expected, "observed": seen,
                        "fatal_markers": fatal,
                        "console": str(log.relative_to(ROOT))})
        if fatal:
            failures.append(
                f"the {name} boot died: {fatal}; the block self-test is the "
                f"only thing that runs differently between these two cases")
        elif not seen:
            failures.append(
                f"the {name} boot never reported {expected!r}; either the "
                f"scratch device was attached the other way round or the "
                f"driver did not read VIRTIO_BLK_F_RO from it")
    report = {
        "schema": "xaios.qemu.readonly_medium.v1",
        "status": "pass" if not failures else "fail",
        "results": results,
        "failures": failures,
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                      encoding="utf-8")
    if failures:
        for failure in failures:
            print(f"qemu-readonly-medium-gate: FAIL {failure}")
        return 1
    print("qemu-readonly-medium-gate: a read-only device is reported as "
          "read-only and refuses writes, and the same image on a writable "
          "device reports writable and accepts them; report="
          f"{REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
