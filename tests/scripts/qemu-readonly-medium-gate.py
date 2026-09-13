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

B-94: THE RACE THIS GATE WAS LOSING WITH ITSELF. The driver prints the verdict
in two `klog` calls -- `...self-test passed discovery=1 ` and then
`medium=writable ` -- and the gate used to stop reading as soon as `medium=`
appeared anywhere in what it had. The console is forwarded in chunks, so the
read carrying the prefix does not always carry the value: the run that failed on
the runner was killed holding `medium=writ`, and the gate reported a guest that
had said nothing. It was not the read-only boot either, which is what the row
said, and which is why the row stayed open across three sightings: the failure
was read off a verdict that named two causes and threw away everything that
separated them. The captured console went to a file the aggregate does not
upload, so nobody could see the truncation.

Two things changed, and neither can turn a failure into a pass. Reading stops
only on a *complete* value -- the one this case expects, or the other one, which
is a real answer worth stopping for -- so a split token no longer ends the boot.
And a boot that does not report its marker now carries the emulator's exit
status and the tail of its console into the failure message, which is what named
the cause in both sightings this was tested against: the truncation above, and a
stale lock on another image that stopped QEMU before it started.

Asking QEMU directly what medium it holds -- which is what the row first asked
for -- was tried and dropped. `query-block` returns nothing for these drives,
because they are declared `-drive if=none` and attached with `-device`, and
`query-named-block-nodes` cannot answer it either: it reports the file-level
`ro` flag, and with `snapshot=on` QEMU puts a qcow2 overlay over the scratch
image whose *backing* file is the one named on the command line. Matching on
that name returns the same answer for both cases -- a signal with no
discriminating power, which is worse here than none, because it would read as
QEMU contradicting the guest. The guest's own line distinguishes the two causes
once it is not being cut in half: a device attached the other way round prints
the other complete value, and that is visible in the tail.
"""

from __future__ import annotations

import json
import os
import re
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
# The driver prints this line in two klog calls, so stopping as soon as the
# prefix is in hand kills the emulator between them. Wait for a *complete*
# value: the one this case expects, or the other one, which is an answer.
MEDIUM_VALUE = re.compile(r"medium=(?:read-only|writable)")
FATAL = ("CYAN SCREEN OF DEATH", "assertion failed", "KERNEL PANIC")
# Enough console to see what the boot was doing when it stopped. The whole
# capture is still written to its own file; this is what fits in a message a
# person reads out of a CI log.
CONSOLE_TAIL = 14

CASES = (
    ("read-only", "1", "medium=read-only"),
    ("writable", "0", "medium=writable"),
)


def boot(read_only: str, expected: str) -> tuple[str, dict[str, object]]:
    """Run one boot and return its console, and what the host can say about it."""
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
                if expected in text or any(f in text for f in FATAL):
                    break
                if MEDIUM_VALUE.search(text):
                    # A complete value that is not the expected one: a real
                    # answer, and not the one this case asked for.
                    break
            elif process.poll() is not None:
                break
    finally:
        exited_on_its_own = process.poll() is not None
        if not exited_on_its_own:
            try:
                os.killpg(process.pid, 15)
                process.wait(timeout=10)
            except Exception:  # noqa: BLE001 - the boot is over either way
                try:
                    os.killpg(process.pid, 9)
                except ProcessLookupError:
                    pass
    return "".join(output), {
        "qemu_exit_status": process.returncode,
        "qemu_exited_on_its_own": exited_on_its_own,
    }


def main() -> int:
    failures: list[str] = []
    results: list[dict[str, object]] = []
    for name, knob, expected in CASES:
        print(f"qemu-readonly-medium-gate: booting with a {name} scratch "
              f"device", flush=True)
        text, host = boot(knob, expected)
        log = BUILD / f"qemu-readonly-medium-{name}.log"
        log.write_text(text, encoding="utf-8")
        fatal = [marker for marker in FATAL if marker in text]
        seen = expected in text
        results.append({"case": name, "expected": expected, "observed": seen,
                        "fatal_markers": fatal, "host_view": host,
                        "console": str(log.relative_to(ROOT))})
        if fatal:
            failures.append(
                f"the {name} boot died: {fatal}; the block self-test is the "
                f"only thing that runs differently between these two cases")
        elif not seen:
            other = [medium for medium in ("medium=read-only", "medium=writable")
                     if medium != expected and medium in text]
            if other:
                where = (f"the guest reported {other[0]}, so the scratch device "
                         f"was attached the other way round")
            elif not text.strip():
                where = ("the boot printed nothing at all, so it did not reach "
                         "the self-test")
            else:
                where = (f"the guest printed neither value, so the self-test "
                         f"did not reach the point of reading the bit")
            tail = "\n".join(
                line for line in text.splitlines()[-CONSOLE_TAIL:] if line)
            failures.append(
                f"the {name} boot never reported {expected!r}: {where}. "
                f"qemu exit={host.get('qemu_exit_status')} "
                f"exited_on_its_own={host.get('qemu_exited_on_its_own')}. "
                f"Console tail:\n{tail if tail else '(the boot printed nothing)'}")
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
