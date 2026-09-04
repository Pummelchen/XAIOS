#!/usr/bin/env python3
"""Log in to a release-configuration RISC-V guest over SSH and run applications.

The other RISC-V gates boot the boot-test configuration, where the shell's
commands are built into the kernel and no on-demand application is ever
launched. The release configuration -- the one the other architectures ship
as `make image` -- launches applications as processes, and on RISC-V that
path had never run. When it first did, it found three kernel defects in a
row: no per-process address spaces (the child overwrote its parent's
mappings), a supervisor-access depth counter shared between harts, and an
idle wait that put a worker hart to sleep with nothing armed to wake it.

This gate boots the release configuration, logs in with the default
credentials, and runs the smallest application, a query-driven one, and the
process monitor, checking each one's output and that the machine is still
answering afterwards. It also checks that the monitor sees every hart: the
usage table used to be sized when only the boot hart was online.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import riscv64_gate_lib as rvgate  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
GATE_DIR = BUILD / "qemu-riscv64-release-gate"
HARTS = 4
COMMAND_TIMEOUT = 90


def reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def ssh(port: int, command: str) -> tuple[int, str]:
    """One command as admin, by password. A refused connection is retried:
    the guest's sshd occasionally refuses a password right after a session
    closed, and that is a separate question from whether the command runs."""
    for attempt in range(3):
        finished = subprocess.run(
            ["sshpass", "-p", "xaios", "ssh",
             "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
             "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no",
             "-o", "ConnectTimeout=25", "-p", str(port), "admin@127.0.0.1", command],
            capture_output=True, text=True, timeout=COMMAND_TIMEOUT,
        )
        if finished.returncode != 255:
            return finished.returncode, finished.stdout
        time.sleep(2)
    return 255, finished.stdout + finished.stderr


def check(condition: bool, message: str, problems: list) -> None:
    if not condition:
        problems.append(message)


def main() -> int:
    if not rvgate.available():
        print("qemu-system-riscv64 is not installed; skipping", file=sys.stderr)
        return 0
    if shutil.which("sshpass") is None:
        print("sshpass is not installed; this gate logs in by password", file=sys.stderr)
        return 2
    for missing in rvgate.prerequisites():
        print(f"missing: {missing}", file=sys.stderr)
        return 2
    if GATE_DIR.exists():
        shutil.rmtree(GATE_DIR)
    GATE_DIR.mkdir(parents=True)
    log = GATE_DIR / "serial.log"
    state = GATE_DIR / "state"
    port = reserve_port()
    problems: list = []

    guest = rvgate.launch(log, state, harts=HARTS, ssh_port=port)
    try:
        if not rvgate.wait_ready(guest, log, timeout=900):
            problems.append("the guest did not come up to a running sshd")
            problems.extend(rvgate.problems(rvgate.read(log), [], label="boot"))
            return report(problems)
        time.sleep(3)

        rc, out = ssh(port, "hello")
        check(rc == 0 and "hello world from C userspace" in out and "hello: complete" in out,
              f"hello over ssh: rc={rc} output={out.strip()[:200]!r}", problems)

        rc, out = ssh(port, "sysinfo")
        check(rc == 0 and "monotonic_nanos=" in out and "sysinfo: complete" in out,
              f"sysinfo over ssh: rc={rc} output={out.strip()[:200]!r}", problems)

        rc, out = ssh(port, "xtop --plain --columns 100 --rows 30")
        check(rc == 0 and "XAIOS xtop sample_ms=" in out and "xtop: complete" in out,
              f"xtop over ssh: rc={rc} output={out.strip()[:200]!r}", problems)
        check(f"cpus={HARTS}" in out,
              f"xtop reported the wrong CPU count on a {HARTS}-hart machine: "
              f"{out.splitlines()[0][:120] if out else ''!r}", problems)

        # Still answering, which a kernel that faulted or a hart that fell
        # asleep in a syscall would not be.
        rc, out = ssh(port, "xaiosctl status")
        check(rc == 0 and "ssh=running" in out,
              f"the machine stopped answering after the applications: rc={rc}", problems)

        text = rvgate.read(log)
        check(rvgate.PANIC not in text, "the guest panicked", problems)
        check("mode=per-hart-user-aspace" in text,
              "the kernel did not report per-hart user address spaces", problems)
        for pattern in ("/bin/hello", "/bin/sysinfo", "/bin/xtop"):
            check(f"reaped transient process" in text and pattern in text,
                  f"{pattern} was not launched as a process", problems)
    finally:
        rvgate.stop(guest)
    return report(problems)


def report(problems: list) -> int:
    if problems:
        for problem in problems:
            print(f"FAIL: {problem}", file=sys.stderr)
        return 1
    print(f"qemu-riscv64-release-gate: release configuration on {HARTS} harts ran "
          f"hello, sysinfo and xtop as processes over SSH and kept answering")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
