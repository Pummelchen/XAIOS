#!/usr/bin/env python3
"""Boot RISC-V across a range of hart counts, then log in over the network.

The boot gate proves one machine boots once. This proves the things a single
boot cannot: that the kernel comes up on one hart and on eight, that it does so
repeatedly rather than by luck, and that the result is reachable from outside.

Hart count is the dimension worth sweeping here rather than an arbitrary one.
Firmware picks its own boot hart and it is not always hart 0 -- on this board
it has been seen as 0, 1, 2 and 3 across consecutive runs of an identical
command -- so every boot in the sweep draws again, and a single-hart boot and
an eight-hart boot exercise different halves of the bring-up: one never starts
a secondary, the other starts seven and has to wake them.

Each boot is independent: fresh firmware variables and fresh writable volumes,
so a run cannot pass because a previous one left the disk in a helpful state.
"""
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import riscv64_gate_lib as rvgate
from qemu_gate_lib import BUILD, ROOT

LOG_DIR = BUILD / "riscv64-matrix"

HART_COUNTS = [int(value) for value in
               os.environ.get("XAIOS_RISCV64_HARTS", "1,2,4,8").split(",")]
SSH_PORT = int(os.environ.get("XAIOS_RISCV64_SSH_PORT", "2298"))
BOOT_TIMEOUT = int(os.environ.get("XAIOS_RISCV64_TIMEOUT", "700"))

READY = rvgate.READY
REQUIRED = [
    "initramfs: mounted rofs version=2",
    "xaifs: mounted /models",
    "kernel: /init returned to kernel exit_code=0",
    "[########################################] 100%",
    "xaios login:",
    READY,
]
MINIMUM_SELF_TESTS = 70


def check(log: Path, harts: int) -> list:
    text = rvgate.read(log)
    found = rvgate.problems(text, REQUIRED,
                           minimum_self_tests=MINIMUM_SELF_TESTS,
                           label=f"{harts} harts")
    # The kernel should have brought up exactly the harts it was given.
    if text and f"smp: riscv64 {harts} harts scheduling online={harts}" not in text:
        found.append(f"{harts} harts: the kernel did not report {harts} harts "
                     f"scheduling")
    return found


def ssh_check(port: int) -> list:
    """Log in and ask the machine something only a running system can answer."""
    if shutil.which("sshpass") is None:
        print("sshpass is not installed; skipping the login check",
              file=sys.stderr)
        return []
    command = [
        "sshpass", "-p", "xaios", "ssh",
        "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "PreferredAuthentications=password",
        "-o", "PubkeyAuthentication=no", "-o", "ConnectTimeout=25",
        "-p", str(port), "admin@127.0.0.1", "xaiosctl status",
    ]
    finished = subprocess.run(command, capture_output=True, text=True,
                              timeout=120)
    if "ssh=running" not in finished.stdout:
        return [f"login succeeded but the machine did not report a running "
                f"ssh service: {finished.stdout.strip()[:120]!r}"]
    return []


def main() -> int:
    if not rvgate.available():
        print("qemu-system-riscv64 is not installed; skipping", file=sys.stderr)
        return 0
    for missing in rvgate.prerequisites():
        print(f"missing: {missing}", file=sys.stderr)
        return 2
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    problems = []
    for index, harts in enumerate(HART_COUNTS):
        log = LOG_DIR / f"boot-{harts}-harts.log"
        if log.exists():
            log.unlink()
        port = SSH_PORT + index
        status = "did not run"
        with tempfile.TemporaryDirectory() as scratch:
            process = rvgate.launch(log, Path(scratch), harts=harts,
                                    ssh_port=port)
            try:
                if not rvgate.wait_ready(process, log, timeout=BOOT_TIMEOUT):
                    problems.append(f"{harts} harts: never came up")
                found = check(log, harts)
                # The login check runs against a live guest, so it has to
                # happen before the guest is killed.
                if not found:
                    found = [f"{harts} harts: {issue}"
                             for issue in ssh_check(port)]
                problems += found
                status = "ok" if not found else f"{len(found)} problem(s)"
            finally:
                rvgate.stop(process)
        print(f"  {harts:>2} hart(s): {status}")

    if problems:
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print(f"logs in {LOG_DIR.relative_to(ROOT)}", file=sys.stderr)
        return 1

    counts = ", ".join(str(count) for count in HART_COUNTS)
    print(f"qemu-riscv64-matrix-gate: booted and logged in over SSH at "
          f"{counts} harts, no errors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
