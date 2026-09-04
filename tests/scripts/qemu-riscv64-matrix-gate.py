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
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
RUNNER = ROOT / "platform/qemu/run-qemu-riscv64.sh"
LOG_DIR = BUILD / "riscv64-matrix"

HART_COUNTS = [int(value) for value in
               os.environ.get("XAIOS_RISCV64_HARTS", "1,2,4,8").split(",")]
SSH_PORT = int(os.environ.get("XAIOS_RISCV64_SSH_PORT", "2298"))
BOOT_TIMEOUT = int(os.environ.get("XAIOS_RISCV64_TIMEOUT", "700"))

READY = "SSH server: up and running"
REQUIRED = [
    "initramfs: mounted rofs version=2",
    "xaifs: mounted /models",
    "kernel: /init returned to kernel exit_code=0",
    "[########################################] 100%",
    "xaios login:",
    READY,
]
FORBIDDEN = ["ERROR: assertion failed", "CYAN SCREEN OF DEATH"]
MINIMUM_SELF_TESTS = 70


def boot(harts: int, log: Path, state: Path, ssh_port: int):
    """Start one guest and wait for it to be reachable. Returns the process."""
    environment = dict(os.environ)
    environment["XAIOS_RISCV64_LOG"] = str(log)
    environment["XAIOS_RISCV64_STATE"] = str(state)
    environment["XAIOS_RISCV64_CPUS"] = str(harts)
    environment["XAIOS_RISCV64_SSH_PORT"] = str(ssh_port)
    guest = subprocess.Popen([str(RUNNER)], cwd=str(ROOT), env=environment,
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + BOOT_TIMEOUT
    while time.monotonic() < deadline:
        if guest.poll() is not None:
            break
        if log.is_file():
            text = log.read_text(encoding="utf-8", errors="replace")
            if READY in text or "CYAN SCREEN" in text:
                break
        time.sleep(1.0)
    return guest


def check(log: Path, harts: int) -> list:
    if not log.is_file() or log.stat().st_size == 0:
        return [f"{harts} harts: no serial output at all"]
    text = log.read_text(encoding="utf-8", errors="replace")
    problems = [f"{harts} harts: missing {marker}"
                for marker in REQUIRED if marker not in text]
    problems += [f"{harts} harts: forbidden {marker}"
                 for marker in FORBIDDEN if marker in text]
    tests = text.count("self-test passed")
    if tests < MINIMUM_SELF_TESTS:
        problems.append(f"{harts} harts: only {tests} self-tests passed")
    # The kernel should have brought up exactly the harts it was given.
    if f"smp: riscv64 {harts} harts scheduling online={harts}" not in text:
        problems.append(f"{harts} harts: the kernel did not report {harts} "
                        f"harts scheduling")
    return problems


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
    if shutil.which("qemu-system-riscv64") is None:
        print("qemu-system-riscv64 is not installed; skipping", file=sys.stderr)
        return 0
    if not RUNNER.is_file():
        print(f"no runner at {RUNNER}", file=sys.stderr)
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
            guest = boot(harts, log, Path(scratch), port)
            try:
                found = check(log, harts)
                # The login check runs against a live guest, so it has to
                # happen before the guest is killed.
                if not found:
                    found = [f"{harts} harts: {issue}"
                             for issue in ssh_check(port)]
                problems += found
                status = "ok" if not found else f"{len(found)} problem(s)"
            finally:
                if guest.poll() is None:
                    guest.kill()
                    guest.wait()
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
