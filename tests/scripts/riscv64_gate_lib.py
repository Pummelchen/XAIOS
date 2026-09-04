#!/usr/bin/env python3
"""Booting the RISC-V machine, for the gates that need one.

Four gates boot this machine and each had grown its own copy of the same
thirty lines: start the runner with the right environment, watch the log for a
marker, give up after a timeout, kill whatever is left. Copies of a boot
routine drift the way any other copies do, and the ways they drift are exactly
the ways a gate stops testing what it says it tests -- a timeout that is
generous in one and tight in another, a kill that terminates politely in one
and not in the other.

The generic half -- comparing markers, deciding pass from fail -- comes from
qemu_gate_lib, which the other architectures' gates already use.
"""
import os
import shutil
import subprocess
import time
from pathlib import Path

from qemu_gate_lib import BUILD, ROOT, check_markers

RUNNER = ROOT / "platform/qemu/run-qemu-riscv64.sh"

#: The last thing a complete boot prints. Watched for, so a good run ends when
#: the boot ends rather than when the timeout does.
READY = "SSH server: up and running"
#: What a panic writes first, so a bad run ends promptly too.
PANIC = "CYAN SCREEN OF DEATH"

FORBIDDEN = ["ERROR: assertion failed", PANIC]


def available() -> bool:
    """Whether this machine can run the guest at all."""
    return shutil.which("qemu-system-riscv64") is not None


def prerequisites() -> list:
    """Build products a RISC-V gate cannot run without."""
    missing = []
    for needed in (RUNNER, BUILD / "kernel-riscv64/kernel.elf",
                   BUILD / "xaios-riscv64-initfs.img"):
        if not Path(needed).exists():
            missing.append(str(needed))
    return missing


def launch(log: Path, state: Path, *, harts: int = 4, ssh_port: int = 0,
           extra_env: dict = None) -> subprocess.Popen:
    """Start a guest and return it still running. The caller must kill it."""
    if log.exists():
        log.unlink()
    environment = dict(os.environ)
    environment["XAIOS_RISCV64_LOG"] = str(log)
    environment["XAIOS_RISCV64_STATE"] = str(state)
    environment["XAIOS_RISCV64_CPUS"] = str(harts)
    environment["XAIOS_RISCV64_SSH_PORT"] = str(ssh_port)
    if extra_env:
        environment.update(extra_env)
    return subprocess.Popen([str(RUNNER)], cwd=str(ROOT), env=environment,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)


def wait_ready(process: subprocess.Popen, log: Path, *, timeout: int = 700,
               ready: str = READY) -> bool:
    """Wait for the guest to come up, panic, or run out of time."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        if log.is_file():
            text = log.read_text(encoding="utf-8", errors="replace")
            if ready in text:
                return True
            if PANIC in text:
                return False
        time.sleep(1.0)
    return False


def stop(process: subprocess.Popen) -> None:
    """Kill a guest and reap it. Safe to call on one that has already exited."""
    if process.poll() is None:
        process.kill()
    process.wait()


def boot(log: Path, state: Path, *, harts: int = 4, ssh_port: int = 0,
         timeout: int = 700, ready: str = READY,
         kill_when_ready: bool = False, extra_env: dict = None) -> bool:
    """Run one guest to completion for a gate that does not talk to it.

    A gate that needs the machine alive -- to log in, say -- must use launch,
    wait_ready and stop instead: this kills the guest before it returns, and
    an SSH check against a dead machine reports an empty answer rather than a
    failure anyone can act on. That is exactly what it did once.

    `kill_when_ready` cuts the guest off with SIGKILL the moment it comes up,
    which is how the durability gate simulates losing power: a terminate would
    let QEMU flush, which is the opposite of the point.
    """
    process = launch(log, state, harts=harts, ssh_port=ssh_port,
                     extra_env=extra_env)
    try:
        return wait_ready(process, log, timeout=timeout, ready=ready)
    finally:
        stop(process)


def read(log: Path) -> str:
    """The serial output, or an empty string if the guest produced none."""
    if not log.is_file() or log.stat().st_size == 0:
        return ""
    return log.read_text(encoding="utf-8", errors="replace")


def self_tests(text: str) -> int:
    return text.count("self-test passed")


def problems(text: str, required, *, minimum_self_tests: int = 0,
             forbidden=None, label: str = "") -> list:
    """Everything wrong with one boot's output, named so a reader can act."""
    prefix = f"{label}: " if label else ""
    if not text:
        return [f"{prefix}no serial output at all -- qemu did not start, or "
                f"started and printed nothing"]
    found = [f"{prefix}missing: {marker}"
             for marker in check_markers(text, required)]
    for marker in (FORBIDDEN if forbidden is None else forbidden):
        if marker in text:
            found.append(f"{prefix}forbidden: {marker}")
    if minimum_self_tests:
        count = self_tests(text)
        if count < minimum_self_tests:
            found.append(f"{prefix}only {count} self-tests passed, expected at "
                         f"least {minimum_self_tests}")
    return found
