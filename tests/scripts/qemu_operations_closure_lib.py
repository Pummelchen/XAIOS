#!/usr/bin/env python3
"""Guest, SSH and process plumbing for the QEMU operations closure gate.

The gate is `qemu-operations-closure.py`. This module holds the machine it
drives -- reserving a port, starting a guest, talking to it over SSH, and
waiting for the markers a boot prints -- split out so that the gate, which
sequences those operations, stays under the repository's 500-line limit.
Nothing in the code below changed in the move; the gate imports these names.
"""

from __future__ import annotations

import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from qemu_gate_lib import smoke_timeout, timeout_scale  # noqa: E402


ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
DEBIAN_IMAGE = "xaios-debian13-network-client:13"
READY = "SSH server: up and running (tcp/22)"
# What the kernel says once per boot about the record the *next* boot reads.
# Waiting for SSH is not the same thing: a guest whose state volume never
# mounted reaches SSH just as fast, keeps its lifecycle record in memory, and
# leaves the next boot with nothing to find -- which this gate used to report
# as a missed unclean boot, blaming the second guest for what the first one
# never wrote. Only "durable" means the record is on a disk; every other
# verdict the kernel can print ("volatile", "unwritten", "absent") is a
# failure of the first boot and is reported as one, at the boot that caused it.
LIFECYCLE = "lifecycle: record "
LIFECYCLE_DURABLE = "lifecycle: record durable"


def reserve_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def run(command: list[str], *, env: dict[str, str] | None = None,
        timeout: int = 240) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(command), flush=True)
    try:
        return subprocess.run(command, cwd=ROOT, env=env, text=True,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT,
                              timeout=timeout, check=True)
    except subprocess.CalledProcessError as error:
        # A build that fails here used to be reported as a traceback with the
        # command and nothing about why: the output was captured and then
        # dropped by the exception, so the reason existed and was unreadable.
        if error.output:
            print(error.output, flush=True)
        raise


def wait_marker(path: Path, marker: str, count: int = 1,
                timeout: float = 180.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        text = path.read_text(errors="replace") if path.exists() else ""
        if text.count(marker) >= count:
            return
        time.sleep(0.25)
    tail = "\n".join(text.splitlines()[-80:])
    raise TimeoutError(f"missing marker {marker!r} count={count}\n{tail}")


def lifecycle_lines(path: Path) -> list[str]:
    text = path.read_text(errors="replace") if path.exists() else ""
    return [line.strip() for line in text.splitlines() if LIFECYCLE in line]


def wait_lifecycle_durable(path: Path, count: int = 1,
                           timeout: float = 180.0) -> list[str]:
    """Wait until `count` boots have each put their record on a disk.

    Raises as soon as a boot says otherwise, rather than waiting out the
    timeout: the kernel has already told us this boot's record will not
    survive, so no later boot can make that true.
    """
    deadline = time.monotonic() + timeout
    lines: list[str] = []
    while time.monotonic() < deadline:
        lines = lifecycle_lines(path)
        bad = [line for line in lines if LIFECYCLE_DURABLE not in line]
        if bad:
            raise RuntimeError(
                "guest reported its lifecycle record is not durable, so a "
                "later boot cannot detect this one: " + "; ".join(bad)
            )
        if len(lines) >= count:
            return lines
        time.sleep(0.25)
    raise TimeoutError(
        f"missing {count} durable lifecycle record(s); saw {lines!r}"
    )


def stop(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=10)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=10)


def ssh_base(key: Path, port: int, host: str = "127.0.0.1") -> list[str]:
    return [
        "ssh", "-F", "/dev/null", "-i", str(key),
        "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=5",
        "-p", str(port), f"admin@{host}",
    ]


def ssh_reboot(key: Path, port: int) -> None:
    """Ask the guest to reboot, and do not require ssh to come back cleanly.

    `reboot` is the one command whose success destroys the connection carrying
    it. Whether ssh exits 0, exits non-zero, or hangs until its own timeout
    depends on whether the guest manages to close the channel before it goes
    down -- which is a race with the machine's own shutdown, and on a runner
    with no hardware virtualisation the guest loses it. This gate asserted a
    clean exit within 30 s and had been failing that way on CI since
    2026-09-02, with `subprocess.TimeoutExpired` on the word `reboot`.

    Nothing is lost by not asserting it. The evidence that the reboot happened
    is on the console and is checked immediately below: the lifecycle record
    reaching its third durable write, and the guest printing its ready marker a
    third time. That is a stronger claim than an exit status -- it says the
    machine came back, not merely that it accepted the request.

    What is *not* waived is a guest that answers and declines, which is the
    other thing a non-zero status can mean and the reason this used to pass
    `ok=None`: the command schedules the power action and returns, so the
    status is the guest's answer, while 255 is ssh's own "the connection
    failed" and is what a shutdown racing the channel looks like. A refusal is
    raised here with the guest's words, because the phase below waits for
    lifecycle records a refusal will never produce and would otherwise fail
    with a sentence about the records rather than about the refusal.
    """
    try:
        result = subprocess.run(ssh_base(key, port) + ["reboot"], cwd=ROOT,
                                text=True, capture_output=True,
                                timeout=30 * timeout_scale())
    except subprocess.TimeoutExpired:
        return
    if result.returncode in (0, 255):
        return
    output = (result.stdout + result.stderr).strip()
    raise RuntimeError(
        f"the guest refused the reboot: exit={result.returncode} "
        f"output={output!r}"
    )


def ssh_command(key: Path, port: int, command: str, *, ok: bool | None = True,
                timeout: int = 30) -> str:
    result = subprocess.run(ssh_base(key, port) + [command], cwd=ROOT,
                            text=True, capture_output=True, timeout=timeout)
    if ok is True and result.returncode != 0:
        raise RuntimeError(
            f"SSH command failed rc={result.returncode}: {command}\n"
            f"stdout={result.stdout}\nstderr={result.stderr}"
        )
    if ok is False and result.returncode == 0:
        raise RuntimeError(f"SSH command unexpectedly succeeded: {command}")
    return result.stdout


def wait_ssh(key: Path, port: int, arch: str = "aarch64",
             timeout: int = 180) -> None:
    """Wait for the guest to answer, on a budget that knows what host it is on.

    Sixty seconds was written on a Mac, where these guests boot with hardware
    virtualisation. The CI runner has none and interprets every instruction, so
    the same boot takes several times longer and this raised
    `TimeoutError: SSH did not become ready` -- a sentence about the guest, for
    a condition of the host. That is B-39's finding, and this gate was missed
    when it was applied: it does not import `timeout_scale` at all.

    The scale is declared by the environment rather than sniffed at, which is
    the same arrangement the other gates use.

    The base was sixty and is a hundred and eighty. Sixty was enough here and
    not on the runner; a hundred and eighty times the CI scale gives nine
    minutes, and a boot that has not answered in nine minutes is broken rather
    than slow. The number the runner actually needs is not knowable from this
    machine -- it cannot be measured here, because here it passes -- and it is
    not knowable from the parity container either, which is arm64 and cannot
    build the x86-64 userland at all. What can be done is to stop the budget
    being the thing that fails and let the runner report its own figure.
    """
    scaled = smoke_timeout(arch, timeout)
    deadline = time.monotonic() + scaled
    while time.monotonic() < deadline:
        try:
            if ssh_command(key, port, "echo closure-ready",
                           timeout=10 * timeout_scale()).strip() == "closure-ready":
                return
        except (RuntimeError, subprocess.TimeoutExpired):
            pass
        time.sleep(0.25)
    raise TimeoutError(
        f"{arch}: SSH did not become ready on port {port} within {scaled}s "
        f"(base {timeout}s, scaled by qemu_gate_lib.smoke_timeout). On a host "
        f"without hardware virtualisation every guest here is interpreted; if "
        f"that is this host, XAIOS_GATE_TIMEOUT_SCALE is what declares it.")


def start_guest(arch: str, port: int, persistent: Path,
                log_path: Path) -> subprocess.Popen[bytes]:
    env = os.environ.copy()
    env["XAIOS_QEMU_HOSTFWD_PORT"] = str(port)
    if arch == "aarch64":
        env.update({
            "XAIOS_QEMU_ACCEL": "tcg",
            "XAIOS_QEMU_SMP": "4",
            "XAIOS_PERSISTENT_IMAGE": str(persistent),
        })
        runner = ROOT / "platform" / "qemu" / "run-qemu-aarch64.sh"
    elif arch == "x86_64":
        env.update({
            "XAIOS_QEMU_X86_ACCEL": "tcg",
            "XAIOS_QEMU_X86_SMP": "4",
            "XAIOS_X86_PERSISTENT_IMAGE": str(persistent),
        })
        runner = ROOT / "platform" / "qemu" / "run-qemu-x86_64.sh"
    else:
        # RISC-V has no hypervisor on any host this runs on, so there is no
        # accelerator to ask for, and its runner writes the console to a file
        # by default while this gate reads the boot out of the process's
        # stdout. Its host-forwarding knob has this architecture's own name.
        env.update({
            "XAIOS_RISCV64_SSH_PORT": str(port),
            "XAIOS_RISCV64_CPUS": "4",
            "XAIOS_RISCV64_SERIAL": "stdio",
            "XAIOS_PERSISTENT_IMAGE": str(persistent),
        })
        runner = ROOT / "platform" / "qemu" / "run-qemu-riscv64.sh"
    log_file = log_path.open("ab")
    process = subprocess.Popen([str(runner)], cwd=ROOT, env=env,
                               stdin=subprocess.DEVNULL, stdout=log_file,
                               stderr=subprocess.STDOUT,
                               start_new_session=True)
    process._xaios_log_file = log_file  # type: ignore[attr-defined]
    return process


def close_guest(process: subprocess.Popen[bytes]) -> None:
    stop(process)
    log_file = getattr(process, "_xaios_log_file", None)
    if log_file is not None:
        log_file.close()


def docker_ssh(key: Path, port: int, command: str) -> str:
    result = subprocess.run([
        "docker", "run", "--rm",
        "--add-host", "host.docker.internal:host-gateway",
        "--volume", f"{key}:/key:ro", DEBIAN_IMAGE,
        "ssh", "-F", "/dev/null", "-i", "/key",
        "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
        "-p", str(port), "admin@host.docker.internal", command,
    ], cwd=ROOT, text=True, capture_output=True, timeout=60)
    if result.returncode != 0:
        raise RuntimeError(f"Debian SSH failed: {result.stdout}\n{result.stderr}")
    return result.stdout


def assert_contains(value: str, *markers: str) -> None:
    missing = [marker for marker in markers if marker not in value]
    if missing:
        raise RuntimeError(f"missing {missing!r} in output {value!r}")
