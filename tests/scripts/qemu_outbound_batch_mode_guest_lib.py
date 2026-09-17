#!/usr/bin/env python3
"""Guest image build, boot and SSH plumbing for the B-37 batch-mode gate.

Moved verbatim out of `qemu-outbound-batch-mode-gate.py`: the image build that
packs one identity in, the QEMU lifecycle and its readiness wait, and the two
ways this gate drives the guest -- a no-PTY command with a bounded timeout and
a PTY-backed shell for the interactive path. The run context it reads
(paths, architecture, timeouts, the SSH base options) lives once in
`qemu_outbound_batch_mode_gate_lib.py`; the phase logic stays in the gate.

It is imported and is not itself a program: `python3
tests/scripts/qemu-outbound-batch-mode-gate.py` remains the only entry point,
with the same command line, output and exit codes.
"""

from __future__ import annotations

import os
import selectors
import subprocess
import time
from pathlib import Path

from qemu_gate_lib import (qemu_boot_environment, qemu_runner, smoke_timeout,
                           translate_qemu_env)
from qemu_outbound_batch_mode_gate_lib import (BOOT_TIMEOUT, BUILD,
                                               BUILD_COMMANDS,
                                               FATAL_BOOT_MARKERS, KEYS, ROOT,
                                               SSH_BASE, SSH_READY_MARKER,
                                               SUFFIX, TARGET_ARCH)


# ----------------------------------------------------------------- the guest

def build_guest_image(identity: Path) -> None:
    """Build the image with `identity` packed in as the client's key.

    A key reaches this guest no other way: the kernel refuses writes whose
    bytes look like credential material, which is what an OpenSSH private key
    is, so the runtime routes -- SFTP, a shell redirect -- are closed by
    design. That is why this gate builds twice.
    """
    env = os.environ.copy()
    env["XAIOS_AUTHORIZED_KEYS_FILE"] = str(KEYS / "inbound.pub")
    env["XAIOS_SSH_CLIENT_IDENTITY_FILE"] = str(identity)
    if TARGET_ARCH == "riscv64":
        env.setdefault("XAIOS_BOOT_TEST_APPS", "0")
    for command in BUILD_COMMANDS:
        print("+", " ".join(command), f"[identity={identity.name}]", flush=True)
        result = subprocess.run(command, cwd=ROOT, env=env, text=True,
                                capture_output=True,
                                timeout=smoke_timeout(TARGET_ARCH, 1200))
        if result.returncode != 0:
            tail = "\n".join((result.stdout + result.stderr).splitlines()[-40:])
            raise RuntimeError(f"guest image build failed:\n{tail}")


def start_guest(name: str, port: int) -> tuple[subprocess.Popen[bytes], object]:
    log_path = BUILD / f"qemu-outbound-batch-mode-gate{SUFFIX}-{name}.log"
    log_file = log_path.open("wb")
    persistent = BUILD / f"qemu-outbound-batch-mode-gate{SUFFIX}-{name}.img"
    persistent.unlink(missing_ok=True)
    env = qemu_boot_environment(
        TARGET_ARCH, os.environ.copy(), accel="tcg", smp=4,
        persistent=persistent, hostfwd_port=port,
        state_dir=BUILD / f"qemu-outbound-batch-mode-gate{SUFFIX}-{name}-state",
        serial_to_stdout=True)
    env.update(translate_qemu_env(TARGET_ARCH, {}))
    process = subprocess.Popen([str(ROOT / qemu_runner(TARGET_ARCH))], cwd=ROOT,
                               env=env, stdin=subprocess.DEVNULL,
                               stdout=log_file, stderr=subprocess.STDOUT)
    deadline = time.monotonic() + smoke_timeout(TARGET_ARCH, BOOT_TIMEOUT)
    while time.monotonic() < deadline:
        if log_path.exists():
            text = log_path.read_text(errors="replace")
            if SSH_READY_MARKER in text:
                print(f"guest {name!r} is up on port {port}", flush=True)
                return process, log_file
            lower = text.lower()
            fatal = next((m for m in FATAL_BOOT_MARKERS if m.lower() in lower),
                         None)
            if fatal is not None:
                raise RuntimeError(f"fatal guest boot marker {fatal!r}")
        if process.poll() is not None:
            raise RuntimeError("QEMU exited before the guest was ready")
        time.sleep(0.25)
    raise TimeoutError(f"the guest never reached {SSH_READY_MARKER!r}")


def stop_guest(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


class GuestRun:
    """One guest command run with no PTY, and how long it took."""

    def __init__(self, command: str, output: str, status: int,
                 seconds: float) -> None:
        self.command = command
        self.output = output
        self.status = status
        self.seconds = seconds

    def record(self) -> dict[str, object]:
        return {"command": self.command, "exit_status": self.status,
                "seconds": round(self.seconds, 1),
                "output": self.output.strip()}


def guest_no_pty(port: int, command: str, *, timeout: float) -> GuestRun:
    """Run one command on the guest with no terminal and stdin closed.

    `-T` refuses a PTY outright and stdin is /dev/null, so a prompt written
    by whatever the guest launches has nobody to answer it. The timeout is
    the point of the exercise: it fires as a failure, never as a wait.
    """
    argv = ["ssh", "-T", *SSH_BASE, "-i", str(KEYS / "inbound"),
            "-p", str(port), "admin@127.0.0.1", command]
    print(f"GUEST (no pty)> {command}", flush=True)
    started = time.monotonic()
    try:
        result = subprocess.run(argv, cwd=ROOT, stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as expired:
        partial = (expired.stdout or b"") + (expired.stderr or b"")
        raise RuntimeError(
            f"NO PTY: still blocked after {timeout:.0f}s; "
            f"partial output = {partial!r}\n  command: {command}") from None
    seconds = time.monotonic() - started
    finished = GuestRun(command, result.stdout + result.stderr,
                        result.returncode, seconds)
    print(f"  exit {finished.status} after {seconds:.1f}s: "
          f"{finished.output.strip()!r}", flush=True)
    return finished


class GuestShell:
    """A PTY-backed guest session -- the path the Fusion gate relies on."""

    def __init__(self, port: int, timeout: float = 150.0) -> None:
        self.timeout = timeout
        self.process = subprocess.Popen(
            ["ssh", "-tt", *SSH_BASE, "-i", str(KEYS / "inbound"),
             "-p", str(port), "admin@127.0.0.1"],
            cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT)
        assert self.process.stdout is not None
        os.set_blocking(self.process.stdout.fileno(), False)
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        self.output = bytearray()
        self.cursor = 0

    def _drain(self) -> None:
        assert self.process.stdout is not None
        while True:
            try:
                chunk = self.process.stdout.read(4096)
            except BlockingIOError:
                return
            if not chunk:
                return
            self.output.extend(chunk)

    def expect(self, marker: bytes, description: str) -> bytes:
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            position = self.output.find(marker, self.cursor)
            if position >= 0:
                end = position + len(marker)
                seen = bytes(self.output[self.cursor:end])
                self.cursor = end
                return seen
            if self.process.poll() is not None:
                self._drain()
                break
            if self.selector.select(timeout=0.25):
                self._drain()
        tail = bytes(self.output[-4096:]).decode(errors="replace")
        raise RuntimeError(f"timed out waiting for {description}\n{tail}")

    def send(self, text: str) -> None:
        print(f"GUEST (pty)> {text.strip()}", flush=True)
        assert self.process.stdin is not None
        self.process.stdin.write(text.encode("ascii"))
        self.process.stdin.flush()

    def close(self) -> None:
        if self.process.poll() is None:
            try:
                self.send("exit\n")
            except (BrokenPipeError, OSError):
                pass
        try:
            self.process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=10)
