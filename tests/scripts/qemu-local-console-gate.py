#!/usr/bin/env python3
"""Exercise authenticated local-console shell behavior through QEMU TCG."""

from __future__ import annotations

import os
from pathlib import Path
import select
import shutil
import socket
import subprocess
import sys
import time

from qemu_gate_lib import (arch_from_argv, qemu_boot_environment,
                           qemu_runner)


ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
GATE_DIR = BUILD / "qemu-local-console-gate"
BOOT_TIMEOUT_SECONDS = 180.0
STEP_TIMEOUT_SECONDS = 30.0


class Console:
    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        self.process = process
        self.output = bytearray()

    def send(self, value: bytes) -> None:
        if self.process.stdin is None:
            raise RuntimeError("QEMU console stdin is unavailable")
        self.process.stdin.write(value)
        self.process.stdin.flush()

    def wait_for(self, marker: bytes, timeout: float) -> None:
        if self.process.stdout is None:
            raise RuntimeError("QEMU console stdout is unavailable")
        deadline = time.monotonic() + timeout
        while marker not in self.output:
            if self.process.poll() is not None:
                raise RuntimeError(
                    f"QEMU exited with status {self.process.returncode} while "
                    f"waiting for {marker!r}\n{self.tail()}"
                )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"timed out waiting for {marker!r}\n{self.tail()}")
            ready, _, _ = select.select(
                [self.process.stdout.fileno()], [], [], min(remaining, 0.25)
            )
            if ready:
                chunk = os.read(self.process.stdout.fileno(), 4096)
                if not chunk:
                    continue
                self.output.extend(chunk)
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()

    def checkpoint(self) -> int:
        return len(self.output)

    def wait_since(self, checkpoint: int, marker: bytes, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while marker not in self.output[checkpoint:]:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"timed out waiting for {marker!r}\n{self.tail()}")
            self.wait_for_growth(remaining)

    def wait_for_growth(self, timeout: float) -> None:
        if self.process.stdout is None:
            raise RuntimeError("QEMU console stdout is unavailable")
        if self.process.poll() is not None:
            raise RuntimeError(f"QEMU exited with status {self.process.returncode}")
        ready, _, _ = select.select(
            [self.process.stdout.fileno()], [], [], min(timeout, 0.25)
        )
        if ready:
            chunk = os.read(self.process.stdout.fileno(), 4096)
            if chunk:
                self.output.extend(chunk)
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()

    def tail(self) -> str:
        return bytes(self.output[-8192:]).decode(errors="replace")


def reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def run_checked(
    command: list[str], label: str, env: dict[str, str] | None = None
) -> None:
    print(f"+ {label}", flush=True)
    subprocess.run(command, cwd=ROOT, env=env, check=True, timeout=180)


def terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def main() -> int:
    arch = arch_from_argv(sys.argv[1:])
    # Every wait in this gate was sized against a machine with host
    # acceleration behind it. RISC-V runs the same boot through an
    # interpreter, and a login prompt that takes four times as long to answer
    # is a slower machine, not a broken one. Scaled here rather than at each
    # call site so no wait is left behind.
    global BOOT_TIMEOUT_SECONDS, STEP_TIMEOUT_SECONDS
    if arch == "riscv64":
        BOOT_TIMEOUT_SECONDS *= 5
        STEP_TIMEOUT_SECONDS *= 5
    gate_dir = GATE_DIR if arch == "aarch64" else Path(f"{GATE_DIR}-{arch}")
    if gate_dir.exists():
        shutil.rmtree(gate_dir)
    gate_dir.mkdir(parents=True, mode=0o700)
    persistent = gate_dir / "persistent.img"
    build_env = os.environ.copy()
    build_env.pop("XAIOS_SSH_USERS_FILE", None)
    build_env.pop("XAIOS_SSH_PASSWORD_AUTH", None)
    if arch == "riscv64":
        build_env["XAIOS_BOOT_TEST_APPS"] = "1"
        run_checked(["./scripts/build-riscv64.sh"],
                    "build riscv64 kernel", build_env)
        run_checked(["./scripts/build-riscv64-image.sh"],
                    "build riscv64 image", build_env)
    else:
        run_checked(
            ["make", "image"], "build default local-console image", build_env
        )

    qemu_env = qemu_boot_environment(
        arch, build_env, persistent=persistent, state_dir=gate_dir / "state",
        hostfwd_port=reserve_port(), smp=4, serial_to_stdout=True)
    if arch == "aarch64":
        qemu_env["XAIOS_QEMU_ACCEL"] = "tcg"
    process = subprocess.Popen(
        [qemu_runner(arch)],
        cwd=ROOT,
        env=qemu_env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
    )
    console = Console(process)
    try:
        console.wait_for(b"xaios login: ", BOOT_TIMEOUT_SECONDS)

        checkpoint = console.checkpoint()
        console.send(b"admin\rwrong-password\r")
        # Two waits, not one match across a line break. The kernel shares this
        # console, so anything it logs between the refusal and the next prompt
        # -- a denied open from the login program, say -- breaks a contiguous
        # match while proving nothing about the refusal. What matters is that
        # the wrong password was refused and that the machine asked again.
        console.wait_since(checkpoint, b"Login incorrect", STEP_TIMEOUT_SECONDS)
        console.wait_since(checkpoint, b"xaios login: ", STEP_TIMEOUT_SECONDS)

        checkpoint = console.checkpoint()
        console.send(b"admin\rxaios\r")
        console.wait_since(
            checkpoint, b"XAIOS local console session opened", STEP_TIMEOUT_SECONDS
        )
        console.wait_since(checkpoint, b"admin@xaios", STEP_TIMEOUT_SECONDS)

        checkpoint = console.checkpoint()
        console.send(b"pong\r")
        console.wait_since(
            checkpoint, b"PONG  Human wins: 0  Computer wins: 0",
            STEP_TIMEOUT_SECONDS,
        )
        console.wait_since(checkpoint, b"Speed: 100.00%", STEP_TIMEOUT_SECONDS)
        console.send(b"wsppq")
        console.wait_since(checkpoint, b"\x1b[?1049l", STEP_TIMEOUT_SECONDS)
        console.wait_since(checkpoint, b"admin@xaios", STEP_TIMEOUT_SECONDS)

        checkpoint = console.checkpoint()
        console.send(
            b"mkdir /state/local-console\r"
            b"cd /state/local-console\r"
            b"write note.txt console-ok\r"
            b"cat note.txt\r"
            b"pwd\r"
        )
        console.wait_since(checkpoint, b"console-ok", STEP_TIMEOUT_SECONDS)
        console.wait_since(checkpoint, b"/state/local-console", STEP_TIMEOUT_SECONDS)

        checkpoint = console.checkpoint()
        console.send(b"does-not-exist\r")
        console.wait_since(
            checkpoint,
            b"xaios: does-not-exist: command not found",
            STEP_TIMEOUT_SECONDS,
        )
        console.wait_since(checkpoint, b"admin@xaios", STEP_TIMEOUT_SECONDS)

        checkpoint = console.checkpoint()
        console.send(b"logout\r")
        # Split for the same reason as the refusal above: the kernel shares
        # this console and may log between the shell exiting and the prompt.
        console.wait_since(checkpoint, b"logout", STEP_TIMEOUT_SECONDS)
        console.wait_since(checkpoint, b"xaios login: ", STEP_TIMEOUT_SECONDS)
    finally:
        terminate(process)
        persistent.unlink(missing_ok=True)

    print("PASS: authenticated local console shell and filesystem gate complete")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired, TimeoutError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
