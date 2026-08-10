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


ROOT = Path(__file__).resolve().parents[1]
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
        sock.bind(("0.0.0.0", 0))
        return int(sock.getsockname()[1])


def run_checked(command: list[str], env: dict[str, str] | None = None) -> None:
    print("+", " ".join(command), flush=True)
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
    if GATE_DIR.exists():
        shutil.rmtree(GATE_DIR)
    GATE_DIR.mkdir(parents=True, mode=0o700)
    password = GATE_DIR / "password"
    users = GATE_DIR / "sshd-users"
    persistent = GATE_DIR / "persistent.img"
    password.write_text("admin\n", encoding="ascii")
    password.chmod(0o600)
    run_checked(
        [
            sys.executable,
            "scripts/create-sshd-user-config.py",
            "--password-file",
            str(password),
            "--output",
            str(users),
            "--iterations",
            "100000",
        ]
    )

    build_env = os.environ.copy()
    build_env.update(
        {
            "XAIOS_SSH_USERS_FILE": str(users),
            "XAIOS_SSH_PASSWORD_AUTH": "1",
        }
    )
    run_checked(["make", "image"], build_env)

    qemu_env = build_env.copy()
    qemu_env.update(
        {
            "XAIOS_QEMU_ACCEL": "tcg",
            "XAIOS_QEMU_SMP": "4",
            "XAIOS_QEMU_HOSTFWD_PORT": str(reserve_port()),
            "XAIOS_PERSISTENT_IMAGE": str(persistent),
        }
    )
    process = subprocess.Popen(
        [str(ROOT / "scripts" / "run-qemu-aarch64.sh")],
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
        console.wait_since(checkpoint, b"Login incorrect\r\nxaios login: ", STEP_TIMEOUT_SECONDS)

        checkpoint = console.checkpoint()
        console.send(b"admin\radmin\r")
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
        console.wait_since(checkpoint, b"logout\r\nxaios login: ", STEP_TIMEOUT_SECONDS)
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
