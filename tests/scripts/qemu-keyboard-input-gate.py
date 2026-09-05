#!/usr/bin/env python3
"""Validate QEMU USB keyboard input through the local XAIOS console."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import select
import shutil
import socket
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
sys.path.insert(0, str(ROOT / "tests" / "scripts"))
from qemu_gate_lib import qemu_boot_environment, qemu_runner, smoke_timeout

BOOT_TIMEOUT_SECONDS = 180.0
STEP_TIMEOUT_SECONDS = 30.0

# The image each architecture types into, and how it is built. RISC-V has no
# separate release image target here: the kernel is the artefact, and the
# medium the local console boots is built from it.
IMAGE_BUILD = {
    "aarch64": [["make", "image"]],
    "x86_64": [["make", "image-x86_64"]],
    "riscv64": [["./scripts/build-riscv64.sh"],
                ["./scripts/build-riscv64-image.sh"]],
}


class Console:
    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        self.process = process
        self.output = bytearray()

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
                if chunk:
                    self.output.extend(chunk)
                    sys.stdout.buffer.write(chunk)
                    sys.stdout.buffer.flush()

    def tail(self) -> str:
        return bytes(self.output[-8192:]).decode(errors="replace")


def run_checked(command: list[str], label: str, env: dict[str, str]) -> None:
    print(f"+ {label}", flush=True)
    subprocess.run(command, cwd=ROOT, env=env, check=True, timeout=300)


def terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def qmp_connect(path: Path) -> socket.socket:
    deadline = time.monotonic() + STEP_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if path.exists():
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                client.connect(str(path))
                client.recv(4096)
                return client
            except OSError:
                client.close()
        time.sleep(0.05)
    raise TimeoutError("timed out waiting for QEMU QMP socket")


def qmp_command(client: socket.socket, payload: dict[str, object]) -> None:
    client.sendall((json.dumps(payload) + "\r\n").encode("ascii"))
    ready, _, _ = select.select([client], [], [], STEP_TIMEOUT_SECONDS)
    if not ready:
        raise TimeoutError(f"timed out waiting for QMP response to {payload!r}")
    response = client.recv(4096)
    if b'"return"' not in response:
        raise RuntimeError(f"QMP command failed: {response.decode(errors='replace')}")


def send_key_sequence(qmp_socket: Path, keys: list[str]) -> None:
    client = qmp_connect(qmp_socket)
    try:
        qmp_command(client, {"execute": "qmp_capabilities"})
        for key in keys:
            qmp_command(
                client,
                {
                    "execute": "send-key",
                    "arguments": {"keys": [{"type": "qcode", "data": key}]},
                },
            )
    finally:
        client.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch",
                        choices=("aarch64", "x86_64", "riscv64"), required=True)
    args = parser.parse_args()
    boot_timeout = smoke_timeout(args.arch, int(BOOT_TIMEOUT_SECONDS))
    step_timeout = smoke_timeout(args.arch, int(STEP_TIMEOUT_SECONDS))

    gate_dir = BUILD / f"qemu-keyboard-input-{args.arch}"
    if gate_dir.exists():
        shutil.rmtree(gate_dir)
    gate_dir.mkdir(parents=True, mode=0o700)

    build_env = os.environ.copy()
    build_env.pop("XAIOS_SSH_USERS_FILE", None)
    build_env.pop("XAIOS_SSH_PASSWORD_AUTH", None)
    build_env["XAIOS_BOOT_VERBOSE"] = "1"
    for build_command in IMAGE_BUILD[args.arch]:
        run_checked(build_command, f"build {args.arch} keyboard image",
                    build_env)

    qmp_socket = gate_dir / "qmp.sock"
    qemu_env = qemu_boot_environment(
        args.arch, build_env.copy(),
        keyboard="usb",
        qmp_socket=qmp_socket,
        persistent=gate_dir / "persistent.img",
        state_dir=gate_dir / "state",
        hostfwd_port="none",
        accel="tcg",
        # This reads the console out of the runner's stdout and types back
        # over QMP; RISC-V's runner writes the console to a file by default.
        serial_to_stdout=True)

    process = subprocess.Popen(
        [qemu_runner(args.arch)],
        cwd=ROOT,
        env=qemu_env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
    )
    console = Console(process)
    try:
        console.wait_for(b"input: xHCI HID boot keyboard initialized",
                         boot_timeout)
        console.wait_for(b"xaios login: ", boot_timeout)
        send_key_sequence(
            qmp_socket,
            ["a", "d", "m", "i", "n", "ret", "x", "a", "i", "o", "s", "ret"],
        )
        console.wait_for(b"XAIOS local console session opened",
                         step_timeout)
        console.wait_for(b"admin@xaios", step_timeout)
    finally:
        terminate(process)

    print(f"PASS: {args.arch} QEMU USB keyboard local-console gate complete")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired, TimeoutError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
