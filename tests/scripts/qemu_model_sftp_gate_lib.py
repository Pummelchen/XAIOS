#!/usr/bin/env python3
"""QEMU lifecycle and SSH/SFTP plumbing for the xaiFS model SFTP gate.

Moved verbatim out of `qemu-model-sftp-gate.py` so that neither file has to
carry the whole gate. This half is everything that touches a machine: the
port reservation, the two readiness waits, the process teardown, the fixture
writer, and the `ssh`, `sftp` and parallel-client helpers the scenario
drives. It also owns the run context both halves share -- the repository
paths, the selected architecture, the readiness marker and the verification
chunk size, taken from the same command line the gate was given. The package
manifests and register commands live in `qemu_model_sftp_package_lib.py`.
"""

from __future__ import annotations

import json
import os
import platform
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
sys.path.insert(0, str(ROOT / "tests" / "scripts"))
from qemu_gate_lib import (arch_from_argv, qemu_boot_environment, qemu_runner,
                           smoke_timeout)

ARCH = arch_from_argv(sys.argv)
SUFFIX = "" if ARCH == "aarch64" else f"-{ARCH}"
READY_MARKER = "SSH server: up and running (tcp/22)"
MODEL_CHUNK_SIZE = 2 * 1024 * 1024


def reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def wait_for_marker(
    log_path: Path,
    marker: str,
    timeout: float,
    process: subprocess.Popen[bytes],
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if log_path.exists():
            log = log_path.read_text(errors="replace")
            if marker in log:
                return
            if "System halted. Manual reset required." in log:
                raise RuntimeError("XAIOS halted before the SSH service became ready")
        if process.poll() is not None:
            raise RuntimeError(f"QEMU exited before readiness rc={process.returncode}")
        time.sleep(0.25)
    tail = ""
    if log_path.exists():
        tail = "\n".join(log_path.read_text(errors="replace").splitlines()[-60:])
    raise TimeoutError(f"timed out waiting for {marker!r}\n{tail}")


def stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except ProcessLookupError:
            return
        process.wait(timeout=10)


def wait_for_ssh(port: int, process: subprocess.Popen[bytes], timeout: float) -> None:
    deadline = time.monotonic() + timeout
    last_error = "no SSH probe attempted"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"QEMU exited before SSH key exchange rc={process.returncode}"
            )
        try:
            result = subprocess.run(
                [
                    "ssh-keyscan",
                    "-T",
                    "5",
                    "-p",
                    str(port),
                    "127.0.0.1",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
            )
        except subprocess.TimeoutExpired:
            last_error = "ssh-keyscan timed out"
        else:
            if result.returncode == 0 and "ssh-ed25519" in result.stdout:
                return
            last_error = (
                f"ssh-keyscan rc={result.returncode} stdout={result.stdout!r} "
                f"stderr={result.stderr!r}"
            )
        time.sleep(1.0)
    raise TimeoutError(f"timed out waiting for SSH key exchange: {last_error}")


def start_qemu_ready(
    log_path: Path, environment: dict[str, str]
) -> tuple[subprocess.Popen[bytes], object]:
    last_error: TimeoutError | None = None
    for attempt in range(2):
        log_file = log_path.open("wb")
        process = subprocess.Popen(
            [str(ROOT / qemu_runner(ARCH))],
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            preexec_fn=os.setsid,
        )
        try:
            wait_for_marker(log_path, READY_MARKER,
                            float(smoke_timeout(ARCH, 150)), process)
            return process, log_file
        except BaseException as error:
            stop_process(process)
            log_file.close()
            log_text = log_path.read_text(errors="replace")
            if isinstance(error, TimeoutError):
                last_error = error
            if (
                not isinstance(error, TimeoutError)
                or "XAIOS loader starting" in log_text
                or attempt != 0
            ):
                raise
            log_path.replace(BUILD / "qemu-model-sftp-firmware-attempt-1.log")
            time.sleep(1.0)
    assert last_error is not None
    raise last_error


def write_fixture(
    path: Path, size: int = 2 * 1024 * 1024 + 64 * 1024, seed: int = 11
) -> None:
    block = bytes((index * 13 + seed) & 0xFF for index in range(4096))
    with path.open("wb") as stream:
        remaining = size
        while remaining:
            data = block[: min(remaining, len(block))]
            stream.write(data)
            remaining -= len(data)


def sftp_arguments(key: Path, port: int, host: str) -> list[str]:
    return [
        "sftp",
        "-b",
        "-",
        "-i",
        str(key),
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        # Explicitly on. PreferredAuthentications names the order to try;
        # PubkeyAuthentication decides whether the key is offered at all. A
        # Host block in a developer's ~/.ssh/config that turns it off for
        # 127.0.0.1 -- a reasonable thing to have when logging into the guest
        # by password -- otherwise leaves the client loading the key and never
        # attempting it. CI runners have no such file, which is why this
        # failed on one machine and nowhere else.
        "-o",
        "PubkeyAuthentication=yes",
        "-o",
        "PreferredAuthentications=publickey",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "ConnectTimeout=20",
        "-P",
        str(port),
        f"admin@{host}",
    ]


def run_parallel_sftp(
    gate_dir: Path,
    key: Path,
    port: int,
    mac_commands: str,
    debian_commands: str,
) -> None:
    mac = subprocess.Popen(
        sftp_arguments(key, port, "127.0.0.1"),
        cwd=ROOT,
        text=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    docker_args = sftp_arguments(Path("/work/admin"), port,
                                  "host.docker.internal")
    debian = subprocess.Popen(
        [
            "docker",
            "run",
            "--interactive",
            "--rm",
            "--add-host",
            "host.docker.internal:host-gateway",
            "--volume",
            f"{gate_dir}:/work",
            "xaios-debian13-network-client:13",
            *docker_args,
        ],
        cwd=ROOT,
        text=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    host_name = "macOS" if platform.system() == "Darwin" else platform.system()
    clients = ((host_name, mac, mac_commands), ("Debian", debian, debian_commands))
    failures: list[str] = []
    for name, process, commands in clients:
        try:
            stdout, stderr = process.communicate(commands, timeout=600)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            failures.append(f"{name} SFTP timed out\n{stdout}\n{stderr}")
            continue
        if process.returncode != 0:
            failures.append(
                f"{name} SFTP failed rc={process.returncode}\n"
                f"commands={commands}\n{stdout}\n{stderr}"
            )
    if failures:
        raise RuntimeError("\n".join(failures))


def run_sftp(key: Path, port: int, commands: str) -> str:
    result = subprocess.run(
        sftp_arguments(key, port, "127.0.0.1"),
        cwd=ROOT,
        text=True,
        input=commands,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=600,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"sftp batch failed rc={result.returncode}\n"
            f"commands={commands}\nstdout={result.stdout}\nstderr={result.stderr}"
        )
    return result.stdout + result.stderr


def run_ssh(key: Path, port: int, command: str) -> str:
    result = subprocess.run(
        [
            "ssh",
            "-i",
            str(key),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "PubkeyAuthentication=yes",
            "-o",
            "PreferredAuthentications=publickey",
            "-o",
            "PasswordAuthentication=no",
            "-p",
            str(port),
            "admin@127.0.0.1",
            command,
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=180,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"ssh command failed rc={result.returncode} command={command}\n"
            f"stdout={result.stdout}\nstderr={result.stderr}"
        )
    return result.stdout


def run_ssh_json(key: Path, port: int, command: str) -> dict[str, object]:
    output = run_ssh(key, port, command)
    try:
        envelope = json.loads(output)
    except json.JSONDecodeError as error:
        raise RuntimeError(
            f"ssh command returned invalid JSON command={command}: {output!r}"
        ) from error
    if envelope.get("schema_version") != 1 or envelope.get("status") != "ok":
        raise RuntimeError(
            f"ssh command returned invalid envelope command={command}: {envelope!r}"
        )
    data = envelope.get("data")
    if not isinstance(data, dict):
        raise RuntimeError(
            f"ssh command returned non-object data command={command}: {envelope!r}"
        )
    return data

