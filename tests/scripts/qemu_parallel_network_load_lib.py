#!/usr/bin/env python3
"""Harness for qemu-parallel-network-load.py.

Moved verbatim out of the gate so that neither file has to carry the whole
run. This half is everything that touches the two client origins and the
guest: the port reservation, the readiness waits, the process teardown, the
`docker`/`ssh` client command builders, the QEMU boot loop and the stress
group orchestration. It owns the run context both halves share -- the
repository paths, the selected architecture, the Docker image tag, the SSH
readiness marker and the two budgets -- taken from the same command line the
gate was given.

It is imported by the gate and is not itself a program: `python3
tests/scripts/qemu-parallel-network-load.py` remains the only entry point.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "scripts"))
from qemu_gate_lib import (arch_from_argv, qemu_boot_environment, qemu_runner,
                           smoke_timeout)

ARCH = arch_from_argv(sys.argv)
BUILD = ROOT / "build"
IMAGE = "xaios-debian13-network-client:13"
SSH_READY_MARKER = "SSH server: up and running (tcp/22)"
BOOT_TIMEOUT_SECONDS = float(smoke_timeout(ARCH, 150))
CLIENT_TIMEOUT_SECONDS = 900.0


def reserve_port(socket_type: int) -> int:
    with socket.socket(socket.AF_INET, socket_type) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for_marker(log_path: Path, marker: str, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if log_path.exists() and marker in log_path.read_text(errors="replace"):
            return
        time.sleep(0.25)
    tail = ""
    if log_path.exists():
        tail = "\n".join(log_path.read_text(errors="replace").splitlines()[-60:])
    raise TimeoutError(f"timed out waiting for {marker!r}\n{tail}")


def stop_process(process: subprocess.Popen[bytes], timeout: float = 10.0) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=timeout)


def start_qemu(
    name: str, knobs: dict[str, object], packet_capture: Path | None = None
) -> tuple[subprocess.Popen[bytes], object, Path, Path, int]:
    """Boot the guest this gate loads, on whichever machine was asked for.

    `knobs` are logical names -- hostfwd_port, net_socket_port and so on --
    which qemu_boot_environment turns into whatever this architecture's runner
    reads. The packet capture is the one knob all three runners already spell
    the same way, so it is set directly.
    """
    log_path = BUILD / f"{name}.log"
    persistent_path = BUILD / f"{name}-persistent.img"
    persistent_path.unlink(missing_ok=True)
    last_error: TimeoutError | None = None
    for attempt in range(2):
        log_file = log_path.open("wb")
        env = qemu_boot_environment(
            ARCH, os.environ.copy(), accel="tcg", smp=4,
            persistent=persistent_path,
            state_dir=BUILD / f"{name}-state",
            # The console is redirected into log_path; the RISC-V runner
            # writes it to a file of its own unless told otherwise.
            serial_to_stdout=True,
            **knobs)
        if packet_capture is not None:
            env["XAIOS_QEMU_NET_DUMP"] = str(packet_capture)
        process = subprocess.Popen(
            [str(ROOT / qemu_runner(ARCH))],
            cwd=ROOT,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
        try:
            wait_for_marker(log_path, SSH_READY_MARKER, BOOT_TIMEOUT_SECONDS)
            return process, log_file, log_path, persistent_path, attempt + 1
        except TimeoutError as error:
            last_error = error
            stop_process(process)
            log_file.close()
            log_text = log_path.read_text(errors="replace")
            if "XAIOS loader starting" in log_text or attempt != 0:
                raise
            archived = BUILD / f"{name}-firmware-attempt-1.log"
            log_path.replace(archived)
            print(
                "RETRY: firmware did not enter the XAIOS loader; "
                f"saved {archived}",
                flush=True,
            )
            time.sleep(1.0)
    assert last_error is not None
    raise last_error


def run_checked(
    command: list[str], timeout: float, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(command), flush=True)
    return subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        check=True,
        text=True,
        timeout=timeout,
    )


def wait_for_ssh_recovery(key: Path, ssh_port: int, timeout: float = 30.0) -> None:
    marker = "capacity-recovered"
    deadline = time.monotonic() + timeout
    command = [
        "ssh", "-F", "/dev/null", "-i", str(key),
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        # See qemu-model-sftp-gate: a ~/.ssh/config that disables public key
        # authentication for this host would otherwise stop the key being
        # offered at all, on that machine only.
        "-o", "PubkeyAuthentication=yes",
        "-o", "PreferredAuthentications=publickey",
        "-o", "PasswordAuthentication=no",
        "-o", "ConnectTimeout=3",
        "-o", "LogLevel=ERROR",
        "-p", str(ssh_port), "admin@127.0.0.1", f"echo {marker}",
    ]
    while time.monotonic() < deadline:
        result = subprocess.run(
            command,
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode == 0 and result.stdout.strip() == marker:
            return
        time.sleep(0.1)
    raise TimeoutError("SSH capacity did not recover after saturation")


def client_command(
    origin: str,
    key_dir: Path,
    coord_dir: Path,
    ssh_port: int,
    udp_port: int,
    mode: str,
    *extra: str,
) -> list[str]:
    if origin == "macos":
        return [
            sys.executable,
            str(ROOT / "tests" / "network" / "parallel-client-load.py"),
            "--mode", mode,
            "--client-id", "macos",
            "--host", "127.0.0.1",
            "--ssh-port", str(ssh_port),
            "--udp-port", str(udp_port),
            "--authorized-key", str(key_dir / "authorized"),
            "--unauthorized-key", str(key_dir / "unauthorized"),
            "--password-file", str(key_dir / "password"),
            *extra,
        ]
    return [
        "docker", "run", "--rm",
        "--add-host", "host.docker.internal:host-gateway",
        "--volume", f"{key_dir}:/keys:ro",
        "--volume", f"{coord_dir}:/coord",
        IMAGE,
        "python3", "/usr/local/bin/xaios-parallel-network-client",
        "--mode", mode,
        "--client-id", "debian",
        "--host", "host.docker.internal",
        "--ssh-port", str(ssh_port),
        "--udp-port", str(udp_port),
        "--authorized-key", "/keys/authorized",
        "--unauthorized-key", "/keys/unauthorized",
        "--password-file", "/keys/password",
        *extra,
    ]


def start_logged(
    name: str, command: list[str]
) -> tuple[subprocess.Popen[bytes], object, Path]:
    log_path = BUILD / f"qemu-parallel-{name}.log"
    log_file = log_path.open("wb")
    print("+", " ".join(command), flush=True)
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )
    return process, log_file, log_path


def wait_group(
    processes: list[tuple[str, subprocess.Popen[bytes], object, Path]],
    timeout: float = CLIENT_TIMEOUT_SECONDS,
) -> None:
    deadline = time.monotonic() + timeout
    pending = list(processes)
    try:
        while pending:
            for entry in list(pending):
                name, process, log_file, log_path = entry
                status = process.poll()
                if status is None:
                    continue
                log_file.close()
                if status != 0:
                    detail = log_path.read_text(errors="replace")
                    raise RuntimeError(
                        f"client {name} failed with status {status}\n{detail}"
                    )
                pending.remove(entry)
            if not pending:
                break
            if time.monotonic() >= deadline:
                names = ", ".join(name for name, *_ in pending)
                raise TimeoutError(f"timed out waiting for clients: {names}")
            time.sleep(0.1)
    finally:
        for _, process, log_file, _ in pending:
            stop_process(process)
            log_file.close()


def stop_group(
    processes: list[tuple[str, subprocess.Popen[bytes], object, Path]]
) -> None:
    for _, process, log_file, _ in processes:
        stop_process(process)
        if not log_file.closed:
            log_file.close()


def wait_ready(
    entries: list[tuple[str, subprocess.Popen[bytes], object, Path]],
    ready_files: list[Path],
    timeout: float,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for name, process, _, log_path in entries:
            if process.poll() is not None:
                detail = log_path.read_text(errors="replace")
                raise RuntimeError(f"client {name} exited before ready\n{detail}")
        if all(path.exists() for path in ready_files):
            return
        time.sleep(0.1)
    raise TimeoutError("timed out waiting for client readiness")


def run_parallel_clients(
    phase: str,
    origins: tuple[str, ...],
    key_dir: Path,
    coord_dir: Path,
    ssh_port: int,
    udp_port: int,
    mode: str,
    *extra: str,
) -> None:
    entries = []
    for origin in origins:
        entries.append(
            (
                origin,
                *start_logged(
                    f"{phase}-{origin}",
                    client_command(
                        origin,
                        key_dir,
                        coord_dir,
                        ssh_port,
                        udp_port,
                        mode,
                        *extra,
                    ),
                ),
            )
        )
    wait_group(entries)


def start_stress_clients(
    phase: str,
    key_dir: Path,
    coord_dir: Path,
    ssh_port: int,
    udp_port: int,
    workers: int,
    cycles: int,
    udp_count: int,
    minimum_seconds: int,
    capture_audit: bool = False,
) -> tuple[
    list[tuple[str, subprocess.Popen[bytes], object, Path]],
    list[Path],
    Path,
    Path | None,
    Path | None,
]:
    start_file = coord_dir / f"{phase}.start"
    audit_request = coord_dir / f"{phase}.audit-request" if capture_audit else None
    audit_output = coord_dir / f"{phase}.audit-output" if capture_audit else None
    entries = []
    ready_files = []
    for origin in ("macos", "debian"):
        ready_host = coord_dir / f"{phase}-{origin}.ready"
        ready_files.append(ready_host)
        if origin == "macos":
            ready_arg = str(ready_host)
            start_arg = str(start_file)
        else:
            ready_arg = f"/coord/{ready_host.name}"
            start_arg = f"/coord/{start_file.name}"
        audit_args: list[str] = []
        if capture_audit and origin == "macos":
            assert audit_request is not None and audit_output is not None
            audit_args = [
                "--audit-request-file", str(audit_request),
                "--audit-output-file", str(audit_output),
            ]
        entries.append(
            (
                origin,
                *start_logged(
                    f"{phase}-{origin}",
                    client_command(
                        origin,
                        key_dir,
                        coord_dir,
                        ssh_port,
                        udp_port,
                        "stress",
                        "--workers", str(workers),
                        "--cycles", str(cycles),
                        "--udp-count", str(udp_count),
                        "--minimum-seconds", str(minimum_seconds),
                        "--ready-file", ready_arg,
                        "--start-file", start_arg,
                        *audit_args,
                        "--timeout", str(CLIENT_TIMEOUT_SECONDS),
                    ),
                ),
            )
        )
    wait_ready(entries, ready_files, 120.0)
    return entries, ready_files, start_file, audit_request, audit_output


def direct_client_commands(
    key_dir: Path, socket_port_1: int, socket_port_2: int
) -> list[tuple[str, list[str]]]:
    macos = [
        sys.executable,
        str(ROOT / "tests" / "network" / "qemu-ipv6-tcp-client.py"),
        "--host", "127.0.0.1",
        "--port", str(socket_port_1),
        "--timeout", "40",
    ]
    debian = [
        "docker", "run", "--rm",
        "--add-host", "host.docker.internal:host-gateway",
        "--volume", f"{key_dir}:/keys:ro",
        IMAGE,
        "python3", "/usr/local/bin/xaios-ipv6-tcp-client",
        "--host", "host.docker.internal",
        "--port", str(socket_port_2),
        "--timeout", "40",
        "--client-mac", "52:54:00:aa:bb:cd",
        "--client-ipv6", "fd00::3",
        "--client-ipv4", "10.0.2.101",
        "--client-port", "42023",
    ]
    return [("macos", macos), ("debian", debian)]


def assert_qemu_healthy(process: subprocess.Popen[bytes], log_path: Path) -> None:
    if process.poll() is not None:
        raise RuntimeError(f"QEMU exited unexpectedly with status {process.returncode}")
    log_text = log_path.read_text(errors="replace")
    failure_markers = (
        "CYAN SCREEN OF DEATH",
        "kernel panic",
        "assertion failed",
        "CRITICAL double free",
    )
    for marker in failure_markers:
        if marker.lower() in log_text.lower():
            raise RuntimeError(f"QEMU log contains failure marker: {marker}")
