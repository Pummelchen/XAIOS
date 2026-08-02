#!/usr/bin/env python3
"""Run Debian 13 SSH/SFTP/UDP and direct IPv6 tests against XAIOS."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build"
IMAGE = "xaios-debian13-network-client:13"
BOOT_MARKER = "kernel: starting persistent /bin/sshd service"
BOOT_TIMEOUT_SECONDS = 150.0
CLIENT_TIMEOUT_SECONDS = 300.0


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
        tail = "\n".join(log_path.read_text(errors="replace").splitlines()[-40:])
    raise TimeoutError(f"timed out waiting for {marker!r}\n{tail}")


def stop_qemu(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def start_qemu(name: str, extra_env: dict[str, str]) -> tuple[subprocess.Popen[bytes], object, Path, Path]:
    log_path = BUILD / f"{name}.log"
    persistent_path = BUILD / f"{name}-persistent.img"
    persistent_path.unlink(missing_ok=True)
    log_file = log_path.open("wb")
    env = os.environ.copy()
    env.update(
        {
            "XAIOS_QEMU_ACCEL": "tcg",
            "XAIOS_QEMU_SMP": "4",
            "XAIOS_PERSISTENT_IMAGE": str(persistent_path),
        }
    )
    env.update(extra_env)
    process = subprocess.Popen(
        [str(ROOT / "scripts" / "run-qemu-aarch64.sh")],
        cwd=ROOT,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=log_file,
        stderr=subprocess.STDOUT,
    )
    return process, log_file, log_path, persistent_path


def run_checked(command: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(command), flush=True)
    return subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        text=True,
        timeout=timeout,
    )


def main() -> int:
    if shutil.which("docker") is None:
        raise SystemExit("error: Docker CLI is required")
    run_checked(["docker", "info", "--format", "{{.ServerVersion}} {{.Architecture}}"], 30)
    run_checked(
        [
            "docker",
            "build",
            "--pull",
            "--file",
            "tests/network/Dockerfile.debian13",
            "--tag",
            IMAGE,
            ".",
        ],
        300,
    )
    version = subprocess.run(
        ["docker", "run", "--rm", IMAGE, "sh", "-c", ". /etc/os-release; printf '%s' \"$VERSION_ID\""],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout
    if not version.startswith("13"):
        raise RuntimeError(f"expected Debian 13 container, got VERSION_ID={version!r}")

    BUILD.mkdir(parents=True, exist_ok=True)
    results: dict[str, object] = {"debian_version": version, "image": IMAGE}

    ssh_port = reserve_port(socket.SOCK_STREAM)
    udp_port = reserve_port(socket.SOCK_DGRAM)
    packet_capture = BUILD / "qemu-docker-network-suite.pcap"
    packet_capture.unlink(missing_ok=True)
    qemu, log_file, log_path, persistent_path = start_qemu(
        "qemu-docker-network-suite",
        {
            "XAIOS_QEMU_HOSTFWD_PORT": str(ssh_port),
            "XAIOS_QEMU_HOSTFWD_UDP_PORT": str(udp_port),
            "XAIOS_QEMU_NET_DUMP": str(packet_capture),
        },
    )
    try:
        wait_for_marker(log_path, BOOT_MARKER, BOOT_TIMEOUT_SECONDS)
        run_checked(
            [
                "docker",
                "run",
                "--rm",
                "--add-host",
                "host.docker.internal:host-gateway",
                IMAGE,
                "/usr/local/bin/xaios-network-client-suite",
                "host.docker.internal",
                str(ssh_port),
                str(udp_port),
            ],
            CLIENT_TIMEOUT_SECONDS,
        )
        if qemu.poll() is not None:
            raise RuntimeError(f"QEMU exited unexpectedly with status {qemu.returncode}")
        results["ipv4_ssh_sftp_udp"] = "passed"
        results["ssh_port"] = ssh_port
        results["udp_port"] = udp_port
        results["packet_capture"] = str(packet_capture)
    finally:
        stop_qemu(qemu)
        log_file.close()
        persistent_path.unlink(missing_ok=True)

    socket_port = reserve_port(socket.SOCK_STREAM)
    qemu, log_file, ipv6_log_path, persistent_path = start_qemu(
        "qemu-docker-ipv6-suite",
        {
            "XAIOS_QEMU_HOSTFWD_PORT": "none",
            "XAIOS_QEMU_NET_SOCKET_HOST": "0.0.0.0",
            "XAIOS_QEMU_NET_SOCKET_PORT": str(socket_port),
        },
    )
    try:
        wait_for_marker(ipv6_log_path, BOOT_MARKER, BOOT_TIMEOUT_SECONDS)
        run_checked(
            [
                "docker",
                "run",
                "--rm",
                "--add-host",
                "host.docker.internal:host-gateway",
                IMAGE,
                "python3",
                "/usr/local/bin/xaios-ipv6-tcp-client",
                "--host",
                "host.docker.internal",
                "--port",
                str(socket_port),
                "--timeout",
                "30",
            ],
            60,
        )
        if qemu.poll() is not None:
            raise RuntimeError(f"IPv6 QEMU exited unexpectedly with status {qemu.returncode}")
        results["ipv6_tcp"] = "passed"
        results["socket_port"] = socket_port
    finally:
        stop_qemu(qemu)
        log_file.close()
        persistent_path.unlink(missing_ok=True)

    report_path = BUILD / "qemu-docker-network-suite.json"
    report_path.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n")
    print(f"PASS: Docker network suite report: {report_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError, subprocess.TimeoutExpired, TimeoutError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
