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
SSH_READY_MARKER = "syscall: net_listen protocol=17 port=2223 sockfd=2"
BOOT_TIMEOUT_SECONDS = 150.0
CLIENT_TIMEOUT_SECONDS = 600.0


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


def start_qemu(
    name: str,
    extra_env: dict[str, str],
    persistent_path: Path | None = None,
    reset_persistent: bool = True,
) -> tuple[subprocess.Popen[bytes], object, Path, Path]:
    log_path = BUILD / f"{name}.log"
    if persistent_path is None:
        persistent_path = BUILD / f"{name}-persistent.img"
    if reset_persistent:
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


def start_qemu_ready(
    name: str,
    extra_env: dict[str, str],
    marker: str,
    persistent_path: Path | None = None,
    reset_persistent: bool = True,
) -> tuple[subprocess.Popen[bytes], object, Path, Path]:
    last_error: TimeoutError | None = None
    for attempt in range(2):
        process, log_file, log_path, selected_persistent = start_qemu(
            name,
            extra_env,
            persistent_path=persistent_path,
            reset_persistent=reset_persistent and attempt == 0,
        )
        try:
            wait_for_marker(log_path, marker, BOOT_TIMEOUT_SECONDS)
            return process, log_file, log_path, selected_persistent
        except TimeoutError as error:
            last_error = error
            stop_qemu(process)
            log_file.close()
            log_text = log_path.read_text(errors="replace")
            if "XAIOS loader starting" in log_text or attempt != 0:
                raise
            attempt_log = BUILD / f"{name}-firmware-attempt-1.log"
            log_path.replace(attempt_log)
            print(
                f"RETRY: QEMU firmware did not enter the XAIOS loader; "
                f"saved {attempt_log}",
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
        check=True,
        text=True,
        timeout=timeout,
        env=env,
    )


def docker_command(key_dir: Path, *command: str) -> list[str]:
    return [
        "docker",
        "run",
        "--rm",
        "--add-host",
        "host.docker.internal:host-gateway",
        "--volume",
        f"{key_dir}:/keys:ro",
        IMAGE,
        *command,
    ]


def scan_host_key(key_dir: Path, port: int) -> tuple[str, str]:
    completed = subprocess.run(
        docker_command(
            key_dir,
            "ssh-keyscan",
            "-T",
            "20",
            "-p",
            str(port),
            "host.docker.internal",
        ),
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    for line in completed.stdout.splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[1] == "ssh-ed25519":
            return fields[1], fields[2]
    raise RuntimeError("ssh-keyscan did not return an Ed25519 host key")


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
    key_dir = BUILD / "qemu-network-keys"
    if key_dir.exists():
        shutil.rmtree(key_dir)
    key_dir.mkdir(mode=0o700)
    for name in ("authorized", "unauthorized"):
        run_checked(
            [
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-C",
                f"xaios-{name}-fixture",
                "-f",
                str(key_dir / name),
            ],
            30,
        )
    password_file = key_dir / "password"
    password_file.write_text("admin\n", encoding="ascii")
    password_file.chmod(0o600)
    users_file = key_dir / "sshd-users"
    run_checked(
        [
            sys.executable,
            "scripts/create-sshd-user-config.py",
            "--password-file",
            str(password_file),
            "--output",
            str(users_file),
            "--iterations",
            "100000",
        ],
        30,
    )
    build_env = os.environ.copy()
    build_env["XAIOS_AUTHORIZED_KEYS_FILE"] = str(key_dir / "authorized.pub")
    build_env["XAIOS_SSH_USERS_FILE"] = str(users_file)
    run_checked(["make", "image"], 180, build_env)

    results: dict[str, object] = {"debian_version": version, "image": IMAGE}

    ssh_port = reserve_port(socket.SOCK_STREAM)
    udp_port = reserve_port(socket.SOCK_DGRAM)
    packet_capture = BUILD / "qemu-docker-network-suite.pcap"
    packet_capture.unlink(missing_ok=True)
    qemu, log_file, log_path, persistent_path = start_qemu_ready(
        "qemu-docker-network-suite",
        {
            "XAIOS_QEMU_HOSTFWD_PORT": str(ssh_port),
            "XAIOS_QEMU_HOSTFWD_UDP_PORT": str(udp_port),
            "XAIOS_QEMU_NET_DUMP": str(packet_capture),
        },
        SSH_READY_MARKER,
    )
    try:
        run_checked(
            docker_command(
                key_dir,
                "/usr/local/bin/xaios-network-client-suite",
                "host.docker.internal",
                str(ssh_port),
                str(udp_port),
            ),
            CLIENT_TIMEOUT_SECONDS,
        )
        if qemu.poll() is not None:
            raise RuntimeError(f"QEMU exited unexpectedly with status {qemu.returncode}")
        results["ipv4_ssh_sftp_udp"] = "passed"
        results["sftp_file_directory_operations"] = "passed"
        results["ssh_rekey"] = "passed"
        results["ssh_shared_transport_channels"] = "passed"
        results["ssh_port"] = ssh_port
        results["udp_port"] = udp_port
        results["packet_capture"] = str(packet_capture)
        first_host_key = scan_host_key(key_dir, ssh_port)
        results["public_key_auth"] = "passed"
    finally:
        stop_qemu(qemu)
        log_file.close()

    reboot_qemu, reboot_log_file, reboot_log_path, _ = start_qemu_ready(
        "qemu-docker-network-reboot",
        {"XAIOS_QEMU_HOSTFWD_PORT": str(ssh_port)},
        SSH_READY_MARKER,
        persistent_path=persistent_path,
        reset_persistent=False,
    )
    try:
        second_host_key = scan_host_key(key_dir, ssh_port)
        if first_host_key != second_host_key:
            raise RuntimeError("SSH host key changed across persistent reboot")
        run_checked(
            docker_command(
                key_dir,
                "ssh",
                "-i",
                "/keys/authorized",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-p",
                str(ssh_port),
                "admin@host.docker.internal",
                "echo host-key-persisted",
            ),
            60,
        )
        results["host_key_persistence"] = "passed"
    finally:
        stop_qemu(reboot_qemu)
        reboot_log_file.close()
        persistent_path.unlink(missing_ok=True)

    socket_port = reserve_port(socket.SOCK_STREAM)
    qemu, log_file, ipv6_log_path, persistent_path = start_qemu_ready(
        "qemu-docker-ipv6-suite",
        {
            "XAIOS_QEMU_HOSTFWD_PORT": "none",
            "XAIOS_QEMU_NET_SOCKET_HOST": "0.0.0.0",
            "XAIOS_QEMU_NET_SOCKET_PORT": str(socket_port),
        },
        SSH_READY_MARKER,
    )
    try:
        run_checked(
            docker_command(
                key_dir,
                "python3",
                "/usr/local/bin/xaios-ipv6-tcp-client",
                "--host",
                "host.docker.internal",
                "--port",
                str(socket_port),
                "--timeout",
                "30",
            ),
            60,
        )
        if qemu.poll() is not None:
            raise RuntimeError(f"IPv6 QEMU exited unexpectedly with status {qemu.returncode}")
        results["ipv6_tcp"] = "passed"
        results["tcp_invalid_reset_rejection"] = "passed"
        results["socket_port"] = socket_port
    finally:
        stop_qemu(qemu)
        log_file.close()
        persistent_path.unlink(missing_ok=True)

    no_rng_port = reserve_port(socket.SOCK_STREAM)
    qemu, log_file, no_rng_log_path, persistent_path = start_qemu_ready(
        "qemu-docker-no-rng-suite",
        {
            "XAIOS_QEMU_HOSTFWD_PORT": str(no_rng_port),
            "XAIOS_QEMU_RNG": "none",
        },
        "kernel: /bin/sshd returned to kernel exit_code=1",
    )
    try:
        banner = b""
        try:
            with socket.create_connection(
                ("127.0.0.1", no_rng_port), timeout=5
            ) as client:
                client.settimeout(3)
                banner = client.recv(128)
        except (ConnectionRefusedError, ConnectionResetError, TimeoutError):
            pass
        if banner.startswith(b"SSH-"):
            raise RuntimeError("sshd exposed an SSH banner without secure entropy")
        results["entropy_fail_closed"] = "passed"
    finally:
        stop_qemu(qemu)
        log_file.close()
        persistent_path.unlink(missing_ok=True)

    key_only_env = os.environ.copy()
    key_only_env["XAIOS_AUTHORIZED_KEYS_FILE"] = str(key_dir / "authorized.pub")
    key_only_env.pop("XAIOS_SSH_USERS_FILE", None)
    run_checked(["make", "image"], 180, key_only_env)
    key_only_port = reserve_port(socket.SOCK_STREAM)
    qemu, log_file, key_only_log_path, persistent_path = start_qemu_ready(
        "qemu-docker-key-only-suite",
        {"XAIOS_QEMU_HOSTFWD_PORT": str(key_only_port)},
        SSH_READY_MARKER,
    )
    try:
        run_checked(
            docker_command(
                key_dir,
                "ssh",
                "-i", "/keys/authorized",
                "-o", "IdentitiesOnly=yes",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-p", str(key_only_port),
                "admin@host.docker.internal",
                "echo key-only-auth-ok",
            ),
            60,
        )
        password_attempt = subprocess.run(
            docker_command(
                key_dir,
                "sshpass", "-p", "admin",
                "ssh",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "PreferredAuthentications=password",
                "-o", "PubkeyAuthentication=no",
                "-o", "NumberOfPasswordPrompts=1",
                "-p", str(key_only_port),
                "admin@host.docker.internal",
                "true",
            ),
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if password_attempt.returncode == 0:
            raise RuntimeError("default image accepted an unprovisioned password")
        results["password_default_disabled"] = "passed"
    finally:
        stop_qemu(qemu)
        log_file.close()
        persistent_path.unlink(missing_ok=True)

    invalid_users = key_dir / "invalid-sshd-users"
    invalid_users.write_text("admin:plaintext:admin\n", encoding="ascii")
    invalid_env = key_only_env.copy()
    invalid_env["XAIOS_SSH_USERS_FILE"] = str(invalid_users)
    run_checked(["make", "image"], 180, invalid_env)
    invalid_port = reserve_port(socket.SOCK_STREAM)
    qemu, log_file, invalid_log_path, persistent_path = start_qemu_ready(
        "qemu-docker-invalid-users-suite",
        {"XAIOS_QEMU_HOSTFWD_PORT": str(invalid_port)},
        "kernel: /bin/sshd returned to kernel exit_code=1",
    )
    try:
        banner = b""
        try:
            with socket.create_connection(("127.0.0.1", invalid_port), timeout=5) as client:
                client.settimeout(3)
                banner = client.recv(128)
        except (ConnectionRefusedError, ConnectionResetError, TimeoutError):
            pass
        if banner.startswith(b"SSH-"):
            raise RuntimeError("sshd exposed a banner with malformed credentials")
        results["malformed_credentials_fail_closed"] = "passed"
    finally:
        stop_qemu(qemu)
        log_file.close()
        persistent_path.unlink(missing_ok=True)

    report_path = BUILD / "qemu-docker-network-suite.json"
    report_path.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n")
    shutil.rmtree(key_dir)
    print(f"PASS: Docker network suite report: {report_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError, subprocess.TimeoutExpired, TimeoutError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
