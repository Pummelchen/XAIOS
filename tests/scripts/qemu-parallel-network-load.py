#!/usr/bin/env python3
"""Stress one XAIOS guest from concurrent macOS and Debian 13 clients."""

from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import sys
import time


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


def main() -> int:
    started = time.monotonic()
    if platform.system() != "Darwin":
        raise SystemExit("error: this dual-origin gate requires a macOS host")
    for tool in ("docker", "ssh", "sftp", "ssh-keygen"):
        if shutil.which(tool) is None:
            raise SystemExit(f"error: required tool is unavailable: {tool}")
    run_checked(["docker", "info", "--format", "{{.ServerVersion}} {{.Architecture}}"], 30)
    try:
        run_checked(
            [
                "docker", "build", "--pull",
                "--file", "tests/network/Dockerfile.debian13",
                "--tag", IMAGE, ".",
            ],
            300,
        )
    except subprocess.CalledProcessError:
        if subprocess.run(
            ["docker", "image", "inspect", IMAGE], cwd=ROOT,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=30,
        ).returncode != 0:
            raise
        print(
            "warning: registry refresh failed; using the existing local "
            f"{IMAGE} image",
            flush=True,
        )
    debian_version = subprocess.run(
        [
            "docker", "run", "--rm", IMAGE, "sh", "-c",
            ". /etc/os-release; printf '%s' \"$VERSION_ID\"",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout
    if not debian_version.startswith("13"):
        raise RuntimeError(f"expected Debian 13, got {debian_version!r}")

    BUILD.mkdir(parents=True, exist_ok=True)
    key_dir = BUILD / "qemu-parallel-network-keys"
    coord_dir = BUILD / "qemu-parallel-network-coord"
    for path in (key_dir, coord_dir):
        if path.exists():
            shutil.rmtree(path)
        path.mkdir(mode=0o700)
    for name in ("authorized", "unauthorized"):
        run_checked(
            [
                "ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                "-C", f"xaios-parallel-{name}", "-f", str(key_dir / name),
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
            "--password-file", str(password_file),
            "--output", str(users_file),
            "--iterations", "100000",
        ],
        30,
    )
    build_env = os.environ.copy()
    build_env["XAIOS_AUTHORIZED_KEYS_FILE"] = str(key_dir / "authorized.pub")
    build_env["XAIOS_SSH_USERS_FILE"] = str(users_file)
    build_env["XAIOS_SSH_PASSWORD_AUTH"] = "1"
    for command in {"aarch64": [["make", "image"]],
                    "x86_64": [["make", "image-x86_64"]],
                    "riscv64": [["./scripts/build-riscv64.sh"],
                                ["./scripts/build-riscv64-image.sh"]]}[ARCH]:
        run_checked(command, smoke_timeout(ARCH, 180), build_env)

    ssh_port = reserve_port(socket.SOCK_STREAM)
    udp_port = reserve_port(socket.SOCK_DGRAM)
    socket_port_1 = reserve_port(socket.SOCK_STREAM)
    socket_port_2 = reserve_port(socket.SOCK_STREAM)
    suffix = "" if ARCH == "aarch64" else f"-{ARCH}"
    packet_capture = BUILD / f"qemu-parallel-network-load{suffix}.pcap"
    packet_capture.unlink(missing_ok=True)
    qemu, qemu_log_file, qemu_log_path, persistent_path, launch_attempts = start_qemu(
        f"qemu-parallel-network-load{suffix}",
        {
            "hostfwd_port": ssh_port,
            "hostfwd_udp_port": udp_port,
            "net_socket_host": "0.0.0.0",
            "net_socket_port": socket_port_1,
            "net_socket_port_2": socket_port_2,
        },
        packet_capture,
    )
    phases: dict[str, str] = {}
    try:
        run_parallel_clients(
            "preflight",
            ("macos", "debian"),
            key_dir,
            coord_dir,
            ssh_port,
            udp_port,
            "preflight",
            "--udp-count", "20",
        )
        assert_qemu_healthy(qemu, qemu_log_path)
        phases["dual_origin_preflight"] = "passed"

        mixed, _, mixed_start, _, _ = start_stress_clients(
            "mixed", key_dir, coord_dir, ssh_port, udp_port,
            workers=1, cycles=4, udp_count=40, minimum_seconds=15,
        )
        mixed_start.write_text("start\n", encoding="ascii")
        direct_entries = []
        for origin, command in direct_client_commands(
            key_dir, socket_port_1, socket_port_2
        ):
            direct_entries.append(
                (
                    origin,
                    *start_logged(f"direct-{origin}", command),
                )
            )
        try:
            wait_group(direct_entries, 120.0)
            wait_group(mixed)
        except BaseException:
            stop_group(mixed)
            raise
        assert_qemu_healthy(qemu, qemu_log_path)
        for origin, _, _, log_path in direct_entries:
            direct_output = log_path.read_text(errors="replace")
            for marker in (
                "outbound_ipv4_fragments=2",
                "outbound_ipv6_fragments=2",
            ):
                if marker not in direct_output:
                    raise RuntimeError(
                        f"direct {origin} client omitted {marker!r}\n{direct_output}"
                    )
        phases["raw_tcp_under_ssh_sftp_udp_load"] = "passed"
        phases["ipv4_ipv6_fragment_reassembly_under_load"] = "passed"
        phases["ipv4_ipv6_source_fragmentation_under_load"] = "passed"

        saturation, _, saturation_start, audit_request, audit_output = start_stress_clients(
            "saturation", key_dir, coord_dir, ssh_port, udp_port,
            workers=16, cycles=2, udp_count=100, minimum_seconds=30,
            capture_audit=True,
        )
        try:
            run_parallel_clients(
                "over-capacity",
                ("macos", "debian"),
                key_dir,
                coord_dir,
                ssh_port,
                udp_port,
                "expect-rejected",
            )
            assert audit_request is not None and audit_output is not None
            audit_request.write_text("capture\n", encoding="ascii")
            wait_for_marker(
                audit_output, "Max connections reached", 30.0
            )
            sshd_audit = audit_output.read_text(errors="replace")
            capacity_markers = sshd_audit.count("Max connections reached")
            saturation_start.write_text("start\n", encoding="ascii")
            wait_group(saturation)
        except BaseException:
            stop_group(saturation)
            raise
        assert_qemu_healthy(qemu, qemu_log_path)
        phases["thirty_two_connection_two_channel_saturation"] = "passed"
        phases["over_capacity_rejection"] = "passed"
        wait_for_ssh_recovery(key_dir / "authorized", ssh_port)
        phases["capacity_reclamation"] = "passed"

        run_parallel_clients(
            "reconnect",
            ("macos", "debian"),
            key_dir,
            coord_dir,
            ssh_port,
            udp_port,
            "reconnect",
            "--reconnects", "20",
        )
        run_parallel_clients(
            "health",
            ("macos", "debian"),
            key_dir,
            coord_dir,
            ssh_port,
            udp_port,
            "health",
            "--udp-count", "5",
        )
        assert_qemu_healthy(qemu, qemu_log_path)
        phases["forty_parallel_reconnects"] = "passed"
        phases["post_load_recovery"] = "passed"

        report = {
            "schema": "xaios.qemu.parallel_network_load.v1",
        "arch": ARCH,
            "status": "pass",
            "guest_instances": 1,
            "guest_launch_attempts": launch_attempts,
            "clients": {
                "macos": platform.mac_ver()[0],
                "debian": debian_version,
            },
            "phases": phases,
            "workload": {
                "declared_connection_limit": 32,
                "saturation_connections": 32,
                "channels_per_connection": 2,
                "sftp_cycles": 64,
                "reconnects": 40,
                "udp_round_trips": 330,
                "over_capacity_rejections": 2,
                "guest_capacity_audit_entries": capacity_markers,
                "raw_tcp_clients": 2,
                "fragmented_ipv4_clients": 2,
                "fragmented_ipv6_clients": 2,
                "outbound_ipv4_fragment_sequences": 2,
                "outbound_ipv6_fragment_sequences": 2,
            },
            "artifacts": {
                "qemu_log": str(qemu_log_path),
                "packet_capture": str(packet_capture),
            },
            "duration_seconds": round(time.monotonic() - started, 3),
        }
        report_path = BUILD / f"qemu-parallel-network-load{suffix}.json"
        report_path.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"PASS: parallel network load report: {report_path}")
    finally:
        stop_process(qemu)
        qemu_log_file.close()
        persistent_path.unlink(missing_ok=True)
        shutil.rmtree(key_dir, ignore_errors=True)
        shutil.rmtree(coord_dir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        OSError,
        RuntimeError,
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
        TimeoutError,
    ) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        raise SystemExit(1)
