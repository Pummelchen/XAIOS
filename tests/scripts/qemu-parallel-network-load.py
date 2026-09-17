#!/usr/bin/env python3
"""Stress one XAIOS guest from concurrent macOS and Debian 13 clients.

The machine-facing plumbing lives in `qemu_parallel_network_load_lib.py`;
this file keeps the command line, the scenario order and the report.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import time

from qemu_parallel_network_load_lib import (ARCH, BUILD, IMAGE, ROOT,
                                           assert_qemu_healthy,
                                           direct_client_commands,
                                           reserve_port, run_checked,
                                           run_parallel_clients,
                                           smoke_timeout, start_logged,
                                           start_qemu, start_stress_clients,
                                           stop_group, stop_process,
                                           wait_for_marker,
                                           wait_for_ssh_recovery, wait_group)


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
