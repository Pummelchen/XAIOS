#!/usr/bin/env python3
"""Cross-architecture QEMU closure gate for non-AI OS operations."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import socket
import subprocess
import time


ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
DEBIAN_IMAGE = "xaios-debian13-network-client:13"
READY = "SSH server: up and running (tcp/22)"


def reserve_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def run(command: list[str], *, env: dict[str, str] | None = None,
        timeout: int = 240) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(command), flush=True)
    return subprocess.run(command, cwd=ROOT, env=env, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          timeout=timeout, check=True)


def wait_marker(path: Path, marker: str, count: int = 1,
                timeout: float = 180.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        text = path.read_text(errors="replace") if path.exists() else ""
        if text.count(marker) >= count:
            return
        time.sleep(0.25)
    tail = "\n".join(text.splitlines()[-80:])
    raise TimeoutError(f"missing marker {marker!r} count={count}\n{tail}")


def stop(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=10)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=10)


def ssh_base(key: Path, port: int, host: str = "127.0.0.1") -> list[str]:
    return [
        "ssh", "-F", "/dev/null", "-i", str(key),
        "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=5",
        "-p", str(port), f"admin@{host}",
    ]


def ssh_command(key: Path, port: int, command: str, *, ok: bool | None = True,
                timeout: int = 30) -> str:
    result = subprocess.run(ssh_base(key, port) + [command], cwd=ROOT,
                            text=True, capture_output=True, timeout=timeout)
    if ok is True and result.returncode != 0:
        raise RuntimeError(
            f"SSH command failed rc={result.returncode}: {command}\n"
            f"stdout={result.stdout}\nstderr={result.stderr}"
        )
    if ok is False and result.returncode == 0:
        raise RuntimeError(f"SSH command unexpectedly succeeded: {command}")
    return result.stdout


def wait_ssh(key: Path, port: int, timeout: float = 60.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if ssh_command(key, port, "echo closure-ready", timeout=10).strip() == "closure-ready":
                return
        except (RuntimeError, subprocess.TimeoutExpired):
            pass
        time.sleep(0.25)
    raise TimeoutError(f"SSH did not become ready on port {port}")


def start_guest(arch: str, port: int, persistent: Path,
                log_path: Path) -> subprocess.Popen[bytes]:
    env = os.environ.copy()
    env["XAIOS_QEMU_HOSTFWD_PORT"] = str(port)
    if arch == "aarch64":
        env.update({
            "XAIOS_QEMU_ACCEL": "tcg",
            "XAIOS_QEMU_SMP": "4",
            "XAIOS_PERSISTENT_IMAGE": str(persistent),
        })
        runner = ROOT / "scripts" / "run-qemu-aarch64.sh"
    else:
        env.update({
            "XAIOS_QEMU_X86_ACCEL": "tcg",
            "XAIOS_QEMU_X86_SMP": "4",
            "XAIOS_X86_PERSISTENT_IMAGE": str(persistent),
        })
        runner = ROOT / "scripts" / "run-qemu-x86_64.sh"
    log_file = log_path.open("ab")
    process = subprocess.Popen([str(runner)], cwd=ROOT, env=env,
                               stdin=subprocess.DEVNULL, stdout=log_file,
                               stderr=subprocess.STDOUT,
                               start_new_session=True)
    process._xaios_log_file = log_file  # type: ignore[attr-defined]
    return process


def close_guest(process: subprocess.Popen[bytes]) -> None:
    stop(process)
    log_file = getattr(process, "_xaios_log_file", None)
    if log_file is not None:
        log_file.close()


def docker_ssh(key: Path, port: int, command: str) -> str:
    result = subprocess.run([
        "docker", "run", "--rm",
        "--add-host", "host.docker.internal:host-gateway",
        "--volume", f"{key}:/key:ro", DEBIAN_IMAGE,
        "ssh", "-F", "/dev/null", "-i", "/key",
        "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
        "-p", str(port), "admin@host.docker.internal", command,
    ], cwd=ROOT, text=True, capture_output=True, timeout=60)
    if result.returncode != 0:
        raise RuntimeError(f"Debian SSH failed: {result.stdout}\n{result.stderr}")
    return result.stdout


def assert_contains(value: str, *markers: str) -> None:
    missing = [marker for marker in markers if marker not in value]
    if missing:
        raise RuntimeError(f"missing {missing!r} in output {value!r}")


def exercise(arch: str, key: Path, docker_enabled: bool) -> dict[str, object]:
    port = reserve_port()
    persistent = BUILD / f"operations-{arch}-persistent.img"
    log_path = BUILD / f"operations-{arch}.log"
    persistent.unlink(missing_ok=True)
    log_path.unlink(missing_ok=True)

    # Boot 1: leave a running lifecycle record by abruptly stopping QEMU.
    first = start_guest(arch, port, persistent, log_path)
    try:
        wait_marker(log_path, READY)
        wait_ssh(key, port)
    finally:
        close_guest(first)

    # Boot 2: verify unclean detection, then exercise the reset primitive.
    second = start_guest(arch, port, persistent, log_path)
    try:
        wait_marker(log_path, READY, 2)
        wait_ssh(key, port)
        recovery = ssh_command(key, port, "recovery status")
        assert_contains(recovery, "unclean_boots=1")
        ssh_command(key, port, "reboot")
        if arch == "aarch64":
            wait_marker(log_path, READY, 3)
            wait_ssh(key, port)
        else:
            second.wait(timeout=30)
    finally:
        close_guest(second)

    # x86 -no-reboot exits; ARM remains in the rebooted guest.
    third = start_guest(arch, port, persistent, log_path)
    try:
        expected_ready = 3 if arch == "x86_64" else 4
        wait_marker(log_path, READY, expected_ready)
        wait_ssh(key, port)
        assert_contains(ssh_command(key, port, "ifconfig"),
                        "vtnet0", "10.0.2.15", "RUNNING")
        assert_contains(ssh_command(key, port, "route"),
                        "Destination Gateway Netmask", "10.0.2.2")
        assert_contains(ssh_command(key, port, "netstat"),
                        "rx_packets=", "tcp_established=", "udp_drops=")
        assert_contains(ssh_command(key, port, "limits"),
                        "pressure=normal", "processes_max=1024")
        assert_contains(ssh_command(key, port, "service list"),
                        "/init", "/bin/service-manager")
        assert_contains(ssh_command(key, port,
                                    "service start /bin/xaios-worker"),
                        "service start /bin/xaios-worker: ok")
        assert_contains(ssh_command(key, port,
                                    "service status /bin/xaios-worker"),
                        "state=running")
        assert_contains(ssh_command(key, port,
                                    "service stop /bin/xaios-worker"),
                        "service stop /bin/xaios-worker: ok")
        assert_contains(ssh_command(key, port, "update status"),
                        "update_active=", "generation=")
        assert_contains(ssh_command(key, port, "date"),
                        "epoch_seconds=", "source=")
        assert_contains(ssh_command(key, port, "ntp status"),
                        "ntp_state=", "server=")
        ssh_command(key, port, "ntp sync")
        ssh_command(key, port, "ping 10.0.2.2")
        time.sleep(1.0)
        ping = ssh_command(key, port, "ping status")
        assert_contains(ping, "target=10.0.2.2", "rtt_ns=")
        first_dns = ssh_command(key, port, "nslookup example.com", ok=None)
        time.sleep(1.0)
        second_dns = ssh_command(key, port, "nslookup example.com", ok=None)
        if "pending" in first_dns and "pending" in second_dns:
            raise RuntimeError("DNS remained pending after the network poll interval")
        dns_value = second_dns.partition(": ")[2].strip()
        if dns_value != "dnssec-unverified":
            try:
                if ipaddress.ip_address(dns_value).version != 4:
                    raise ValueError("not IPv4")
            except ValueError as error:
                raise RuntimeError(
                    "DNS A response was neither authenticated nor fail-closed"
                ) from error
        first_aaaa = ssh_command(key, port, "nslookup -6 example.com", ok=None)
        time.sleep(1.0)
        second_aaaa = ssh_command(key, port, "nslookup -6 example.com", ok=None)
        if "pending" in first_aaaa and "pending" in second_aaaa:
            raise RuntimeError("DNS AAAA remained pending after the network poll interval")
        aaaa_value = second_aaaa.partition(": ")[2].strip()
        if aaaa_value != "dnssec-unverified":
            try:
                if ipaddress.ip_address(aaaa_value).version != 6:
                    raise ValueError("not IPv6")
            except ValueError as error:
                raise RuntimeError(
                    "DNS AAAA response was neither authenticated nor fail-closed"
                ) from error
        ssh_command(key, port, "config export /tmp/closure-config.bin")
        assert_contains(ssh_command(key, port,
                                    "config import /tmp/closure-config.bin"),
                        "config import: ok")
        support = ssh_command(key, port, "support")
        assert_contains(support, "XAIOS support bundle (redacted)",
                        "secrets=redacted", "thermal=unavailable",
                        "pmu=unavailable")
        ssh_command(key, port, "kill 1", ok=False)
        if docker_enabled:
            assert_contains(docker_ssh(key, port, "support"),
                            "secrets=redacted", "pressure=")
        ssh_command(key, port, "shutdown")
        third.wait(timeout=30)
    finally:
        close_guest(third)

    # Boot once more from the same disk. A zero count proves the preceding
    # shutdown persisted a clean lifecycle record before QEMU powered off.
    fourth = start_guest(arch, port, persistent, log_path)
    try:
        final_ready = 5 if arch == "aarch64" else 4
        wait_marker(log_path, READY, final_ready)
        wait_ssh(key, port)
        clean = ssh_command(key, port, "recovery status")
        assert_contains(clean, "unclean_boots=0")
    finally:
        close_guest(fourth)

    return {
        "arch": arch,
        "status": "pass",
        "unclean_recovery": "pass",
        "reboot": "pass",
        "orderly_shutdown": "pass",
        "native_client": platform.system().lower(),
        "native_client_status": "pass",
        "debian_client": "pass" if docker_enabled else "skipped",
        "log": str(log_path.relative_to(ROOT)),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch", choices=("aarch64", "x86_64", "all"),
                        default="all")
    parser.add_argument("--skip-docker", action="store_true")
    args = parser.parse_args()
    BUILD.mkdir(parents=True, exist_ok=True)
    key = BUILD / "operations-closure-key"
    for candidate in (key, Path(f"{key}.pub")):
        candidate.unlink(missing_ok=True)
    run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)])
    env = os.environ.copy()
    env["XAIOS_AUTHORIZED_KEYS_FILE"] = f"{key}.pub"
    arches = ("aarch64", "x86_64") if args.arch == "all" else (args.arch,)
    for arch in arches:
        run(["make", "image" if arch == "aarch64" else "image-x86_64"],
            env=env)

    docker_enabled = not args.skip_docker and shutil.which("docker") is not None
    if docker_enabled:
        run(["docker", "build", "--file", "tests/network/Dockerfile.debian13",
             "--tag", DEBIAN_IMAGE, "."], timeout=600)
    results = [exercise(arch, key, docker_enabled) for arch in arches]
    report = {"status": "pass", "results": results,
              "evidence_boundary": "QEMU correctness only"}
    report_path = BUILD / "qemu-operations-closure-report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"qemu-operations-closure: PASS report={report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
