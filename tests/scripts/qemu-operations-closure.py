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
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from qemu_operations_closure_dns import (  # noqa: E402
    DNS_UNVERIFIED,
    check_dns_argument_errors,
    wait_dns_result,
)
from qemu_operations_closure_lib import (  # noqa: E402
    BUILD,
    DEBIAN_IMAGE,
    READY,
    ROOT,
    assert_contains,
    close_guest,
    docker_ssh,
    lifecycle_lines,
    reserve_port,
    run,
    ssh_command,
    ssh_reboot,
    start_guest,
    wait_lifecycle_durable,
    wait_marker,
    wait_ssh,
)


def exercise(arch: str, key: Path, docker_enabled: bool) -> dict[str, object]:
    port = reserve_port()
    persistent = BUILD / f"operations-{arch}-persistent.img"
    log_path = BUILD / f"operations-{arch}.log"
    persistent.unlink(missing_ok=True)
    log_path.unlink(missing_ok=True)

    # Boot 1: leave a running lifecycle record by abruptly stopping QEMU.
    # The record, not SSH, is what boot 2 is asked about, so wait for the boot
    # to say the record is on the disk before killing anything. On this bench
    # that happens roughly eleven seconds before SSH is announced, so the wait
    # costs nothing on a healthy boot -- and on an unhealthy one it fails here,
    # naming the boot that failed, instead of at boot 2 with a clean record.
    first = start_guest(arch, port, persistent, log_path)
    try:
        print(wait_lifecycle_durable(log_path, 1)[-1], flush=True)
        wait_marker(log_path, READY)
        wait_ssh(key, port, arch)
    finally:
        close_guest(first)

    # Boot 2: verify unclean detection, then exercise the reset primitive.
    second = start_guest(arch, port, persistent, log_path)
    try:
        wait_lifecycle_durable(log_path, 2)
        wait_marker(log_path, READY, 2)
        wait_ssh(key, port, arch)
        recovery = ssh_command(key, port, "recovery status")
        assert_contains(recovery, "unclean_boots=1")
        ssh_reboot(key, port)
        if arch == "x86_64":
            # The x86-64 runner is the only one given `-no-reboot`, so a
            # reboot ends that process; the other two come back inside it.
            second.wait(timeout=30)
        else:
            wait_lifecycle_durable(log_path, 3)
            wait_marker(log_path, READY, 3)
            wait_ssh(key, port, arch)
    finally:
        close_guest(second)

    # x86 -no-reboot exits; ARM remains in the rebooted guest.
    third = start_guest(arch, port, persistent, log_path)
    try:
        expected_ready = 3 if arch == "x86_64" else 4
        wait_lifecycle_durable(log_path, expected_ready)
        wait_marker(log_path, READY, expected_ready)
        wait_ssh(key, port, arch)
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
        check_dns_argument_errors(key, port)
        second_dns = wait_dns_result(key, port, "nslookup example.com", "A")
        dns_value = second_dns.partition(": ")[2].strip()
        if dns_value != DNS_UNVERIFIED:
            try:
                if ipaddress.ip_address(dns_value).version != 4:
                    raise ValueError("not IPv4")
            except ValueError as error:
                raise RuntimeError(
                    "DNS A response was neither authenticated nor fail-closed: "
                    f"{dns_value!r} (the whole line was {second_dns!r})"
                ) from error
        second_aaaa = wait_dns_result(key, port, "nslookup -6 example.com", "AAAA")
        aaaa_value = second_aaaa.partition(": ")[2].strip()
        if aaaa_value != DNS_UNVERIFIED:
            try:
                if ipaddress.ip_address(aaaa_value).version != 6:
                    raise ValueError("not IPv6")
            except ValueError as error:
                raise RuntimeError(
                    "DNS AAAA response was neither authenticated nor "
                    f"fail-closed: {aaaa_value!r} (the whole line was "
                    f"{second_aaaa!r})"
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
        final_ready = 4 if arch == "x86_64" else 5
        wait_lifecycle_durable(log_path, final_ready)
        wait_marker(log_path, READY, final_ready)
        wait_ssh(key, port, arch)
        clean = ssh_command(key, port, "recovery status")
        assert_contains(clean, "unclean_boots=0")
    finally:
        close_guest(fourth)

    return {
        "arch": arch,
        "status": "pass",
        "durable_lifecycle_records": len(lifecycle_lines(log_path)),
        "dns_argument_error_rejected": "pass",
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
    parser.add_argument("--arch",
                        choices=("aarch64", "x86_64", "riscv64", "all"),
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
    arches = (("aarch64", "x86_64", "riscv64") if args.arch == "all"
              else (args.arch,))
    builds = {"aarch64": "image", "x86_64": "image-x86_64",
              "riscv64": "riscv64"}
    for arch in arches:
        run(["make", builds[arch]], env=env)

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
