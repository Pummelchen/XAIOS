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
# What the kernel says once per boot about the record the *next* boot reads.
# Waiting for SSH is not the same thing: a guest whose state volume never
# mounted reaches SSH just as fast, keeps its lifecycle record in memory, and
# leaves the next boot with nothing to find -- which this gate used to report
# as a missed unclean boot, blaming the second guest for what the first one
# never wrote. Only "durable" means the record is on a disk; every other
# verdict the kernel can print ("volatile", "unwritten", "absent") is a
# failure of the first boot and is reported as one, at the boot that caused it.
LIFECYCLE = "lifecycle: record "
LIFECYCLE_DURABLE = "lifecycle: record durable"


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


def lifecycle_lines(path: Path) -> list[str]:
    text = path.read_text(errors="replace") if path.exists() else ""
    return [line.strip() for line in text.splitlines() if LIFECYCLE in line]


def wait_lifecycle_durable(path: Path, count: int = 1,
                           timeout: float = 180.0) -> list[str]:
    """Wait until `count` boots have each put their record on a disk.

    Raises as soon as a boot says otherwise, rather than waiting out the
    timeout: the kernel has already told us this boot's record will not
    survive, so no later boot can make that true.
    """
    deadline = time.monotonic() + timeout
    lines: list[str] = []
    while time.monotonic() < deadline:
        lines = lifecycle_lines(path)
        bad = [line for line in lines if LIFECYCLE_DURABLE not in line]
        if bad:
            raise RuntimeError(
                "guest reported its lifecycle record is not durable, so a "
                "later boot cannot detect this one: " + "; ".join(bad)
            )
        if len(lines) >= count:
            return lines
        time.sleep(0.25)
    raise TimeoutError(
        f"missing {count} durable lifecycle record(s); saw {lines!r}"
    )


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


def ssh_reboot(key: Path, port: int) -> None:
    """Ask the guest to reboot, and do not require ssh to come back cleanly.

    `reboot` is the one command whose success destroys the connection carrying
    it. Whether ssh exits 0, exits non-zero, or hangs until its own timeout
    depends on whether the guest manages to close the channel before it goes
    down -- which is a race with the machine's own shutdown, and on a runner
    with no hardware virtualisation the guest loses it. This gate asserted a
    clean exit within 30 s and had been failing that way on CI since
    2026-09-02, with `subprocess.TimeoutExpired` on the word `reboot`.

    Nothing is lost by not asserting it. The evidence that the reboot happened
    is on the console and is checked immediately below: the lifecycle record
    reaching its third durable write, and the guest printing its ready marker a
    third time. That is a stronger claim than an exit status -- it says the
    machine came back, not merely that it accepted the request.
    """
    try:
        ssh_command(key, port, "reboot", ok=None, timeout=30)
    except subprocess.TimeoutExpired:
        pass


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
        runner = ROOT / "platform" / "qemu" / "run-qemu-aarch64.sh"
    else:
        env.update({
            "XAIOS_QEMU_X86_ACCEL": "tcg",
            "XAIOS_QEMU_X86_SMP": "4",
            "XAIOS_X86_PERSISTENT_IMAGE": str(persistent),
        })
        runner = ROOT / "platform" / "qemu" / "run-qemu-x86_64.sh"
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


# What "nslookup <name>" can end up saying, and what each one means. The gate
# needs all four apart, because three of them used to arrive as the same word.
#
#   an address         the chain validated
#   dnssec-unverified  the chain was walked and refused -- a verdict
#   dnssec-timeout     the walk ran out of budget -- no verdict was reached
#   invalid-argument   the command was wrong; nothing was asked about any name
DNS_UNVERIFIED = "dnssec-unverified"
DNS_TIMEOUT = "dnssec-timeout"
DNS_BAD_ARGUMENT = "nslookup: invalid-argument"

# Longer than the resolver's own walk budget (45 s), deliberately. At 15 s this
# gate gave up first and reported its own impatience as the resolver's, which
# is the wrong end of the wire to be measuring: the point is to see the verdict
# the resolver reached, including "dnssec-timeout" when it reached none.
DNS_PATIENCE_SECONDS = 60.0


def wait_dns_result(key: Path, port: int, command: str, label: str) -> str:
    """Wait for XAIOS's asynchronous resolver without accepting a timeout."""
    deadline = time.monotonic() + DNS_PATIENCE_SECONDS
    value = ""
    while time.monotonic() < deadline:
        value = ssh_command(key, port, command, ok=None)
        if "pending" not in value:
            return value
        time.sleep(0.5)
    raise RuntimeError(
        f"DNS {label} remained pending for {DNS_PATIENCE_SECONDS:.0f} seconds, "
        f"longer than the resolver's own walk budget: it never completed at all"
    )


def check_dns_argument_errors(key: Path, port: int) -> None:
    """A malformed nslookup must be refused as a malformed nslookup.

    B-36. Every one of these used to print "dnssec-unverified" and this gate
    accepted that word as a fail-closed resolver, so a shell that reported a
    typo as a DNSSEC failure read here as a pass. The assertion that matters is
    the negative one: the argument error must not be spelled like a verdict
    about a name, because a gate that accepts both cannot tell them apart.
    """
    for command in ("nslookup example.com extra-argument",
                    "nslookup",
                    "nslookup -6",
                    "nslookup -6 a.example.com spare",
                    # 64 characters, one past what the resolver accepts: the
                    # resolver rejects it with the same code it uses for a
                    # refused chain, so the shell has to catch it first.
                    "nslookup " + "a" * 64):
        output = ssh_command(key, port, command, ok=False)
        if DNS_UNVERIFIED in output or DNS_TIMEOUT in output:
            raise RuntimeError(
                f"{command!r} reported a malformed argument as a verdict about "
                f"a name: {output!r}"
            )
        assert_contains(output, DNS_BAD_ARGUMENT)
    # ...and the same shell still answers a well-formed lookup, so the check
    # above cannot be passed by refusing every nslookup.
    well_formed = wait_dns_result(key, port, "nslookup example.com",
                                  "A (well-formed)")
    if DNS_BAD_ARGUMENT in well_formed:
        raise RuntimeError(
            f"a well-formed nslookup was rejected as malformed: {well_formed!r}"
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
        wait_ssh(key, port)
    finally:
        close_guest(first)

    # Boot 2: verify unclean detection, then exercise the reset primitive.
    second = start_guest(arch, port, persistent, log_path)
    try:
        wait_lifecycle_durable(log_path, 2)
        wait_marker(log_path, READY, 2)
        wait_ssh(key, port)
        recovery = ssh_command(key, port, "recovery status")
        assert_contains(recovery, "unclean_boots=1")
        ssh_reboot(key, port)
        if arch == "aarch64":
            wait_lifecycle_durable(log_path, 3)
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
        wait_lifecycle_durable(log_path, expected_ready)
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
                    f"{dns_value!r}"
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
                    f"fail-closed: {aaaa_value!r}"
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
        wait_lifecycle_durable(log_path, final_ready)
        wait_marker(log_path, READY, final_ready)
        wait_ssh(key, port)
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
