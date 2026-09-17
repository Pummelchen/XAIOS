#!/usr/bin/env python3
"""Harness for qemu-sshd-audit-append-gate.py (B-45).

The gate's own docstring states the claim it tests. This module holds the
machinery that makes the measurement: the constants and the console and wire
patterns both instruments are read with, the guest build step, the QEMU
lifecycle, the SSH client plumbing, the workload and rotation drivers, and the
three-configuration runner. `metadata_sectors` is here because the gate's
report carries the metadata figure, and it reads the kernel's own
`XBFS_*_METADATA_SECTORS` defines rather than a copy of them.

It is imported by the gate and is not itself a program: `python3
tests/scripts/qemu-sshd-audit-append-gate.py` remains the only entry point.
"""

from __future__ import annotations

import os
import re
import shutil
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
                           smoke_timeout, write_report)

ARCH = arch_from_argv(sys.argv)
SUFFIX = "" if ARCH == "aarch64" else f"-{ARCH}"
READY_MARKER = "SSH server: up and running (tcp/22)"
APPEND_SELF_TEST = "xaibootfs: append self-test passed"

# Enough connections for a per-connection mean to mean something, and well
# inside SSHD_CONNECTION_RATE_LIMIT for the window they take.
CONNECTIONS = 40

SSH_BASE = ["-F", "/dev/null", "-o", "IdentitiesOnly=yes",
            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "PubkeyAuthentication=yes",
            "-o", "PreferredAuthentications=publickey",
            "-o", "PasswordAuthentication=no", "-o", "LogLevel=ERROR"]

LOG_PATH = "/state/sshd.log"
KEY_PATH = "/etc/xaios_authorized_keys"

REWRITE = re.compile(
    r"xaibootfs: write path=" + re.escape(LOG_PATH) +
    r" size=(?P<size>\d+) blocks=(?P<blocks>\d+)")
LOG_READ = re.compile(
    r"xaibootfs: read path=" + re.escape(LOG_PATH) +
    r" size=(?P<size>\d+) blocks=(?P<blocks>\d+)")
APPEND = re.compile(
    r"xaibootfs: append path=" + re.escape(LOG_PATH) +
    r" added=(?P<added>\d+) size=(?P<size>\d+) touched=(?P<touched>\d+)")
KEY_READ = re.compile(
    r"xaibootfs: read path=" + re.escape(KEY_PATH) + r" size=(?P<size>\d+)")
COST = re.compile(
    r"sshd: durable cost conns=(?P<conns>\d+) audit_writes=(?P<writes>\d+) "
    r"audit_bytes=(?P<bytes>\d+) audit_us=(?P<audit_us>\d+) "
    r"key_loads=(?P<loads>\d+) key_file_reads=(?P<reads>\d+) "
    r"key_us=(?P<key_us>\d+)")
REFUSAL = re.compile(r"sshd: connection refused reason=(?P<reason>[a-z-]+)")
STALL = re.compile(r"sshd: service loop stalled ms=(?P<ms>\d+)")

MOUNTED = re.compile(r"xaibootfs: persistent mounted v(?P<version>\d+) "
                     r"nodes=(?P<nodes>\d+) sectors=(?P<sectors>\d+)")


def metadata_sectors(version: str) -> int:
    """How many sectors a file write commits *besides* the file's own blocks.

    Every write, appended or rewritten, ends in `write_metadata`, which writes
    the whole metadata region and flushes. That cost is identical on both sides
    of this change and it is far larger than the file traffic either side
    moves, so leaving it out of the report would make the improvement look like
    the whole story. Read from the kernel source rather than written down here,
    for the reason every other constant in these gates is: a copy passes after
    someone changes the original.
    """
    text = (ROOT / "kernel" / "fs" / "xaiboot_fs.c").read_text(encoding="utf-8")
    name = ("XBFS_METADATA_SECTORS" if version == "2"
            else f"XBFS_V{version}_METADATA_SECTORS")
    match = re.search(rf"#define\s+{name}\s+(\d+)U", text)
    return int(match.group(1)) if match else 0


def reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def wait_for_marker(log_path: Path, marker: str, timeout: float,
                    process: subprocess.Popen) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("the guest exited before it was ready")
        if log_path.exists() and marker in log_path.read_text(errors="replace"):
            return
        time.sleep(0.5)
    raise TimeoutError(f"the guest never printed {marker!r}")


def run_ssh(key: Path, port: int, command: str, timeout: float,
            expect_failure: bool = False) -> tuple[int, str, str]:
    try:
        result = subprocess.run(
            ["ssh", *SSH_BASE, "-i", str(key), "-p", str(port),
             "admin@127.0.0.1", command],
            cwd=ROOT, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return 255, "", "timed out"
    return result.returncode, result.stdout, result.stderr.strip()


def wait_for_ssh(key: Path, port: int, process: subprocess.Popen,
                 timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("the guest exited before it answered SSH")
        rc, out, _ = run_ssh(key, port, "recovery status", 30.0, True)
        if rc == 0 and "rescue=" in out:
            return
        time.sleep(1.0)
    raise TimeoutError("the guest never answered an SSH command")


def stop_process(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        pass


def build(key: Path, kernel_flags: str, sshd_flags: str) -> None:
    env = os.environ.copy()
    env["XAIOS_AUTHORIZED_KEYS_FILE"] = str(key.with_suffix(".pub"))
    if kernel_flags:
        env["XAIOS_KERNEL_CFLAGS_EXTRA"] = kernel_flags
    else:
        env.pop("XAIOS_KERNEL_CFLAGS_EXTRA", None)
    if sshd_flags:
        env["XAIOS_SSHD_CFLAGS_EXTRA"] = sshd_flags
    else:
        env.pop("XAIOS_SSHD_CFLAGS_EXTRA", None)
    commands = {
        "aarch64": [["make", "image-qemu-test"]],
        "x86_64": [["make", "image-x86_64-qemu-test"]],
        "riscv64": [["./scripts/build-riscv64.sh"],
                    ["./scripts/build-riscv64-image.sh"]],
    }[ARCH]
    for command in commands:
        subprocess.run(command, cwd=ROOT, env=env, check=True,
                       timeout=smoke_timeout(ARCH, 600))


def console_since(log_path: Path, mark: int) -> str:
    """What the guest printed after `mark` bytes of console.

    Sliced as bytes and decoded afterwards. The boot banner carries escape
    sequences and the console is not guaranteed to be valid UTF-8, so a byte
    count is not a character index -- decoding first and slicing by a byte
    offset silently skips past real output.
    """
    return log_path.read_bytes()[mark:].decode(errors="replace")


def measure(window: str) -> dict[str, object]:
    """Everything the two instruments say about one workload.

    A write of size zero is the truncate that rotation performs, not a
    read-modify-write of a file's contents, and counting it as one would have
    left the fixed build looking as though it still rewrote the log. They are
    counted apart.

    The running totals are differenced from the first and the last line *inside
    the window*, rather than against a reading taken before it. A reading taken
    before the window races the close it is waiting on -- the connection has
    returned to the host before the guest has printed the line about letting it
    go -- and the first draft of this gate reported every time as zero for
    exactly that reason.
    """
    writes = [m.groupdict() for m in REWRITE.finditer(window)]
    rewrites = [w for w in writes if int(w["size"]) != 0]
    truncates = [w for w in writes if int(w["size"]) == 0]
    log_reads = [m.groupdict() for m in LOG_READ.finditer(window)]
    appends = [m.groupdict() for m in APPEND.finditer(window)]
    key_reads = [m.groupdict() for m in KEY_READ.finditer(window)]
    costs = [{k: int(v) for k, v in m.groupdict().items()}
             for m in COST.finditer(window)]

    result: dict[str, object] = {
        "log_rewrites": len(rewrites),
        "log_rewrite_bytes": sum(int(r["size"]) for r in rewrites),
        "log_rewrite_blocks": sum(int(r["blocks"]) for r in rewrites),
        "log_truncates": len(truncates),
        "log_reads": len(log_reads),
        "log_read_bytes": sum(int(r["size"]) for r in log_reads),
        "appends": len(appends),
        "append_bytes": sum(int(a["added"]) for a in appends),
        "append_blocks_touched": sum(int(a["touched"]) for a in appends),
        "key_file_reads_kernel": len(key_reads),
        "refusals": [m.group("reason") for m in REFUSAL.finditer(window)],
        "loop_stalls": [int(m.group("ms")) for m in STALL.finditer(window)],
    }
    if len(costs) < 2:
        result["cost"] = None
        result["cost_connections"] = 0
        return result
    result["cost"] = {key: costs[-1][key] - costs[0][key] for key in costs[-1]}
    result["cost_connections"] = costs[-1]["conns"] - costs[0]["conns"]
    return result


def per_connection(value: float, connections: int) -> float:
    return round(value / connections, 2) if connections else 0.0


def boot(gate_dir: Path, port: int, log_path: Path) -> subprocess.Popen:
    log_path.unlink(missing_ok=True)
    env = qemu_boot_environment(
        ARCH, os.environ.copy(), accel="tcg", smp=4, hostfwd_port=port,
        persistent=gate_dir / "persistent.img",
        state_dir=gate_dir / "state",
        serial_to_stdout=True)
    handle = log_path.open("wb")
    return subprocess.Popen([str(ROOT / qemu_runner(ARCH))], cwd=ROOT, env=env,
                            stdin=subprocess.DEVNULL, stdout=handle,
                            stderr=subprocess.STDOUT, preexec_fn=os.setsid)


def workload(key: Path, port: int, failures: list[str], name: str) -> int:
    """The connections that are measured. Sequential, and each one a full
    connection: version exchange, key exchange, publickey authentication, one
    command, close. That is the shape a soak's round has and the shape B-45's
    arithmetic is about."""
    served = 0
    for index in range(CONNECTIONS):
        rc, out, message = run_ssh(key, port, "recovery status", 60.0, True)
        if rc != 0 or "rescue=" not in out:
            failures.append(
                f"{name}: connection {index + 1} of {CONNECTIONS} did not "
                f"complete: rc={rc} {message!r}. The measurement below is "
                f"about a workload that did not run")
            break
        served += 1
    return served


def rotate_key(key: Path, new_key: Path, port: int,
               timeout: float) -> dict[str, object]:
    """Add a second authorized key the way an administrator would, and see
    whether the server notices. `xaiosctl auth key add` has the kernel write
    the managed key database, which bumps that file's generation -- the thing
    the cache is keyed on. Nothing here tells sshd to reload."""
    put = subprocess.run(
        ["sftp", *SSH_BASE, "-i", str(key), "-P", str(port), "-b", "-",
         "admin@127.0.0.1"], cwd=ROOT, text=True,
        input=f"put {new_key.with_suffix('.pub')} /tmp/gate-key-b.pub\n",
        capture_output=True, timeout=timeout)
    add_rc, add_out, add_err = run_ssh(
        key, port,
        "xaiosctl auth key add /tmp/gate-key-b.pub --principal gate-key-b "
        "--role administrator --operation-id 94501",
        timeout, True)
    used_rc, used_out, used_err = run_ssh(new_key, port, "recovery status",
                                          timeout, True)
    return {
        "upload_rc": put.returncode,
        "upload_message": put.stderr.strip()[-300:],
        "add_rc": add_rc,
        "add_output": add_out.strip()[-300:],
        "add_message": add_err[-300:],
        "new_key_rc": used_rc,
        "new_key_accepted": used_rc == 0 and "rescue=" in used_out,
        "new_key_message": used_err[-300:],
    }


def run_configuration(name: str, kernel_flags: str, sshd_flags: str,
                      key: Path, second_key: Path, measured: bool,
                      rotate: bool, failures: list[str]) -> dict[str, object]:
    gate_dir = BUILD / f"sshd-audit-append{SUFFIX}" / name
    # A persistent.img left behind holds the previous run's key database, and
    # a stale one would decide this run's authentication for it.
    if gate_dir.exists():
        shutil.rmtree(gate_dir)
    gate_dir.mkdir(parents=True, exist_ok=True)

    build(key, kernel_flags, sshd_flags)
    port = reserve_port()
    log_path = BUILD / f"qemu-sshd-audit-append{SUFFIX}-{name}.log"
    qemu = boot(gate_dir, port, log_path)
    report: dict[str, object] = {"kernel_flags": kernel_flags,
                                 "sshd_flags": sshd_flags}
    try:
        wait_for_marker(log_path, READY_MARKER,
                        float(smoke_timeout(ARCH, 300)), qemu)
        boot_console = console_since(log_path, 0)

        # Control one: the append path's own refusals, proved at boot on a
        # volume filled to the last block. A build that reached the numbers
        # below without this line would have an append path that never says no.
        report["append_self_test"] = APPEND_SELF_TEST in boot_console
        mounted = MOUNTED.search(boot_console)
        report["persistent_volume"] = mounted.groupdict() if mounted else None

        wait_for_ssh(key, port, qemu, float(smoke_timeout(ARCH, 240)))
        if measured:
            mark = len(log_path.read_bytes())
            served = workload(key, port, failures, name)
            time.sleep(3.0)
            window = console_since(log_path, mark)
            report["connections"] = served
            report.update(measure(window))
        if rotate:
            report["rotation"] = rotate_key(key, second_key, port,
                                            float(smoke_timeout(ARCH, 120)))
    finally:
        stop_process(qemu)
    return report
