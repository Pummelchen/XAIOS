#!/usr/bin/env python3
"""How long the guest's network stack goes without running, measured.

B-44. `network_poll_tick` drains the device's receive ring and runs the whole
TCP state machine -- ACKs, retransmits, flow expiry -- and there is no timer
behind it, no interrupt handler and no kernel thread. It runs inside the
network syscalls a process makes and inside `wait_events`, and the kernel's
last act before starting sshd is to switch preemption and the periodic timer
off (`kmain.c`), so on a booted machine sshd is not merely the only network
process: it is the only thing running on the boot CPU at all. The guest's
networking therefore runs exactly while sshd is inside its loop, and any pause
anywhere in that loop is a total network outage -- nothing comes off the ring,
no ACK leaves, no timeout fires, nothing is refused and nothing is closed.

That arrangement is deliberate and is argued in `wiki/Architecture.md`. What
was not defensible is that it was invisible: from inside, a stack that has not
run for ten seconds looks exactly like a quiet network, and from outside it
looks exactly like a machine that has gone away. So the kernel now measures
the gap between consecutive polls whenever a listener is registered, keeps the
longest, and says so on the console when one is long enough to be an outage.

This gate is the measurement. It boots the verbose build and drives sshd's
loop three ways, reading back the worst gap the guest recorded after each:

  * idle, with sshd sitting in `wait_events`. This is the cadence the stack
    gets for free, and it is the housekeeping interval of that wait.
  * three SFTP round trips of the load soak's own 256 KiB payload, which is
    the shape of work the Fusion run was doing when B-43 appeared. Every
    block of it is a write to the durable volume made from inside the loop
    that drives the network, and each write is preceded by a read of the
    whole file so far -- which is B-45, visible in the console as a read of
    the growing size before every 32 KiB written.
  * a burst of connections the server must engage with and then close, each
    costing several audit-log appends on that same volume -- the slow
    non-network work inside the loop that B-45 is about.

The three run in that order and are measured cumulatively, because the figure
that matters is the worst one this machine produced at all.

What it asserts, and why each one can fail:

  * the instrument ran at all. Remove it and there is no gap line, which is
    this gate's red.
  * the poll count advanced between the first gap line and the last. A gap
    figure from a stack nothing is driving would be meaningless; this is what
    says the number describes a machine that was working.
  * every connection got the server's banner, and every transfer came back
    byte-identical. A worst-case gap measured on a guest that was refusing
    connections, or corrupting them, would not be a measurement of this.
  * the listener count on the line is non-zero, because the measurement is
    deliberately not taken when nothing is listening.

The worst gap itself is recorded, not asserted. This runs on a shared build
machine under TCG, where the host can deschedule the whole emulator for
longer than anything the guest does; failing on the number would be failing on
whoever else is using the laptop. That is the same judgement
`qemu-sshd-close-visibility-gate` makes about sshd's wait-overrun line, and
for the same reason. The number is in the report, which is where B-44's
evidence lives.
"""

from __future__ import annotations

import json
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
                           smoke_timeout)

ARCH = arch_from_argv(sys.argv)
SUFFIX = "" if ARCH == "aarch64" else f"-{ARCH}"
REPORT = BUILD / f"qemu-network-poll-cadence-gate{SUFFIX}.json"
READY_MARKER = "SSH server: up and running (tcp/22)"

# Each new maximum, printed by the kernel as it climbs. The last one in the
# console is the worst gap the guest saw.
GAP_LINE = re.compile(
    r"network: longest gap between polls us=(\d+) polls=(\d+) listeners=(\d+)")
# A gap long enough that the kernel calls it an outage rather than a pause.
OUTAGE_LINE = re.compile(
    r"network: stack was not polled for ms=(\d+) outages=(\d+) listeners=(\d+)")

# Well inside SSHD_CONNECTION_RATE_LIMIT (120 in a 60-second window), so the
# server is busy rather than throttled: a gate that tripped the rate limiter
# would be measuring refusals, not service.
CONNECTIONS = int(os.environ.get("XAIOS_POLL_CADENCE_CONNECTIONS", "90"))

# The load soak's payload, so this transfer is the same shape of work the
# Fusion run was doing when B-43 appeared -- and the same size the
# close-visibility gate uses, so the two figures are comparable. Larger does
# not work: /state caps a file at 256 KiB, and a bigger put stops short, which
# reads as a transfer failure rather than as the limit it is.
PAYLOAD_BYTES = int(os.environ.get("XAIOS_POLL_CADENCE_PAYLOAD",
                                  str(256 * 1024)))
TRANSFERS = int(os.environ.get("XAIOS_POLL_CADENCE_TRANSFERS", "3"))

SSH_BASE = ["-F", "/dev/null", "-o", "IdentitiesOnly=yes",
            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "PubkeyAuthentication=yes",
            "-o", "PreferredAuthentications=publickey",
            "-o", "PasswordAuthentication=no", "-o", "LogLevel=ERROR"]


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


def rejected_peer(port: int) -> bool:
    """Connect, read the banner, offer a version the server must reject.

    Reading the banner first is the point: it is what says the server engaged
    with this connection rather than the connection having died earlier. The
    rejection that follows is work sshd does inside the loop that drives the
    network -- including the audit-log append that B-45 is about -- which is
    exactly the time the stack is not being polled.
    """
    try:
        connection = socket.create_connection(("127.0.0.1", port), 30)
    except OSError:
        return False
    try:
        connection.settimeout(30.0)
        banner = connection.recv(256)
        if not banner.startswith(b"SSH-"):
            return False
        try:
            connection.sendall(b"NOT-AN-SSH-VERSION-LINE\r\n")
            connection.settimeout(10.0)
            while connection.recv(256) != b"":
                pass
        except OSError:
            pass
        return True
    finally:
        connection.close()


def build(key: Path) -> None:
    env = os.environ.copy()
    env["XAIOS_AUTHORIZED_KEYS_FILE"] = str(key.with_suffix(".pub"))
    commands = {
        "aarch64": [["make", "image-qemu-test"]],
        "x86_64": [["make", "image-x86_64-qemu-test"]],
        "riscv64": [["./scripts/build-riscv64.sh"],
                    ["./scripts/build-riscv64-image.sh"]],
    }[ARCH]
    for command in commands:
        subprocess.run(command, cwd=ROOT, env=env, check=True,
                       timeout=smoke_timeout(ARCH, 600))


def wait_for_ssh(key: Path, port: int, process: subprocess.Popen,
                 timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("the guest exited before it answered SSH")
        try:
            result = subprocess.run(
                ["ssh", *SSH_BASE, "-i", str(key), "-p", str(port),
                 "admin@127.0.0.1", "recovery status"],
                cwd=ROOT, capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and "rescue=" in result.stdout:
                return
        except subprocess.TimeoutExpired:
            pass
        time.sleep(1.0)
    raise TimeoutError("the guest never answered an SSH command")


def run_sftp(key: Path, port: int, batch: str, timeout: float) -> int:
    process = subprocess.Popen(
        ["sftp", *SSH_BASE, "-i", str(key), "-P", str(port), "-b", "-",
         "admin@127.0.0.1"], cwd=ROOT, text=True, stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)
    try:
        process.communicate(batch, timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        return 255
    return process.returncode


def worst_gap_so_far(log_path: Path) -> int | None:
    """The largest gap the guest has recorded up to now, in microseconds.

    The kernel prints each new maximum as it is set, so the last line in the
    console is the running worst -- no need to compare them.
    """
    found = GAP_LINE.findall(log_path.read_bytes().decode(errors="replace"))
    return int(found[-1][0]) if found else None


def main() -> int:
    gate_dir = BUILD / f"network-poll-cadence{SUFFIX}"
    # A persistent.img left behind carries the previous run's /state and the
    # previous run's authorized key, which the guest would then refuse.
    if gate_dir.exists():
        shutil.rmtree(gate_dir)
    gate_dir.mkdir(parents=True, exist_ok=True)
    key = gate_dir / "admin"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
                    "xaios-network-poll-cadence-gate", "-f", str(key)],
                   cwd=ROOT, check=True, timeout=30)

    build(key)

    port = reserve_port()
    log_path = BUILD / f"qemu-network-poll-cadence{SUFFIX}.log"
    log_path.unlink(missing_ok=True)
    env = qemu_boot_environment(
        ARCH, os.environ.copy(), accel="tcg", smp=4, hostfwd_port=port,
        persistent=gate_dir / "persistent.img",
        state_dir=gate_dir / "state",
        serial_to_stdout=True)
    handle = log_path.open("wb")
    qemu = subprocess.Popen([str(ROOT / qemu_runner(ARCH))], cwd=ROOT, env=env,
                            stdin=subprocess.DEVNULL, stdout=handle,
                            stderr=subprocess.STDOUT, preexec_fn=os.setsid)

    failures: list[str] = []
    served = 0
    idle_gap_us: int | None = None
    transfer_gap_us: int | None = None
    transfer_rc: int | None = None
    transfer_identical: bool | None = None
    payload = gate_dir / "payload.bin"
    payload.write_bytes(bytes((i * 31 + 7) & 0xFF for i in range(PAYLOAD_BYTES)))
    returned = gate_dir / "returned.bin"
    try:
        wait_for_marker(log_path, READY_MARKER,
                        float(smoke_timeout(ARCH, 420)), qemu)
        wait_for_ssh(key, port, qemu, float(smoke_timeout(ARCH, 300)))

        # 1. Idle. What the stack's cadence is when nothing is asking anything
        #    of it: sshd sitting in wait_events, looking at the network on its
        #    own housekeeping interval. Taken first, so nothing below can have
        #    produced it.
        time.sleep(10)
        idle_gap_us = worst_gap_so_far(log_path)

        # 2. A megabyte each way over SFTP, every block of it written to the
        #    durable volume from inside the loop that drives the network.
        remote = "/state/poll-cadence.bin"
        transfer_rc = 0
        transfer_identical = True
        for _ in range(TRANSFERS):
            returned.unlink(missing_ok=True)
            rc = run_sftp(
                key, port,
                f"put {payload} {remote}\nget {remote} {returned}\n"
                f"rm {remote}\n",
                float(smoke_timeout(ARCH, 300)))
            if rc != 0:
                transfer_rc = rc
            if not (returned.is_file() and
                    returned.read_bytes() == payload.read_bytes()):
                transfer_identical = False
        time.sleep(5)
        transfer_gap_us = worst_gap_so_far(log_path)

        # 3. A burst of connections the server must engage with and reject,
        #    each costing audit-log appends on that same volume.
        for _ in range(CONNECTIONS):
            if rejected_peer(port):
                served += 1
        # The last connections' closes, their audit writes and any gap they
        # caused still have to reach the console.
        time.sleep(15)
    except (RuntimeError, TimeoutError, OSError) as error:
        failures.append(f"the guest never got as far as being measured: {error}")
    finally:
        stop_process(qemu)
        handle.close()

    console = log_path.read_bytes().decode(errors="replace")
    gaps = GAP_LINE.findall(console)
    outages = OUTAGE_LINE.findall(console)

    worst_gap_us = int(gaps[-1][0]) if gaps else None
    first_polls = int(gaps[0][1]) if gaps else None
    last_polls = int(gaps[-1][1]) if gaps else None
    listeners = int(gaps[-1][2]) if gaps else None
    worst_outage_ms = max((int(ms) for ms, _, _ in outages), default=None)

    if not gaps:
        failures.append(
            "the guest never reported a gap between polls, so this machine "
            "has no account of how long its network stack was not running -- "
            "which is the whole of B-44")
    else:
        if listeners is not None and listeners < 1:
            failures.append(
                f"the worst gap was recorded with {listeners} listeners; the "
                f"measurement is only meaningful while something is listening")
        if first_polls is not None and last_polls is not None and \
                last_polls <= first_polls:
            failures.append(
                f"the poll count did not advance across the run "
                f"({first_polls} to {last_polls}), so the gap figure does not "
                f"describe a stack anything was driving")
        if worst_gap_us is not None and worst_gap_us <= 0:
            failures.append("the worst gap reported is not a duration")

    if transfer_rc != 0 or transfer_identical is not True:
        failures.append(
            f"one of the {TRANSFERS} {PAYLOAD_BYTES}-byte SFTP round trips "
            f"did not complete "
            f"(rc={transfer_rc} identical={transfer_identical}); a gap "
            f"measured on a guest that could not move a file is not a "
            f"measurement of a working machine")
    if served != CONNECTIONS:
        failures.append(
            f"the server engaged with {served} of {CONNECTIONS} connections; "
            f"a worst-case gap measured on a guest that was not serving is "
            f"not a measurement of this")

    report = {
        "schema": "xaios.network-poll-cadence.v1",
        "arch": ARCH,
        "connections_offered": CONNECTIONS,
        "connections_served": served,
        "payload_bytes": PAYLOAD_BYTES,
        "transfers": TRANSFERS,
        "transfer_rc": transfer_rc,
        "transfer_identical": transfer_identical,
        "idle_worst_gap_us": idle_gap_us,
        "after_transfer_worst_gap_us": transfer_gap_us,
        "worst_gap_us": worst_gap_us,
        "worst_gap_ms": (round(worst_gap_us / 1000.0, 1)
                         if worst_gap_us is not None else None),
        "gap_records": len(gaps),
        "polls_first_record": first_polls,
        "polls_last_record": last_polls,
        "listeners": listeners,
        "outage_lines": len(outages),
        "worst_outage_ms": worst_outage_ms,
        "outage_threshold_ms": 1000,
        "console": str(log_path),
        "failures": failures,
        "passed": not failures,
    }
    BUILD.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if failures:
        for failure in failures:
            print(f"qemu-network-poll-cadence-gate: {failure}", file=sys.stderr)
        print(f"qemu-network-poll-cadence-gate: console at {log_path}",
              file=sys.stderr)
        print(f"qemu-network-poll-cadence-gate: report written to {REPORT}",
              file=sys.stderr)
        return 1
    print(f"qemu-network-poll-cadence-gate: idle, the worst gap between polls "
          f"was {idle_gap_us} us; after {TRANSFERS} {PAYLOAD_BYTES}-byte "
          f"SFTP round trips, {transfer_gap_us} us; after {served} more "
          f"connections, "
          f"{worst_gap_us} us ({round(worst_gap_us / 1000.0, 1)} ms). "
          f"{len(outages)} gap(s) crossed the one-second outage threshold")
    print(f"qemu-network-poll-cadence-gate: report written to {REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
