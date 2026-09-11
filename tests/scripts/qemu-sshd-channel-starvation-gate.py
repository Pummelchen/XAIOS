#!/usr/bin/env python3
"""B-41: one channel fails, and every channel after it stops being served.

sshd services its open channels from a single loop, `ssh_channel_tick`, and
that loop is the only place a direct-tcpip forward's bytes are moved from the
forwarded connection into the SSH channel. The loop used to `return` the
moment any channel's turn failed. Two things followed from that one line:

  * the channel that failed was left open and active, so the next tick reached
    it, failed on it, and returned again -- for the life of the connection; and
  * every channel later in the table never ran at all. Not slowly: not at all.

The failure that gets there is not exotic. A forwarded connection whose far
end closes makes the guest's next read on it return an error, which is the
ordinary end of an ordinary forward. So one client closing one forwarded
connection stopped every other forward on the machine, in a different session,
belonging to a different user, with one line per tick in an audit file on the
durable volume to say so and nothing on the console at all.

The gate reproduces exactly that shape:

  * a host service (`victim`) that accepts the guest's forwarded connection,
    says hello, and then closes;
  * a host service (`healthy`) that accepts a second forward from a *second*
    SSH session and then writes a numbered line twice a second forever;
  * the victim's forward is opened first, so its channel sits earlier in the
    table than the healthy one and the old loop could never reach the second.

The assertion is about the second session: after the first forward breaks, the
numbered lines must keep arriving, and their numbers must keep climbing. Before
the fix, zero lines arrive in the twenty seconds that follow. That is the whole
defect, and it is why the gate reads the second session rather than the first.

Three things are asserted beyond "lines kept coming", because each of them is a
way this gate could be green while testing nothing:

  * the healthy forward must have been carrying lines *before* the break. A
    forward that never worked would deliver nothing afterwards either, and the
    gate would report B-41 for a broken harness.
  * the failing channel must actually be closed, not merely skipped: the
    client's end of the victim forward must see the connection close. A fix
    that kept servicing the others while leaving the dead channel open would
    leak a channel per broken forward, and the sixty-fourth would exhaust the
    table.
  * the guest must still answer an ordinary SFTP session at the end, so a guest
    that had fallen over is not read as a pass.
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
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
sys.path.insert(0, str(ROOT / "tests" / "scripts"))
from qemu_gate_lib import (arch_from_argv, qemu_boot_environment, qemu_runner,
                           smoke_timeout)

ARCH = arch_from_argv(sys.argv)
SUFFIX = "" if ARCH == "aarch64" else f"-{ARCH}"
READY_MARKER = "SSH server: up and running (tcp/22)"

# The host, as the guest's user-mode network sees it. A forward has to point
# at something the guest can really reach, and this is the address every other
# outbound gate here uses.
GATEWAY = "10.0.2.2"

# The line the healthy service writes, and how often.
TICK_INTERVAL = 0.5
# How long the healthy forward is watched before the break, and after it.
BASELINE_SECONDS = 6.0
AFTER_SECONDS = 20.0
# Lines expected in those windows. Deliberately far below the 12 and 40 that
# the interval implies, because this is an emulated machine that may be
# sharing the host: the claim is that the forward kept being serviced, not
# that it was serviced at a particular rate.
MIN_BASELINE_LINES = 4
MIN_AFTER_LINES = 6
# How long the failing channel has to be closed in. A tick is milliseconds;
# this is generous enough for a loaded machine and far below the 300-second
# idle timeout, which is the only other thing that would ever close it.
CLOSE_BUDGET = 20.0

SSH_BASE = ["-F", "/dev/null", "-o", "IdentitiesOnly=yes",
            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            # Named for the same reason the other SSH gates name them: a
            # developer's ~/.ssh/config can otherwise stop the key being
            # offered on that machine only.
            "-o", "PubkeyAuthentication=yes",
            "-o", "PreferredAuthentications=publickey",
            "-o", "PasswordAuthentication=no", "-o", "LogLevel=ERROR",
            "-o", "ExitOnForwardFailure=yes"]


def reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


class Service:
    """A host TCP service the guest forwards to.

    `victim` says hello and then, when told, closes -- which is what makes the
    guest's next read on that forwarded socket fail. `healthy` says hello and
    then writes a numbered line every TICK_INTERVAL, which only reaches its
    client if the guest is still servicing that channel.
    """

    def __init__(self, mode: str):
        self.mode = mode
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(4)
        self.port = int(self.listener.getsockname()[1])
        self.accepted_at: float | None = None
        self.written = 0
        self.stop = threading.Event()
        self.close_now = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        connection, _ = self.listener.accept()
        self.accepted_at = time.monotonic()
        try:
            connection.sendall(f"{self.mode}-open\n".encode())
        except OSError:
            return
        self.written += 1
        if self.mode == "victim":
            self.close_now.wait()
            connection.close()
            return
        index = 0
        while not self.stop.is_set():
            index += 1
            try:
                connection.sendall(f"tick {index}\n".encode())
            except OSError:
                return
            self.written += 1
            time.sleep(TICK_INTERVAL)


class Endpoint:
    """The client's end of one forward, with every line timestamped."""

    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.lines: list[tuple[float, bytes]] = []
        self.closed_at: float | None = None
        self.stop = threading.Event()
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self) -> None:
        self.sock.settimeout(1.0)
        buffer = b""
        while not self.stop.is_set():
            try:
                data = self.sock.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                self.closed_at = time.monotonic()
                return
            if not data:
                self.closed_at = time.monotonic()
                return
            buffer += data
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                self.lines.append((time.monotonic(), line))

    def since(self, when: float) -> list[bytes]:
        return [line for stamp, line in self.lines if stamp > when]


def tick_numbers(lines: list[bytes]) -> list[int]:
    numbers = []
    for line in lines:
        match = re.fullmatch(rb"tick (\d+)", line)
        if match:
            numbers.append(int(match.group(1)))
    return numbers


def wait_for_marker(log_path: Path, marker: str, timeout: float,
                    process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if log_path.exists():
            log = log_path.read_text(errors="replace")
            if marker in log:
                return
            if "System halted. Manual reset required." in log:
                raise RuntimeError("XAIOS halted before sshd was ready")
        if process.poll() is not None:
            raise RuntimeError(f"QEMU exited rc={process.returncode}")
        time.sleep(0.25)
    raise TimeoutError(f"timed out waiting for {marker!r}")


def wait_for_ssh(port: int, process: subprocess.Popen[bytes],
                 timeout: float) -> None:
    deadline = time.monotonic() + timeout
    last = "no probe attempted"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"QEMU exited rc={process.returncode}")
        try:
            result = subprocess.run(
                ["ssh-keyscan", "-T", "5", "-p", str(port), "127.0.0.1"],
                text=True, capture_output=True, timeout=10, check=False)
        except subprocess.TimeoutExpired:
            last = "ssh-keyscan timed out"
        else:
            if result.returncode == 0 and "ssh-ed25519" in result.stdout:
                return
            last = f"ssh-keyscan rc={result.returncode}"
        time.sleep(1.0)
    raise TimeoutError(f"timed out waiting for SSH key exchange: {last}")


def stop_process(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except ProcessLookupError:
            return
        process.wait(timeout=10)


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
                       timeout=smoke_timeout(ARCH, 300))


def open_tunnel(key: Path, guest_port: int, local: int,
                target: int) -> subprocess.Popen[str]:
    return subprocess.Popen(
        ["ssh", *SSH_BASE, "-i", str(key), "-N",
         "-L", f"127.0.0.1:{local}:{GATEWAY}:{target}",
         "-p", str(guest_port), "admin@127.0.0.1"], cwd=ROOT, text=True,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, preexec_fn=os.setsid)


def connect_forward(local: int, timeout: float = 30.0) -> socket.socket:
    deadline = time.monotonic() + timeout
    last: OSError | None = None
    while time.monotonic() < deadline:
        try:
            return socket.create_connection(("127.0.0.1", local), 5)
        except OSError as error:
            last = error
            time.sleep(0.5)
    raise TimeoutError(f"forward on {local} never accepted: {last}")


def run_sftp(key: Path, port: int, batch: str, timeout: float):
    started = time.monotonic()
    process = subprocess.Popen(["sftp", *SSH_BASE, "-i", str(key), "-P",
                                str(port), "-b", "-", "admin@127.0.0.1"],
                               cwd=ROOT, text=True, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               preexec_fn=os.setsid)
    try:
        output = process.communicate(batch, timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate()
        return None, "", time.monotonic() - started
    return (process.returncode,
            "".join(part or "" for part in output).strip()[:200],
            time.monotonic() - started)


def main() -> int:
    gate_dir = BUILD / f"sshd-channel-starvation{SUFFIX}"
    # Everything from a previous run goes: a persistent.img left behind holds
    # the earlier run's authorized key, and the guest then refuses this run's
    # key -- a stale volume reporting itself as an authentication failure.
    if gate_dir.exists():
        shutil.rmtree(gate_dir)
    gate_dir.mkdir(parents=True, exist_ok=True)
    key = gate_dir / "admin"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
                    "xaios-sshd-channel-starvation-gate", "-f", str(key)],
                   cwd=ROOT, check=True, timeout=30)

    build(key)

    port = reserve_port()
    log_path = BUILD / f"qemu-sshd-channel-starvation{SUFFIX}.log"
    log_path.unlink(missing_ok=True)
    env = qemu_boot_environment(
        ARCH, os.environ.copy(), accel="tcg", smp=4, hostfwd_port=port,
        persistent=gate_dir / "persistent.img",
        state_dir=gate_dir / "state",
        # The RISC-V runner writes the console to a file of its own unless
        # told otherwise, and this gate reads the console.
        serial_to_stdout=True)
    handle = log_path.open("wb")
    qemu = subprocess.Popen([str(ROOT / qemu_runner(ARCH))], cwd=ROOT, env=env,
                            stdin=subprocess.DEVNULL, stdout=handle,
                            stderr=subprocess.STDOUT, preexec_fn=os.setsid)

    victim = Service("victim")
    healthy = Service("healthy")
    tunnels: list[subprocess.Popen[str]] = []
    failures: list[str] = []
    checks: dict[str, object] = {}
    try:
        wait_for_marker(log_path, READY_MARKER,
                        float(smoke_timeout(ARCH, 240)), qemu)
        wait_for_ssh(port, qemu, float(smoke_timeout(ARCH, 180)))
        mark = len(log_path.read_bytes())

        local_victim, local_healthy = reserve_port(), reserve_port()
        tunnels.append(open_tunnel(key, port, local_victim, victim.port))
        tunnels.append(open_tunnel(key, port, local_healthy, healthy.port))
        # Both sessions authenticate before either forward is opened; the
        # order that matters is the order the *channels* are allocated, and
        # that is the order these local connections are made.
        time.sleep(5.0)

        victim_endpoint = Endpoint(connect_forward(local_victim))
        time.sleep(2.0)
        healthy_endpoint = Endpoint(connect_forward(local_healthy))
        time.sleep(BASELINE_SECONDS)

        if (victim.accepted_at is None or healthy.accepted_at is None or
                victim.accepted_at >= healthy.accepted_at):
            failures.append(
                "the guest did not open the two forwards in the order this "
                "gate depends on. The failing channel has to sit earlier in "
                "the channel table than the healthy one, or the loop that "
                "returned early would have reached the healthy one anyway "
                f"(victim={victim.accepted_at} healthy={healthy.accepted_at})")

        baseline = tick_numbers([line for _, line in healthy_endpoint.lines])
        checks["baseline_lines"] = len(baseline)
        checks["victim_greeting"] = [
            line.decode(errors="replace") for _, line in victim_endpoint.lines]
        if len(baseline) < MIN_BASELINE_LINES:
            failures.append(
                f"the healthy forward delivered {len(baseline)} lines in the "
                f"{BASELINE_SECONDS:.0f}s before anything was broken, fewer "
                f"than the {MIN_BASELINE_LINES} this gate needs to be able to "
                f"say anything about what happens after. Nothing below this "
                f"is evidence of B-41")

        # Break the first forward: the far end closes, and the guest's next
        # read on that socket fails.
        break_at = time.monotonic()
        victim.close_now.set()
        time.sleep(AFTER_SECONDS)

        after = tick_numbers(healthy_endpoint.since(break_at))
        checks["lines_after_break"] = len(after)
        checks["first_after"] = after[0] if after else None
        checks["last_after"] = after[-1] if after else None
        checks["victim_endpoint_closed_after_s"] = (
            round(victim_endpoint.closed_at - break_at, 2)
            if victim_endpoint.closed_at is not None else None)

        if len(after) < MIN_AFTER_LINES:
            failures.append(
                f"the second session's forward delivered {len(after)} lines "
                f"in the {AFTER_SECONDS:.0f}s after the first one's far end "
                f"closed, against {len(baseline)} in the "
                f"{BASELINE_SECONDS:.0f}s before it. That is B-41: the tick "
                f"loop returned on the failing channel and never reached this "
                f"one")
        elif baseline and after and after[-1] <= baseline[-1]:
            failures.append(
                f"the second session's forward delivered lines after the "
                f"break, but none of them were new: the last number before "
                f"was {baseline[-1]} and the last after is {after[-1]}. Those "
                f"are bytes that were already in flight, not a channel being "
                f"serviced")

        if victim_endpoint.closed_at is None:
            failures.append(
                f"the failing channel was never closed: {CLOSE_BUDGET:.0f}s "
                f"after its far end went away the client's end of that "
                f"forward was still open. A channel that cannot be serviced "
                f"and is never closed is held until the 300-second idle "
                f"timeout takes the whole session, and there are sixty-four "
                f"of them")
        elif victim_endpoint.closed_at - break_at > CLOSE_BUDGET:
            failures.append(
                f"the failing channel took "
                f"{victim_endpoint.closed_at - break_at:.1f}s to be closed, "
                f"longer than the {CLOSE_BUDGET:.0f}s budget")

        console = log_path.read_bytes()[mark:].decode("utf-8", "replace")
        closures = console.count("sshd: channel closed after tick failure")
        checks["console_closures"] = closures
        if closures == 0:
            failures.append(
                "the console never recorded a channel being closed after a "
                "failed tick. Something else ended the forward, so this run "
                "says nothing about the path B-41 is in")

        # The machine is still there. A guest that had wedged would fail
        # everything above for a reason that is not this one.
        alive, message, seconds = run_sftp(key, port, "ls /state\n",
                                           float(smoke_timeout(ARCH, 60)))
        checks["still_serving_rc"] = alive
        checks["still_serving_seconds"] = round(seconds, 1)
        if alive != 0:
            failures.append(
                f"after the exercise the guest would not answer an ordinary "
                f"SFTP listing: rc={alive} {message!r}")
    finally:
        victim.stop.set()
        victim.close_now.set()
        healthy.stop.set()
        for tunnel in tunnels:
            stop_process(tunnel)
        stop_process(qemu)
        handle.close()

    report = {
        "schema": "xaios.sshd.channel-starvation.v1",
        "status": "pass" if not failures else "fail",
        "architecture": ARCH,
        "checks": checks,
        "failures": failures,
        "guest_log": str(log_path),
    }
    report_path = BUILD / f"qemu-sshd-channel-starvation{SUFFIX}.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    if failures:
        for failure in failures:
            print(f"qemu-sshd-channel-starvation-gate: FAIL {failure}")
        print(f"qemu-sshd-channel-starvation-gate: report={report_path}")
        return 1
    print(f"qemu-sshd-channel-starvation-gate: a second session's forward "
          f"carried {checks['lines_after_break']} lines in the "
          f"{AFTER_SECONDS:.0f}s after another session's forward failed, and "
          f"the failing channel was closed in "
          f"{checks['victim_endpoint_closed_after_s']}s; "
          f"report={report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
