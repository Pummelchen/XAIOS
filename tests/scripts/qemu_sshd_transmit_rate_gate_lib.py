#!/usr/bin/env python3
"""Harness for qemu-sshd-transmit-rate-gate.py (B-40).

The gate's own docstring states the claim it tests. This module holds the
machinery that makes the measurement: the constants that mirror
userspace/sshd/sshd.h, the host service that writes as fast as it is taken,
the relay that trickles the peer's reads, the guest build step and the SSH
client plumbing the gate drives.

It is imported by the gate and is not itself a program: `python3
tests/scripts/qemu-sshd-transmit-rate-gate.py` remains the only entry point.
"""

from __future__ import annotations

import os
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
GATEWAY = "10.0.2.2"

# The trickle. 4 KiB every six seconds is 683 bytes a second: a third of the
# floor the server now applies, and six seconds is inside the ten-second
# window, so the old bound -- which asked only whether a byte had moved --
# never fired on it either.
TRICKLE_BYTES = 4096
# Small enough that the host cannot read the guest ahead of the trickle.
TRICKLE_RCVBUF = 8192
TRICKLE_INTERVAL = 6.0
# The floor the guest applies, repeated here so the gate can assert it is
# trickling below it. Kept in step with SSHD_TRANSMIT_WINDOW_MIN_BYTES and
# SSHD_TIMEOUT_TRANSMIT_WINDOW in userspace/sshd/sshd.h.
FLOOR_BYTES_PER_SECOND = 10240 / 10.0
# Bytes that must have flowed at full speed before the relay starts taking
# slices: the session is authenticated and the forward is carrying data well
# before this.
TRIGGER_BYTES = 64 * 1024

# How long the healthy sessions are timed for, and what counts as a session
# that had to wait for the server rather than for the emulator.
OBSERVE_SECONDS = 90.0
SLOW_PROBE_SECONDS = 3.0
# The fixed server waits one window before it gives up on the trickling peer,
# so one slow probe is expected and more than one is the defect.
MAX_SLOW_PROBES = 1
# After the observation the relay drains at full speed; this is how long the
# backlog between the two is given to clear, and how long the stream has to
# be quiet before it counts as ended.
DRAIN_BUDGET = 30.0
QUIET_SECONDS = 6.0
# How long into the trickle a session may still be made to wait. One window
# plus room for a loaded emulator; past this the server is being held.
CLOSE_BUDGET = 30.0

# The control: a forward drained as fast as the host can take it has to move
# at least this much without the bound firing.
CONTROL_SECONDS = 12.0
CONTROL_MIN_BYTES = 1024 * 1024

SSH_BASE = ["-F", "/dev/null", "-o", "IdentitiesOnly=yes",
            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "PubkeyAuthentication=yes",
            "-o", "PreferredAuthentications=publickey",
            "-o", "PasswordAuthentication=no", "-o", "LogLevel=ERROR",
            "-o", "ExitOnForwardFailure=yes"]

FLOOR_MARKER = "sshd: transmit below the minimum rate, closing"
OLD_STALL_MARKER = "sshd: transmit queue stalled"


def reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


class Blaster:
    """A host service that writes to the forward as fast as it is taken."""

    def __init__(self) -> None:
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.port = int(self.listener.getsockname()[1])
        self.sent = 0
        self.connections = 0
        self.stop = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while not self.stop.is_set():
            try:
                connection, _ = self.listener.accept()
            except OSError:
                return
            self.connections += 1
            threading.Thread(target=self._push, args=(connection,),
                             daemon=True).start()

    def _push(self, connection: socket.socket) -> None:
        payload = bytes(range(256)) * 64
        try:
            while not self.stop.is_set():
                connection.sendall(payload)
                self.sent += len(payload)
        except OSError:
            pass


class TrickleRelay:
    """Carries one session, then takes TRICKLE_BYTES per TRICKLE_INTERVAL.

    Full speed until TRIGGER_BYTES have come back from the guest, because a
    session that is trickled from its first byte never finishes its key
    exchange and never asks the server for anything: the peer this models is
    one that is being served, not one that cannot connect.
    """

    def __init__(self, guest_port: int):
        self.guest_port = guest_port
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = int(self.listener.getsockname()[1])
        self.from_guest = 0
        self.trickled = 0
        self.slices = 0
        self.trickling_since: float | None = None
        self.guest_eof_at: float | None = None
        self.stream_ended_at: float | None = None
        self.last_data_at: float | None = None
        self.stop = threading.Event()
        # Set when the observation is over: the relay then drains what is
        # left at full speed, which is the only way to find out whether the
        # guest has closed its end. While it is trickling it cannot know --
        # there are hundreds of kilobytes buffered between the two, and at
        # 683 bytes a second an end-of-stream behind them would not surface
        # for hours.
        self.stop_trickle = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        client, _ = self.listener.accept()
        guest = socket.socket()
        # Shrink the receive buffer before connecting, or the host reads the
        # guest ahead of us and this gate measures nothing.
        #
        # Without it the host kernel absorbs whatever the guest writes on our
        # behalf: a run here took 4 KiB every 6 s at the socket -- 641 B/s,
        # comfortably under the floor -- while the guest had already written
        # 725,203 bytes and was never once made to wait. From the guest's side
        # the peer was keeping up, so it correctly closed nothing, no session
        # was starved, and the gate failed for a condition it had not created.
        # SO_RCVBUF must be set before connect() to affect the advertised
        # window, and the kernel may round it up; what matters is that it is
        # kilobytes rather than the hundreds this platform defaults to.
        guest.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, TRICKLE_RCVBUF)
        guest.connect(("127.0.0.1", self.guest_port))
        self.effective_rcvbuf = guest.getsockopt(socket.SOL_SOCKET,
                                                 socket.SO_RCVBUF)
        threading.Thread(target=self._upstream, args=(client, guest),
                         daemon=True).start()
        guest.settimeout(1.0)
        client_gone = False
        while not self.stop.is_set():
            trickling = (self.from_guest >= TRIGGER_BYTES and
                         not self.stop_trickle.is_set())
            if trickling and self.trickling_since is None:
                self.trickling_since = time.monotonic()
            data, closed = self._take(guest, trickling)
            now = time.monotonic()
            if closed:
                self.guest_eof_at = now
                self.stream_ended_at = now
                break
            if data:
                self.last_data_at = now
            elif (self.stop_trickle.is_set() and
                  self.last_data_at is not None and
                  now - self.last_data_at >= QUIET_SECONDS):
                # Nothing more is coming. The guest's stack closes a flow by
                # queueing a FIN behind whatever it has already written, so a
                # connection it gave up on while the pipe was full may never
                # reach the host as an end-of-stream at all -- but the bytes
                # stop, and a session the guest was still serving would go on
                # producing them for as long as the host service feeds it.
                self.stream_ended_at = now
                break
            if data:
                self.from_guest += len(data)
                if trickling:
                    self.trickled += len(data)
                    self.slices += 1
                if not client_gone:
                    try:
                        client.sendall(data)
                    except OSError:
                        # The client has gone -- which is what happens when
                        # the guest closes the session. Reading from the
                        # guest continues regardless: whether the guest
                        # closed its end is the thing being measured, and
                        # stopping here would lose it.
                        client_gone = True
            if trickling:
                time.sleep(TRICKLE_INTERVAL)
        for sock in (client, guest):
            try:
                sock.close()
            except OSError:
                pass

    def _take(self, guest: socket.socket,
              trickling: bool) -> tuple[bytes, bool]:
        """Exactly TRICKLE_BYTES while trickling, whatever is there if not.

        Taken to a count rather than by a single recv because one recv returns
        whatever the host's buffering happens to have handed over, which would
        make the rate the guest sees a property of this machine rather than of
        this schedule.
        """
        want = TRICKLE_BYTES if trickling else 65536
        data = b""
        deadline = time.monotonic() + (TRICKLE_INTERVAL if trickling else 1.0)
        while len(data) < want and time.monotonic() < deadline:
            try:
                piece = guest.recv(want - len(data))
            except socket.timeout:
                if not trickling:
                    break
                continue
            except OSError:
                return data, True
            if not piece:
                return data, True
            data += piece
            if not trickling:
                break
        return data, False

    def _upstream(self, client: socket.socket, guest: socket.socket) -> None:
        client.settimeout(1.0)
        while not self.stop.is_set():
            try:
                data = client.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                return
            if not data:
                return
            try:
                guest.sendall(data)
            except OSError:
                return

    def rate(self) -> float:
        if self.trickling_since is None or self.trickled == 0:
            return 0.0
        end = self.stream_ended_at or time.monotonic()
        span = end - self.trickling_since
        return self.trickled / span if span > 0 else 0.0


def drain(sock: socket.socket, counter: list[int],
          stop: threading.Event) -> None:
    sock.settimeout(1.0)
    while not stop.is_set():
        try:
            data = sock.recv(65536)
        except socket.timeout:
            continue
        except OSError:
            return
        if not data:
            return
        counter[0] += len(data)


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


def stop_process(process: subprocess.Popen | None) -> None:
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
