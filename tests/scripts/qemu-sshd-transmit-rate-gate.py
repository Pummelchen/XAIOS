#!/usr/bin/env python3
"""B-40: one peer that barely reads, and a server that serves nobody else.

sshd is a single thread. Its loop accepts new connections, services every open
one, and runs the channel tick; a write that cannot complete is waited on
*inside* that loop, so the wait is not one session's, it is every session's and
the listener's with them.

The transmit path has had a bound on that wait for as long as it has existed,
and the bound asked the wrong question. It measured the gap since the last byte
the peer took and reset on any byte at all, so:

  * a peer that takes a trickle -- a few hundred bytes in each ten seconds --
    renewed the bound forever and held the loop for as long as it liked; and
  * a peer that took nothing was noticed after ten seconds, and then the
    transmit was abandoned *and nothing else happened*. The channel stayed
    open, the connection stayed open, the next tick tried the same write, and
    the server was held for another ten seconds. The peer kept its session and
    kept the machine.

The bound now asks what it should: in each ten-second window the peer must have
taken at least SSHD_TRANSMIT_WINDOW_MIN_BYTES (10 KiB, a kibibyte a second). A
window the peer clears starts another, so a genuinely slow session runs for as
long as it keeps taking its data; a peer below the floor loses its connection,
once, with the reason on the console.

The harness is a relay that carries one authenticated session at full speed and
then starts taking its slice: 4 KiB every six seconds, 683 bytes a second,
comfortably under the floor and comfortably over nothing. What the session is
carrying is a direct-tcpip forward from a host service that writes as fast as
the guest will take it -- the guest's mutable volume caps a file at 256 KiB,
which is less than the host's own socket buffers absorb, so a file download
would never fill the pipe and never make the server wait at all.

The claim being tested is about the *other* sessions, so that is what is
measured: an ordinary SFTP session is opened over and over for ninety seconds
and timed. A gate that watched only the slow session would prove nothing --
the slow session is slow either way.

What separates the two outcomes:

  * unfixed, the server is held in ten-second blocks, over and over, and the
    trickling session is still there at the end of them. Probes taken during
    those blocks wait seconds each, and the console says "transmit queue
    stalled" repeatedly with nothing closed.
  * fixed, the server is held for one window at most, the trickling connection
    is closed with the reason named on the console, and every probe after that
    is a normal sub-second session.

Two controls, because both of the obvious ways to fake this pass otherwise:

  * a peer that keeps up must NOT be closed. The same forward is run first at
    full speed and has to move megabytes without the bound firing. A "fix"
    that closed every session whose socket ever filled would sail through the
    trickle case and break every real transfer.
  * the trickle has to have been a trickle. The relay's own measured rate is
    asserted to be below the floor, and the amount the host service pushed is
    asserted to be far more than the peer took, so the guest really did have
    data it was trying to hand over.
"""

from __future__ import annotations

import json
import os
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


def main() -> int:
    gate_dir = BUILD / f"sshd-transmit-rate{SUFFIX}"
    if gate_dir.exists():
        shutil.rmtree(gate_dir)
    gate_dir.mkdir(parents=True, exist_ok=True)
    key = gate_dir / "admin"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
                    "xaios-sshd-transmit-rate-gate", "-f", str(key)],
                   cwd=ROOT, check=True, timeout=30)

    build(key)

    port = reserve_port()
    log_path = BUILD / f"qemu-sshd-transmit-rate{SUFFIX}.log"
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

    blaster = Blaster()
    stop_drains = threading.Event()
    relay: TrickleRelay | None = None
    tunnels: list[subprocess.Popen[str]] = []
    sinks: list[socket.socket] = []
    failures: list[str] = []
    checks: dict[str, object] = {}
    probe_timeout = float(smoke_timeout(ARCH, 120))
    try:
        wait_for_marker(log_path, READY_MARKER,
                        float(smoke_timeout(ARCH, 240)), qemu)
        wait_for_ssh(port, qemu, float(smoke_timeout(ARCH, 180)))

        # --- Control: a peer that keeps up is left alone --------------------
        control_mark = len(log_path.read_bytes())
        control_local = reserve_port()
        tunnels.append(open_tunnel(key, port, control_local, blaster.port))
        time.sleep(5.0)
        control_sink = connect_forward(control_local)
        sinks.append(control_sink)
        control_bytes = [0]
        threading.Thread(target=drain,
                         args=(control_sink, control_bytes, stop_drains),
                         daemon=True).start()
        time.sleep(CONTROL_SECONDS)
        control_console = log_path.read_bytes()[control_mark:].decode(
            "utf-8", "replace")
        checks["control_bytes"] = control_bytes[0]
        checks["control_floor_lines"] = control_console.count(FLOOR_MARKER)
        if control_bytes[0] < CONTROL_MIN_BYTES:
            failures.append(
                f"a forward drained as fast as the host could take it carried "
                f"only {control_bytes[0]} bytes in {CONTROL_SECONDS:.0f}s, "
                f"under the {CONTROL_MIN_BYTES} this gate needs before it can "
                f"claim anything about a slow one")
        if control_console.count(FLOOR_MARKER) != 0:
            failures.append(
                "the server closed a transmit for being below the minimum "
                "rate while the peer was taking everything it could. The "
                "bound is firing on peers that keep up, which would break "
                "every real transfer on the machine")

        # The control session goes before the slow one starts: what is being
        # measured below is a server with one trickling peer attached, not a
        # server also carrying a transfer at full speed.
        stop_process(tunnels.pop())
        control_sink.close()
        sinks.remove(control_sink)
        time.sleep(2.0)

        # --- The trickling peer ---------------------------------------------
        mark = len(log_path.read_bytes())
        blasted_before = blaster.sent
        relay = TrickleRelay(port)
        slow_local = reserve_port()
        # This session goes through the relay, so the client connects to the
        # relay's port rather than to the guest's.
        tunnels.append(open_tunnel(key, relay.port, slow_local, blaster.port))
        time.sleep(8.0)
        slow_sink = connect_forward(slow_local)
        sinks.append(slow_sink)
        slow_bytes = [0]
        threading.Thread(target=drain,
                         args=(slow_sink, slow_bytes, stop_drains),
                         daemon=True).start()

        # Wait for the relay to start taking slices, so the observation below
        # is of a server with a trickling peer attached rather than of a
        # server with a fast one.
        deadline = time.monotonic() + 60.0
        while relay.trickling_since is None and time.monotonic() < deadline:
            time.sleep(0.5)
        if relay.trickling_since is None:
            failures.append(
                f"the relay never reached the {TRIGGER_BYTES} bytes at which "
                f"it starts trickling, so no peer was ever slow and nothing "
                f"below this is a test of B-40")

        started = time.monotonic()
        probes: list[tuple[float, int | None, float]] = []
        while time.monotonic() - started < OBSERVE_SECONDS:
            at = time.monotonic() - started
            code, message, seconds = run_sftp(key, port, "ls /state\n",
                                              probe_timeout)
            probes.append((round(at, 1), code, round(seconds, 1)))
            if code != 0:
                failures.append(
                    f"an ordinary SFTP session {at:.0f}s into the trickle did "
                    f"not complete: rc={code} {message!r}")
                break

        # Stop trickling and take the rest as fast as it comes: until the
        # backlog between the two is drained there is no way to see whether
        # the guest has closed its end.
        drain_started = time.monotonic()
        relay.stop_trickle.set()
        while (relay.stream_ended_at is None and
               time.monotonic() - drain_started < DRAIN_BUDGET):
            time.sleep(0.5)

        slow = [probe for probe in probes if probe[2] > SLOW_PROBE_SECONDS]
        console = log_path.read_bytes()[mark:].decode("utf-8", "replace")
        checks["probes"] = len(probes)
        checks["slow_probes"] = slow
        checks["worst_probe_seconds"] = max((p[2] for p in probes),
                                            default=None)
        checks["trickle_slices"] = relay.slices
        checks["trickled_bytes"] = relay.trickled
        checks["trickle_rate_bytes_per_second"] = round(relay.rate(), 1)
        checks["blaster_bytes"] = blaster.sent - blasted_before
        checks["floor_lines"] = console.count(FLOOR_MARKER)
        checks["old_stall_lines"] = console.count(OLD_STALL_MARKER)
        checks["stream_ended_after_s"] = (
            round(relay.stream_ended_at - relay.trickling_since, 1)
            if relay.stream_ended_at is not None
            and relay.trickling_since is not None else None)
        checks["guest_sent_eof"] = relay.guest_eof_at is not None
        checks["bytes_from_guest"] = relay.from_guest
        checks["floor_marker_once"] = console.count(FLOOR_MARKER) == 1

        # The trickle has to have been one: slices actually taken, at a rate
        # under the floor, while the guest had far more than that to give.
        if relay.slices < 3:
            failures.append(
                f"the relay took only {relay.slices} slices, too few to say "
                f"the peer was reading at all -- a peer that takes nothing is "
                f"the case the old bound already caught")
        if relay.rate() >= FLOOR_BYTES_PER_SECOND:
            failures.append(
                f"the peer took {relay.rate():.0f} bytes a second, at or "
                f"above the {FLOOR_BYTES_PER_SECOND:.0f} the server requires. "
                f"A peer above the floor is meant to be served, so this run "
                f"tests nothing")
        blasted = blaster.sent - blasted_before
        if blasted < 4 * relay.trickled:
            failures.append(
                f"the host service pushed {blasted} bytes against the "
                f"{relay.trickled} the peer took, not enough of a backlog to "
                f"be sure the guest had anything queued to hand over")

        if console.count(FLOOR_MARKER) == 0:
            # Before blaming the guest, check the gate created the condition.
            #
            # The peer's read rate is not what the guest experiences: the host
            # kernel buffers on the peer's behalf, so the guest can be writing
            # briskly into a socket whose reader is crawling. A run here took
            # 641 B/s at the socket while the guest had already written 725,203
            # bytes and no session waited longer than 0.6s -- the guest was
            # never shown a slow peer, correctly closed nothing, and the gate
            # called that the defect. TRICKLE_RCVBUF is set to stop it, and
            # this is the assertion that the setting worked.
            #
            # Still a failure, and still non-zero: an inconclusive run that
            # exits 0 is a gate that cannot fail. It names the host instead of
            # accusing the guest.
            absorbed = relay.from_guest - relay.trickled
            if (relay.from_guest > 4 * relay.trickled
                    and checks["worst_probe_seconds"] < SLOW_PROBE_SECONDS):
                failures.append(
                    f"INCONCLUSIVE, not a guest defect: the host absorbed "
                    f"{absorbed} bytes on the peer's behalf -- the guest wrote "
                    f"{relay.from_guest} while the peer took {relay.trickled} "
                    f"-- and no session waited more than "
                    f"{checks['worst_probe_seconds']}s, "
                    f"so the guest was never shown a slow peer and had nothing "
                    f"to close. The receive buffer is capped at "
                    f"{TRICKLE_RCVBUF} bytes and this host gave "
                    f"{getattr(relay, 'effective_rcvbuf', 'unknown')}. Lower "
                    f"it, or pin the floor with a hosted test driving "
                    f"send_all_within directly")
            else:
                failures.append(
                    f"the guest never closed the trickling transmit. The "
                    f"console has {console.count(OLD_STALL_MARKER)} stall "
                    f"lines and no {FLOOR_MARKER!r}: the peer took a slice "
                    f"inside every window and kept both its session and the "
                    f"server's attention, which is B-40")
        if relay.stream_ended_at is None:
            failures.append(
                f"the trickling session was still being served at the end: "
                f"with the trickle lifted, bytes kept arriving for the whole "
                f"{DRAIN_BUDGET:.0f}s drain. The server has to end a "
                f"transmit it is not getting anywhere with, not merely "
                f"abandon the packet and try the same write on the next "
                f"tick")

        if len(slow) > MAX_SLOW_PROBES:
            failures.append(
                f"{len(slow)} of {len(probes)} ordinary SFTP sessions took "
                f"longer than {SLOW_PROBE_SECONDS:.0f}s while the trickling "
                f"peer was attached: {slow[:6]}. The server is being held by "
                f"one peer, over and over, which is the whole of B-40. One "
                f"such session is allowed, and is the window the server "
                f"spends deciding")
        late = [probe for probe in slow if probe[0] > CLOSE_BUDGET]
        if late:
            failures.append(
                f"a session was still made to wait {late[0][2]:.0f}s at "
                f"{late[0][0]:.0f}s into the trickle, long after the server "
                f"should have given up on that peer. One window is the "
                f"budget; this is the loop still being held")
    finally:
        stop_drains.set()
        blaster.stop.set()
        for sink in sinks:
            try:
                sink.close()
            except OSError:
                pass
        for tunnel in tunnels:
            stop_process(tunnel)
        if relay is not None:
            relay.stop.set()
        stop_process(qemu)
        handle.close()

    report = {
        "schema": "xaios.sshd.transmit-rate.v1",
        "status": "pass" if not failures else "fail",
        "architecture": ARCH,
        "checks": checks,
        "failures": failures,
        "guest_log": str(log_path),
    }
    report_path = BUILD / f"qemu-sshd-transmit-rate{SUFFIX}.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    if failures:
        for failure in failures:
            print(f"qemu-sshd-transmit-rate-gate: FAIL {failure}")
        print(f"qemu-sshd-transmit-rate-gate: report={report_path}")
        return 1
    print(f"qemu-sshd-transmit-rate-gate: a peer taking "
          f"{checks['trickle_rate_bytes_per_second']} bytes a second stopped "
          f"being served after {checks['stream_ended_after_s']}s while "
          f"{checks['probes']} ordinary sessions ran, the worst of them "
          f"{checks['worst_probe_seconds']}s; a peer that kept up moved "
          f"{checks['control_bytes']} bytes untouched; report={report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
