#!/usr/bin/env python3
"""The machine-facing half: QMP, a serial console, and the two SSH legs.

Moved verbatim out of `qemu-console-xtop-gate.py` so that neither file has to
carry the whole gate. This half is everything that touches a machine -- the QMP
connection that takes a screendump, the serial console read continuously on its
own thread, and the SSH session that runs the same program in a client of the
same size. It also owns the run context both legs share: the selected
architecture, the run directory and the title the two sides look for, taken
from the same command line the gate was given. The picture model those legs are
compared against comes from `qemu_console_xtop_screen.py`.
"""

from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import pty
import select
import socket
import struct
import subprocess
import sys
import termios
import threading
import time

from qemu_console_xtop_screen import ROOT, render_terminal


BUILD = ROOT / "build"
# Which machine. The three differ in how they are built and booted and in how
# the SSH leg authenticates; the picture they must draw is the same.
ARCH = "aarch64"
for index, argument in enumerate(sys.argv[1:], start=1):
    if argument == "--arch" and index < len(sys.argv) - 1:
        ARCH = sys.argv[index + 1]
    elif argument.startswith("--arch="):
        ARCH = argument.split("=", 1)[1]
if ARCH not in ("aarch64", "x86_64", "riscv64"):
    raise SystemExit(f"unsupported --arch {ARCH!r}")
GATE_DIR = BUILD / f"qemu-console-xtop-gate-{ARCH}"

TITLE = "XAIOS xtop — sampled kernel process monitor"


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


# ------------------------------------------------------------------- QEMU/QMP

class Qmp:
    def __init__(self, path: Path) -> None:
        deadline = time.monotonic() + 60.0
        while True:
            try:
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.connect(str(path))
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.2)
        self.buffer = b""
        self._read()                      # greeting
        self.command("qmp_capabilities")

    def _read(self) -> dict:
        while b"\n" not in self.buffer:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise RuntimeError("QMP closed")
            self.buffer += chunk
        line, self.buffer = self.buffer.split(b"\n", 1)
        return json.loads(line)

    def command(self, name: str, **arguments) -> dict:
        payload = {"execute": name}
        if arguments:
            payload["arguments"] = arguments
        self.sock.sendall((json.dumps(payload) + "\n").encode())
        while True:
            message = self._read()
            if "return" in message or "error" in message:
                if "error" in message:
                    raise RuntimeError(f"QMP {name} failed: {message['error']}")
                return message


class Console:
    """The guest's serial line, read continuously on its own thread.

    Continuously, not on demand. The serial line carries the console, and the
    console carries a process monitor drawing a hundred kilobytes a second;
    a pipe nobody reads fills in under a second, QEMU's stdio character
    device then stalls the virtual CPU on every write, and the guest freezes
    for as long as the reader looks elsewhere -- which, during the SSH leg,
    was the whole leg. The SSH session died of a full pipe on the host, and
    it looked exactly like a kernel that could not run two children.
    """

    def __init__(self, process: subprocess.Popen) -> None:
        self.process = process
        self.output = bytearray()
        self.lock = threading.Lock()
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self) -> None:
        while True:
            try:
                chunk = os.read(self.process.stdout.fileno(), 65536)
            except OSError:
                return
            if not chunk:
                return
            with self.lock:
                self.output.extend(chunk)

    def send(self, value: bytes) -> None:
        self.process.stdin.write(value)
        self.process.stdin.flush()

    def checkpoint(self) -> int:
        with self.lock:
            return len(self.output)

    def snapshot(self) -> bytes:
        with self.lock:
            return bytes(self.output)

    def wait_for(self, marker: bytes, timeout: float, since: int = 0) -> None:
        deadline = time.monotonic() + timeout
        while marker not in self.snapshot()[since:]:
            if self.process.poll() is not None:
                raise RuntimeError(
                    f"QEMU exited rc={self.process.returncode} waiting for "
                    f"{marker!r}\n{self.tail()}"
                )
            if time.monotonic() > deadline:
                raise TimeoutError(f"timed out waiting for {marker!r}\n{self.tail()}")
            time.sleep(0.1)

    def drain(self, seconds: float) -> None:
        time.sleep(seconds)

    def tail(self) -> str:
        return self.snapshot()[-8192:].decode(errors="replace")


# ------------------------------------------------------------------------ SSH

def ssh_command(key: Path, port: int, program: str) -> list[str]:
    """The SSH client invocation for one program on the guest."""
    if ARCH == "riscv64":
        # The RISC-V image builder takes no authorized-keys file yet; its
        # gates log in with the default password, and so does this leg.
        return [
            "sshpass", "-p", "xaios", "ssh", "-tt",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "PreferredAuthentications=password",
            "-o", "PubkeyAuthentication=no",
            "-p", str(port), "admin@127.0.0.1", program,
        ]
    return [
        "ssh", "-tt",
        "-i", str(key),
        "-o", "IdentitiesOnly=yes",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        # See qemu-model-sftp-gate: a ~/.ssh/config that disables public
        # key authentication for this host would otherwise stop the key
        # being offered at all, on that machine only.
        "-o", "PubkeyAuthentication=yes",
        "-o", "PreferredAuthentications=none,publickey",
        "-p", str(port), "admin@127.0.0.1", program,
    ]


def ssh_session_filter_check(key: Path, port: int, columns: int, rows: int) -> None:
    """A whole-frame program over SSH reaches the client as changed cells.

    pong redraws its entire screen sixty times a second -- a clear and every
    row -- and knows nothing of the screen framework. The session runs it
    through a screen of its own, so the client sees one clear and then only
    the cells that moved. Without the filter the stream carries a clear per
    frame and more than a hundred kilobytes a second; with it, one clear and
    a few kilobytes. The thresholds sit well clear of both.
    """
    parent, child = pty.openpty()
    fcntl.ioctl(child, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))
    stderr_path = GATE_DIR / "ssh-pong.stderr"
    with stderr_path.open("wb") as stderr:
        process = subprocess.Popen(ssh_command(key, port, "pong"), cwd=ROOT,
                                   stdin=child, stdout=child, stderr=stderr)
    os.close(child)
    collected = bytearray()
    started = time.monotonic()
    first_frame_at = None
    steady_from = 0
    steady_started = None
    try:
        while time.monotonic() - started < 20.0:
            ready, _, _ = select.select([parent], [], [], 0.25)
            if ready:
                try:
                    chunk = os.read(parent, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                collected.extend(chunk)
            if first_frame_at is None and b"\x1b[?1049h" in collected and b"\x1b[2J" in collected:
                first_frame_at = time.monotonic()
            # Two seconds for the game to settle, then four seconds measured.
            if first_frame_at is not None and steady_started is None and \
                    time.monotonic() - first_frame_at > 2.0:
                steady_started = time.monotonic()
                steady_from = len(collected)
            if steady_started is not None and time.monotonic() - steady_started > 4.0:
                break
        try:
            os.write(parent, b"q")
            time.sleep(1.0)
        except OSError:
            pass
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
        os.close(parent)
    (GATE_DIR / "ssh-pong.raw").write_bytes(collected)
    check(first_frame_at is not None and steady_started is not None,
          "pong over SSH produced no frame:\n"
          + collected.decode("utf-8", errors="replace")[-1500:]
          + "\nssh stderr:\n" + stderr_path.read_text(errors="replace")[-1000:])
    steady = bytes(collected[steady_from:])
    seconds = time.monotonic() - steady_started
    clears = steady.count(b"\x1b[2J")
    moves = steady.count(b"H")
    rate = len(steady) / seconds
    print(f"+ pong over SSH: {len(steady)} bytes in {seconds:.1f} s "
          f"({rate:.0f} B/s), {clears} clears, {moves} positioned runs", flush=True)
    for line in render_terminal(bytes(collected), columns)[:6]:
        print(f"  |{line}")
    check(clears == 0, f"the session filter is not diffing: {clears} screen clears in steady state")
    check(moves >= 60, f"too few positioned runs for a running game: {moves}")
    check(rate < 30000, f"steady stream is {rate:.0f} B/s; whole frames are passing through")


def ssh_frame(key: Path, port: int, columns: int, rows: int) -> list[str]:
    """One xtop frame from an SSH session of the given size."""
    parent, child = pty.openpty()
    fcntl.ioctl(child, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))
    stderr_path = GATE_DIR / "ssh.stderr"
    command = ssh_command(key, port, "xtop")
    with stderr_path.open("wb") as stderr:
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            stdin=child,
            stdout=child,
            stderr=stderr,
        )
    os.close(child)
    collected = bytearray()
    deadline = time.monotonic() + 45.0
    # Four seconds of updates after the first frame: enough for the screen
    # to have settled into its steady state.
    settle_at = time.monotonic() + 8.0
    try:
        while time.monotonic() < deadline:
            ready, _, _ = select.select([parent], [], [], 0.25)
            if ready:
                try:
                    chunk = os.read(parent, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                collected.extend(chunk)
            if TITLE.encode() in collected and time.monotonic() > settle_at:
                break
        try:
            os.write(parent, b"q")
            time.sleep(1.0)
        except OSError:
            pass  # the session already ended; the frames are what matter
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
        os.close(parent)
    (GATE_DIR / "ssh.raw").write_bytes(collected)
    if TITLE.encode() not in collected:
        # sshd's own account of the session, fetched over a second session
        # when the first got nowhere -- an unauthorized key or a failed
        # child launch is written there and nowhere the client can see.
        journal = ""
        try:
            fetch = command[:-1] + ["cat /state/sshd.log"]
            fetch = [a for a in fetch if a != "-tt"]
            journal = subprocess.run(fetch, capture_output=True, text=True,
                                     timeout=30).stdout[-1500:]
        except Exception:  # noqa: BLE001 - diagnostics must not mask the result
            journal = "(unavailable)"
        raise RuntimeError(
            f"SSH session produced no xtop frame (rc={process.returncode}):\n"
            + collected.decode("utf-8", errors="replace")[-2000:]
            + "\nssh stderr:\n"
            + stderr_path.read_text(errors="replace")[-2000:]
            + "\nsshd log:\n" + journal
        )
    # The whole stream, applied in order: one full frame, then the cells
    # that changed since. What the terminal shows at the end is the screen.
    return render_terminal(bytes(collected), columns)
