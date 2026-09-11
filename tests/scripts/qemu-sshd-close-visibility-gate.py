#!/usr/bin/env python3
"""B-43: a connection the server gave up on, and a console that never said so.

B-43's whole evidence is an accept with nothing after it. `net_accept
connfd=851` appears on the guest's console, and then, for about eighteen
seconds, nothing -- while the connection accepted *after* it was served to
completion. Reading that requires telling two very different things apart:

  * the server looked at this connection, decided it was not going to become a
    session, and closed it; and
  * the server never got round to this connection at all.

Before this gate's fix those print exactly the same thing on the console:
nothing. Every close of a connection that had already been accepted went to
`ssh_log`, and `ssh_log` writes to the audit file on the durable volume, which
no soak and no gate reads -- the same blind spot that hid B-28's refusal and
B-41's channel failures. The kernel's `syscall: net_close` line is all that
reaches the console, and it carries no reason and, for a connection the server
is patiently waiting on, arrives half a minute after the interesting moment.

The connect timeout is the worst of them and the one B-43 needs most. A client
that has said nothing gives the console nothing either, so a connection closed
thirty seconds later for having never sent a version string is, from the
console's point of view, identical to a connection that was ignored for thirty
seconds. That ambiguity is exactly the reading B-43 turns on, and it is why the
tracker row asks for this regardless of where the defect turns out to be.

What this gate does, on one boot:

  * opens a raw TCP connection to port 22, reads the server's version banner to
    prove the server did engage with it, and then says nothing at all. After
    SSHD_TIMEOUT_CONNECT the server must close it, and the console must carry
    `sshd: connection closed reason=connect-timeout`.
  * opens a second raw connection and sends a version line the server must
    reject. The console must carry `reason=client-version-invalid`.
  * runs an ordinary SFTP session, which must also produce a close line, and
    must NOT produce either of the two reasons above.

The last two are the controls, and each closes a way this gate could be green
while testing nothing:

  * a fix that printed one constant string on every close would satisfy the
    first check on its own. Two connections that fail differently, and that
    must be reported differently, is what makes the reason mean something.
  * a fix that printed a close line only for the paths this gate drives would
    leave the ordinary case as silent as before -- and the ordinary case is
    most of what a soak's console contains. So an ordinary session's close is
    required to be announced too.

`SSHD_TIMEOUT_CONNECT` is read out of `userspace/sshd/sshd.h` rather than
repeated here, for the reason the connection-rate gate reads its limit from the
source: a gate carrying its own copy of a constant passes after someone changes
the real one.

The service-loop stall line is asserted the other way round, by its absence.
sshd is the only thing on this machine that drives the network stack --
`network_poll_tick` runs inside the network syscalls a process makes and inside
its wait, with no timer and no interrupt behind it -- so a pass of sshd's loop
that takes a second is a second in which the guest has no networking at all.
SSHD_LOOP_STALL_REPORT_NS is set far above ordinary work so that the line means
something when it appears; this gate does real transfers and requires it not to
appear, which is what keeps that claim honest.

Its companion, the wait-overrun line, is recorded rather than asserted. That
one fires when sshd was not running at all, which on an emulated guest sharing
a build machine is the host's doing; failing on it would be failing on whoever
else is using the laptop. It is in the report because it is what separates "the
server held the machine" from "the machine was not running" -- a distinction a
peer cannot make and a Fusion soak needs.
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
READY_MARKER = "SSH server: up and running (tcp/22)"

SSH_BASE = ["-F", "/dev/null", "-o", "IdentitiesOnly=yes",
            "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "PubkeyAuthentication=yes",
            "-o", "PreferredAuthentications=publickey",
            "-o", "PasswordAuthentication=no", "-o", "LogLevel=ERROR"]

# 256 KiB, the load soak's payload, so the ordinary session in this gate is the
# same shape of work the Fusion run was doing when B-43 appeared.
PAYLOAD_BYTES = 256 * 1024

CLOSE_LINE = re.compile(
    r"sshd: connection closed reason=(?P<reason>[a-z-]+) sockfd=(?P<sockfd>\d+) "
    r"state=(?P<state>\d+) held_ms=(?P<held>\d+) count=(?P<count>\d+)")


def source_constant(name: str) -> int:
    """A timeout in nanoseconds, read from the header that defines it."""
    text = (ROOT / "userspace" / "sshd" / "sshd.h").read_text(encoding="utf-8")
    match = re.search(rf"#define\s+{name}\s+UINT64_C\((\d+)\)", text)
    if match is None:
        raise RuntimeError(f"{name} is not defined in userspace/sshd/sshd.h")
    return int(match.group(1))


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


def silent_peer(port: int, patience: float) -> dict[str, object]:
    """Connect, read the banner, say nothing, and wait to be closed.

    Reading the banner matters: it is the proof that the server engaged with
    this connection, so a close that follows is the server giving up on a
    connection it was serving rather than anything happening earlier.
    """
    opened = time.monotonic()
    connection = socket.create_connection(("127.0.0.1", port), 30)
    try:
        connection.settimeout(30.0)
        banner = connection.recv(256)
        connection.settimeout(patience)
        closed_at = None
        try:
            while True:
                if connection.recv(256) == b"":
                    closed_at = time.monotonic()
                    break
        except socket.timeout:
            pass
        except OSError:
            closed_at = time.monotonic()
        return {"banner": banner.decode(errors="replace").strip(),
                "closed_after_s": (round(closed_at - opened, 1)
                                   if closed_at is not None else None)}
    finally:
        connection.close()


def bad_version_peer(port: int) -> dict[str, object]:
    """Connect and offer a version line the server has to reject."""
    opened = time.monotonic()
    connection = socket.create_connection(("127.0.0.1", port), 30)
    try:
        connection.settimeout(30.0)
        banner = connection.recv(256)
        connection.sendall(b"NOT-AN-SSH-VERSION-LINE\r\n")
        closed_at = None
        try:
            while True:
                if connection.recv(256) == b"":
                    closed_at = time.monotonic()
                    break
        except socket.timeout:
            pass
        except OSError:
            closed_at = time.monotonic()
        return {"banner": banner.decode(errors="replace").strip(),
                "closed_after_s": (round(closed_at - opened, 1)
                                   if closed_at is not None else None)}
    finally:
        connection.close()


def run_sftp(key: Path, port: int, batch: str, timeout: float):
    started = time.monotonic()
    process = subprocess.Popen(
        ["sftp", *SSH_BASE, "-i", str(key), "-P", str(port), "-b", "-",
         "admin@127.0.0.1"], cwd=ROOT, text=True, stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)
    try:
        _, errors = process.communicate(batch, timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        return 255, "timed out", time.monotonic() - started
    return process.returncode, errors.strip(), time.monotonic() - started


def closes(console: str) -> list[dict[str, str]]:
    return [match.groupdict() for match in CLOSE_LINE.finditer(console)]


def console_since(log_path: Path, mark: int) -> str:
    """What the guest printed after `mark` bytes of console.

    Sliced as bytes and decoded afterwards, not the other way round. The boot
    banner is full of escape sequences and the console is not guaranteed to be
    valid UTF-8, so a byte count is not a character index: decoding first and
    then slicing by a byte offset skips past real output, and silently -- the
    first draft of this gate reported the fix missing when the lines were
    there, which is the same class of mistake as the defect it is gating."""
    return log_path.read_bytes()[mark:].decode(errors="replace")


def main() -> int:
    gate_dir = BUILD / f"sshd-close-visibility{SUFFIX}"
    # A persistent.img left behind holds the previous run's authorized key, and
    # the guest then refuses this run's -- a stale volume reporting itself as
    # an authentication failure.
    if gate_dir.exists():
        shutil.rmtree(gate_dir)
    gate_dir.mkdir(parents=True, exist_ok=True)
    key = gate_dir / "admin"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
                    "xaios-sshd-close-visibility-gate", "-f", str(key)],
                   cwd=ROOT, check=True, timeout=30)

    build(key)

    connect_timeout_s = source_constant("SSHD_TIMEOUT_CONNECT") / 1e9
    stall_report_s = source_constant("SSHD_LOOP_STALL_REPORT_NS") / 1e9

    port = reserve_port()
    log_path = BUILD / f"qemu-sshd-close-visibility{SUFFIX}.log"
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
    checks: dict[str, object] = {}
    payload = gate_dir / "payload.bin"
    payload.write_bytes(bytes((i * 31 + 7) & 0xFF for i in range(PAYLOAD_BYTES)))
    returned = gate_dir / "returned.bin"
    try:
        wait_for_marker(log_path, READY_MARKER,
                        float(smoke_timeout(ARCH, 300)), qemu)
        wait_for_ssh(key, port, qemu, float(smoke_timeout(ARCH, 240)))
        mark = len(log_path.read_bytes())

        # 1. An ordinary session, first, so its close cannot be confused with
        #    either of the two below and so the machine is known good.
        remote = "/state/close-visibility.bin"
        rc, message, seconds = run_sftp(
            key, port,
            f"put {payload} {remote}\nget {remote} {returned}\nrm {remote}\n",
            float(smoke_timeout(ARCH, 120)))
        checks["ordinary_rc"] = rc
        checks["ordinary_seconds"] = round(seconds, 1)
        checks["ordinary_identical"] = (
            returned.is_file() and returned.read_bytes() == payload.read_bytes())
        if rc != 0 or not checks["ordinary_identical"]:
            failures.append(
                f"the ordinary {PAYLOAD_BYTES}-byte SFTP round trip this gate "
                f"needs as its control did not complete: rc={rc} "
                f"identical={checks['ordinary_identical']} {message!r}. "
                f"Nothing below this is evidence about B-43")
        time.sleep(3.0)
        after_ordinary = console_since(log_path, mark)
        ordinary_closes = closes(after_ordinary)
        checks["ordinary_close_reasons"] = sorted(
            {entry["reason"] for entry in ordinary_closes})
        if not ordinary_closes:
            failures.append(
                "an ordinary SFTP session came and went and the console said "
                "nothing about the connection being closed. That is the blind "
                "spot B-43 is read through: most of what a soak's console "
                "holds is ordinary sessions, and if their closes are silent "
                "the interesting one cannot be told from them")
        for forbidden in ("connect-timeout", "client-version-invalid"):
            if forbidden in checks["ordinary_close_reasons"]:
                failures.append(
                    f"an ordinary SFTP session was reported as closed with "
                    f"reason={forbidden}. The reason is being printed rather "
                    f"than derived, so it says nothing about why any "
                    f"particular connection ended")

        # 2. The connect timeout: engaged with, then never spoken to again.
        mark_silent = len(log_path.read_bytes())
        silent = silent_peer(port, connect_timeout_s + 45.0)
        checks["silent_peer"] = silent
        if not silent["banner"].startswith("SSH-2.0"):
            failures.append(
                f"the silent peer never received a version banner "
                f"({silent['banner']!r}), so the server had not begun serving "
                f"it and its close is not the connect-timeout path")
        if silent["closed_after_s"] is None:
            failures.append(
                f"the server never closed a connection that said nothing for "
                f"{connect_timeout_s + 45:.0f}s, though SSHD_TIMEOUT_CONNECT "
                f"is {connect_timeout_s:.0f}s")
        time.sleep(3.0)
        silent_console = console_since(log_path, mark_silent)
        silent_reasons = [entry["reason"] for entry in closes(silent_console)]
        checks["silent_close_reasons"] = silent_reasons
        if "connect-timeout" not in silent_reasons:
            failures.append(
                "the console did not report a connect-timeout close. The "
                "server accepted a connection, served it a banner, waited "
                f"{connect_timeout_s:.0f}s and closed it, and the only thing "
                "the console carries is the kernel's net_close -- which is "
                "indistinguishable from the server never having touched it. "
                f"Reasons seen: {silent_reasons}")

        # 3. A different failure has to report differently.
        mark_bad = len(log_path.read_bytes())
        bad = bad_version_peer(port)
        checks["bad_version_peer"] = bad
        if bad["closed_after_s"] is None:
            failures.append(
                "the server did not close a connection that offered an "
                "invalid SSH version line")
        time.sleep(3.0)
        bad_console = console_since(log_path, mark_bad)
        bad_reasons = [entry["reason"] for entry in closes(bad_console)]
        checks["bad_version_close_reasons"] = bad_reasons
        if "client-version-invalid" not in bad_reasons:
            failures.append(
                f"a connection that offered an invalid version line was not "
                f"reported as closed for that reason. Reasons seen: "
                f"{bad_reasons}")
        if bad["closed_after_s"] is not None and \
                bad["closed_after_s"] > connect_timeout_s:
            failures.append(
                f"the invalid-version connection took "
                f"{bad['closed_after_s']}s to close, which is longer than "
                f"SSHD_TIMEOUT_CONNECT. It was closed by the timeout, not by "
                f"the version check, so this case is not testing what it says")

        # 4. The stall line, by its absence. Everything above did real work,
        #    including a 256 KiB transfer; if SSHD_LOOP_STALL_REPORT_NS were
        #    set anywhere near ordinary work this would be full of them, and
        #    the line would mean nothing on the run that matters.
        console = console_since(log_path, mark)
        stalls = [line for line in console.splitlines()
                  if "sshd: service loop stalled" in line]
        checks["service_loop_stalls"] = stalls
        # Recorded, not asserted. A wait that overran says this process was not
        # running, which on an emulated guest sharing a build machine is the
        # host's doing and not a defect of the guest's. It is in the report
        # because it is exactly the evidence that separates "sshd held the
        # machine" from "the machine was not running", and a gate that failed
        # on it would be failing on the load of whoever ran it.
        checks["service_loop_wait_overruns"] = [
            line for line in console.splitlines()
            if "sshd: service loop wait overran" in line]
        if stalls:
            failures.append(
                f"the service loop reported {len(stalls)} stalls during "
                f"ordinary work, with SSHD_LOOP_STALL_REPORT_NS at "
                f"{stall_report_s:.1f}s: {stalls[:4]}. Either the threshold is "
                f"too low to mean anything, or this guest really does stop "
                f"driving its network stack for that long during an ordinary "
                f"transfer -- and the second of those is B-43")

        # 5. Still there.
        alive, message, _ = run_sftp(key, port, "ls /state\n",
                                     float(smoke_timeout(ARCH, 60)))
        checks["still_serving_rc"] = alive
        if alive != 0:
            failures.append(
                f"after the exercise the guest would not answer an ordinary "
                f"SFTP listing: rc={alive} {message!r}")
    finally:
        stop_process(qemu)
        handle.close()

    report = {
        "schema": "xaios.sshd.close-visibility.v1",
        "status": "pass" if not failures else "fail",
        "architecture": ARCH,
        "connect_timeout_s": connect_timeout_s,
        "stall_report_s": stall_report_s,
        "checks": checks,
        "failures": failures,
        "guest_log": str(log_path),
    }
    report_path = BUILD / f"qemu-sshd-close-visibility{SUFFIX}.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    if failures:
        for failure in failures:
            print(f"qemu-sshd-close-visibility-gate: FAIL {failure}")
        print(f"qemu-sshd-close-visibility-gate: report={report_path}")
        return 1
    print(f"qemu-sshd-close-visibility-gate: every close reached the console "
          f"with its reason -- ordinary session "
          f"{checks['ordinary_close_reasons']}, a peer that said nothing for "
          f"{connect_timeout_s:.0f}s reported as connect-timeout, an invalid "
          f"version line reported as client-version-invalid in "
          f"{checks['bad_version_peer']['closed_after_s']}s, and no service "
          f"loop stall during a {PAYLOAD_BYTES}-byte round trip; "
          f"report={report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
