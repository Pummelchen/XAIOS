#!/usr/bin/env python3
"""B-38: a file transfer that stalls, and a session nobody ever closes.

The report was a 1800-second Fusion load soak in which exactly one SFTP round
out of 2463 failed -- `Read from remote host: Operation timed out` -- and the
guest's own console showed the socket for that round accepted, authenticated,
and then never closed, while the next round was served normally.

The mechanism this gate holds shut:

  * The screen framework's session filter reads every byte a channel sends,
    watching for the eight bytes a program writes to enter the alternate
    screen (ESC [ ? 1 0 4 9 h). Once it sees them it stops forwarding the
    bytes and starts painting them into a terminal screen, sending only the
    cells that changed. That is the whole point of the feature, and it is
    right -- for a terminal.
  * sshd ran *every* channel through it, including the SFTP subsystem. SFTP
    carries file contents, which are arbitrary binary, so a file can contain
    those eight bytes by coincidence. When one does, the filter eats the rest
    of the transfer and the client receives something that is not the file.
  * SFTP frames every message with a length. A mangled stream therefore ends
    one of two ways: a bogus length, which the client reports as `Received
    message too long`, or a length that promises more bytes than will ever
    arrive, which leaves the client waiting for a response the server already
    believes it sent.
  * A client waiting like that sends nothing more. The server sees an
    authenticated connection that has simply gone quiet: no error to report
    and nothing to close. The session sits in sshd's table until the
    300-second idle timeout reaps it -- which is why the console shows an
    accept and an authentication with no matching close anywhere near it, and
    why the machine goes on serving everyone else.

Two shapes are exercised, because the same defect presents as two different
failures depending on where the mangling lands, and a gate that checked only
one would pass on half a fix:

  * a small payload, where the client errors out; and
  * a larger one, where the client hangs and the session is orphaned. This is
    the shape the tracker item describes, so the console is read for it: every
    socket the guest accepted during the transfer must have been closed again.

The negative control is a payload identical in every way except that it does
not contain the sequence. It must round-trip. Without it a guest whose SFTP
was broken for any other reason -- a full volume, a refused subsystem -- would
fail this gate and be read as B-38.

The gate also asserts the escape bytes really are in the payload it sends. A
payload generator that quietly stopped emitting them would make every
assertion below pass while testing nothing at all.
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
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
sys.path.insert(0, str(ROOT / "tests" / "scripts"))
from qemu_gate_lib import (arch_from_argv, qemu_boot_environment, qemu_runner,
                           smoke_timeout)

ARCH = arch_from_argv(sys.argv)
SUFFIX = "" if ARCH == "aarch64" else f"-{ARCH}"
READY_MARKER = "SSH server: up and running (tcp/22)"

# The sequence a program writes to enter the alternate screen, and the one it
# writes to leave. Spelled as bytes rather than as an escaped string so that
# what goes into the payload is unambiguous.
ALTERNATE_ENTER = bytes([0x1B, 0x5B, 0x3F, 0x31, 0x30, 0x34, 0x39, 0x68])
ALTERNATE_LEAVE = bytes([0x1B, 0x5B, 0x3F, 0x31, 0x30, 0x34, 0x39, 0x6C])

# A filler byte that is not part of any escape sequence, so the only thing
# distinguishing a payload below from the control is the sequence itself.
FILLER = b"B"


def payloads() -> dict[str, bytes]:
    """The control first, then the shapes that carry the sequence."""
    return {
        # Same length and same bytes as `small-enter` minus the sequence.
        "control": b"A" * 100 + FILLER * 908,
        # Small enough that the desynchronised framing produces a bogus
        # length and the client gives up at once.
        "small-enter": b"A" * 100 + ALTERNATE_ENTER + FILLER * 900,
        # A payload that enters and leaves again, so a fix that handled only
        # the enter would still be caught.
        "enter-and-leave": (b"A" * 100 + ALTERNATE_ENTER + FILLER * 400 +
                            ALTERNATE_LEAVE + b"C" * 400),
        # Big enough that the mangled stream promises more than it delivers,
        # so the client waits instead of erroring. This is the shape that
        # orphans the session.
        "large-enter": b"A" * 100 + ALTERNATE_ENTER + FILLER * 3000,
    }


def reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def sftp_arguments(key: Path, port: int) -> list[str]:
    return [
        "sftp", "-F", "/dev/null", "-i", str(key),
        "-o", "IdentitiesOnly=yes",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        # Named explicitly for the same reason the session-exhaustion gate
        # names them: a developer's ~/.ssh/config can otherwise stop the key
        # being offered on that machine only.
        "-o", "PubkeyAuthentication=yes",
        "-o", "PreferredAuthentications=publickey",
        "-o", "PasswordAuthentication=no",
        "-o", "LogLevel=ERROR",
        "-P", str(port), "-b", "-", "admin@127.0.0.1",
    ]


def run_sftp(key: Path, port: int, batch: str, timeout: float,
             on_timeout: Any = None) -> tuple[int | None, str, float]:
    """Returns (exit code or None when it hung, client output, seconds).

    `on_timeout` is called while the client is still hung and before it is
    killed. That matters: the guest closes its side as soon as the client's
    FIN arrives, so a console read taken after the kill shows a tidy session
    and hides the very thing the hang is evidence of.
    """
    started = time.monotonic()
    process = subprocess.Popen(sftp_arguments(key, port), cwd=ROOT, text=True,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, preexec_fn=os.setsid)
    try:
        output = process.communicate(batch, timeout=timeout)
    except subprocess.TimeoutExpired:
        if on_timeout is not None:
            on_timeout()
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate()
        return None, "", time.monotonic() - started
    return (process.returncode, ("".join(part or "" for part in output)
                                 ).strip()[:300],
            time.monotonic() - started)


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
    tail = ""
    if log_path.exists():
        tail = "\n".join(log_path.read_text(errors="replace").splitlines()[-40:])
    raise TimeoutError(f"timed out waiting for {marker!r}\n{tail}")


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
            last = f"ssh-keyscan rc={result.returncode} {result.stderr!r}"
        time.sleep(1.0)
    raise TimeoutError(f"timed out waiting for SSH key exchange: {last}")


def stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
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


def sockets_left_open(console: str) -> list[int]:
    """Sockets the guest accepted in this slice and did not close in it."""
    accepted = [int(value) for value in
                re.findall(r"net_accept listenfd=\d+ connfd=(\d+)", console)]
    closed = {int(value) for value in
              re.findall(r"net_close sockfd=(\d+)", console)}
    return [value for value in accepted if value not in closed]


def accepted_count(console: str) -> int:
    return len(re.findall(r"net_accept listenfd=\d+ connfd=\d+", console))


# How long a closing session is given before it counts as orphaned.
#
# The guest closes its side after the client's FIN reaches it, which is a
# moment after the client process has exited -- so reading the console the
# instant sftp returns finds a socket that is about to be closed and calls it
# a leak. This is comfortably longer than that, and far shorter than the
# 300-second idle timeout that is the only thing which reaps a genuinely
# orphaned session, so the two cannot be confused.
ORPHAN_GRACE_S = 30.0


def wait_for_sessions_to_close(log_path: Path, mark: int,
                               grace: float) -> tuple[str, list[int]]:
    """The console since `mark`, once every accepted socket has been closed
    or `grace` has elapsed, whichever is first."""
    deadline = time.monotonic() + grace
    while True:
        console = log_path.read_bytes()[mark:].decode("utf-8", "replace")
        left = sockets_left_open(console)
        if not left or time.monotonic() >= deadline:
            return console, left
        time.sleep(0.5)


def main() -> int:
    gate_dir = BUILD / f"sftp-binary-passthrough{SUFFIX}"
    # Everything from a previous run goes. A persistent.img left behind holds
    # the *earlier* run's authorized key, and the guest then refuses this
    # run's key with "presented public key was not authorized" -- a stale
    # volume reporting itself as an authentication failure.
    if gate_dir.exists():
        shutil.rmtree(gate_dir)
    gate_dir.mkdir(parents=True, exist_ok=True)
    key = gate_dir / "admin"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
                    "xaios-sftp-binary-passthrough-gate", "-f", str(key)],
                   cwd=ROOT, check=True, timeout=30)

    cases = payloads()
    failures: list[str] = []
    checks: dict[str, object] = {}

    # The gate's own payloads, checked before the guest is asked anything.
    #
    # Every assertion below is about what happens to eight particular bytes.
    # If a future edit stopped putting them in, the transfers would all
    # succeed and this gate would report a pass having exercised nothing.
    for name, payload in cases.items():
        carries = ALTERNATE_ENTER in payload
        if name == "control":
            if carries:
                raise RuntimeError(
                    "the control payload contains the alternate-screen "
                    "sequence, so it is not a control and a failure in it "
                    "could not be told from the defect")
        elif not carries:
            raise RuntimeError(
                f"payload {name!r} does not contain the alternate-screen "
                f"sequence, so sending it proves nothing about B-38")
    if len(cases["control"]) != len(cases["small-enter"]):
        raise RuntimeError(
            "the control and the small payload differ in length, so a size "
            "effect could be mistaken for the escape sequence")
    checks["payload_bytes"] = {name: len(value) for name, value in cases.items()}

    build(key)

    port = reserve_port()
    log_path = BUILD / f"qemu-sftp-binary-passthrough{SUFFIX}.log"
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

    # Generous enough for a loaded machine, short enough that a hung transfer
    # is a failure rather than a wait. The defect hangs the client until it
    # is killed; the fixed guest answers in under a second.
    per_transfer = float(smoke_timeout(ARCH, 60))
    results: dict[str, object] = {}
    try:
        wait_for_marker(log_path, READY_MARKER,
                        float(smoke_timeout(ARCH, 240)), qemu)
        wait_for_ssh(port, qemu, float(smoke_timeout(ARCH, 180)))

        for name, payload in cases.items():
            source = gate_dir / f"{name}.bin"
            source.write_bytes(payload)
            returned = gate_dir / f"{name}.back.bin"
            returned.unlink(missing_ok=True)
            remote = f"/state/b38-{name}.bin"

            code, message, _ = run_sftp(
                key, port, f"put {source} {remote}\n", per_transfer)
            if code != 0:
                failures.append(
                    f"{name}: the guest would not accept the upload at all "
                    f"(rc={code} {message!r}), so nothing was left to "
                    f"download and this case proves nothing")
                continue

            mark = len(log_path.read_bytes())
            # Filled in only if the client hangs, from the console as it
            # stood while it was still hanging.
            hung_sessions: list[int] = []

            def snapshot() -> None:
                slice_ = log_path.read_bytes()[mark:].decode("utf-8", "replace")
                hung_sessions.extend(sockets_left_open(slice_))

            code, message, seconds = run_sftp(
                key, port, f"get {remote} {returned}\n", per_transfer,
                on_timeout=snapshot)
            console, orphaned = wait_for_sessions_to_close(
                log_path, mark, ORPHAN_GRACE_S)
            got = returned.read_bytes() if returned.is_file() else b""
            identical = got == payload
            results[name] = {
                "exit_code": code,
                "seconds": round(seconds, 1),
                "identical": identical,
                "bytes_returned": len(got),
                "bytes_sent": len(payload),
                "sessions_accepted": accepted_count(console),
                "sessions_left_open": orphaned,
                "sessions_open_while_hung": hung_sessions,
                "client": message,
            }

            if code is None:
                failures.append(
                    f"{name}: the download never finished -- the client was "
                    f"still waiting after {seconds:.0f}s. That is B-38's "
                    f"reported symptom: a transfer the server believes it "
                    f"answered and a client still waiting for it. While it "
                    f"hung, the guest held socket(s) {hung_sessions} accepted "
                    f"and authenticated with no close")
                continue
            if code != 0:
                failures.append(
                    f"{name}: the download failed (rc={code}) with "
                    f"{message!r}. A length the client calls impossible is "
                    f"what a mangled SFTP stream looks like from the other "
                    f"end")
                continue
            if not identical:
                failures.append(
                    f"{name}: the file came back different -- {len(got)} "
                    f"bytes against the {len(payload)} sent. The bytes that "
                    f"went missing are the payload the screen filter ate")
                continue
            # The tracker item is about a session nobody closes, so that is
            # asserted directly rather than inferred from the transfer having
            # worked. A future defect could corrupt nothing and still leak.
            if accepted_count(console) == 0:
                failures.append(
                    f"{name}: the console recorded no accepted socket during "
                    f"the download, so the check for an unclosed session "
                    f"below had nothing to look at and proves nothing")
            elif orphaned:
                failures.append(
                    f"{name}: the transfer succeeded but {ORPHAN_GRACE_S:.0f}s "
                    f"later the guest still had socket(s) {orphaned} accepted "
                    f"and never closed, which is the leak B-38 describes")

        # And the machine is still there. A guest that had wedged would fail
        # every case above for a reason that is not this one, so this
        # separates "the defect" from "the guest fell over".
        alive, alive_message, _ = run_sftp(
            key, port, "ls /state\n", per_transfer)
        checks["still_serving_rc"] = alive
        if alive != 0:
            failures.append(
                f"after the transfers the guest would not answer an ordinary "
                f"SFTP listing: rc={alive} {alive_message!r}")
    finally:
        stop_process(qemu)
        handle.close()

    checks["transfers"] = results
    report = {
        "schema": "xaios.sftp.binary-passthrough.v1",
        "status": "pass" if not failures else "fail",
        "architecture": ARCH,
        "checks": checks,
        "failures": failures,
        "guest_log": str(log_path),
    }
    report_path = BUILD / f"qemu-sftp-binary-passthrough{SUFFIX}.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    if failures:
        for failure in failures:
            print(f"qemu-sftp-binary-passthrough-gate: FAIL {failure}")
        print(f"qemu-sftp-binary-passthrough-gate: report={report_path}")
        return 1
    print(f"qemu-sftp-binary-passthrough-gate: {len(cases)} payloads "
          f"round-tripped byte for byte, {len(cases) - 1} of them carrying "
          f"the alternate-screen sequence, no session left open; "
          f"report={report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
