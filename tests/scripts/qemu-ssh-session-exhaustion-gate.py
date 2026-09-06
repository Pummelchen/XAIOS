#!/usr/bin/env python3
"""B-25: a guest that boots perfectly and refuses every command.

The report was a Fusion guest that, after a snapshot revert, answered
"Command execution failed" to everything while SFTP kept working, with no
line in the console to say why. It was filed as intermittent and closed twice
as not reproducible, and the evidence against session exhaustion was forty
*successful* sessions in a row -- which is the one case that never leaked.

The mechanism, end to end:

  * The kernel keeps sixty-four session contexts, allocated on the first call
    that names a session id, because a context holds the session's working
    directory and that has to survive between commands.
  * The session id is the connection's socket handle, and socket handles come
    from a counter that only goes up (`g_socket_next_id`) -- they are never
    reused. So every connection is a new session id and a new context.
  * sshd closed the context only when a flag said one had been opened, and
    the flag was set in exactly one place: after a command had *succeeded*.
    A command the kernel refused allocated a context and set nothing. So did
    an interactive shell, whose prompt asks the kernel for the working
    directory before the user has typed a thing.
  * After sixty-four such connections the table was full. Every later session
    was refused inside remote_login_execute_session, *before* the function
    that logs -- so the console said nothing. SFTP does not take that path,
    so it kept working, which is what made the guest look healthy.

That is not intermittent. It is deterministic in the number of connections,
which is why it looked like weather.

This gate reproduces it in that form: open more connections than the table has
slots, each running a command the kernel refuses, then ask the guest to do
something ordinary. Before the fix the ordinary command fails. After it, it
does not.

Two things it asserts beyond the symptom, because the symptom alone would now
be hidden by the kernel's new backstop -- a full table evicts its oldest entry
rather than refusing everything, so a leaking sshd would still answer commands
and this gate would pass having tested nothing:

  * the console must show no eviction and no full table at all. That is the
    assertion that actually pins the sshd fix.
  * the connections must really have been distinct sessions. The gate reads
    the accept log and requires more distinct socket handles than the table
    has slots -- otherwise a stack that recycled handles would make the whole
    exercise a single session repeated, and it would pass for that reason.
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

# The kernel's table is sixty-four. Enough connections to pass it with room to
# spare, so the gate is not sitting exactly on the boundary it is testing.
SESSION_SLOTS = 64
CONNECTIONS = int(os.environ.get("XAIOS_SSH_SESSION_CONNECTIONS", "80"))

# A command the kernel refuses, which is what makes a connection leak.
#
# The kernel answers an unrecognised command with XAIOS_ERR_INVALID and the
# text below, and every non-OK status comes back through the syscall wrapper
# as -1 -- so this is a session whose only command failed, which is exactly
# the case sshd used to allocate a context for and never close. The reply
# text is asserted rather than assumed: a guest that started *accepting* this
# command would tidy up after every connection and the gate would pass having
# tested nothing.
REFUSED_COMMAND = "xaios-b25-no-such-command"
REFUSED_REPLY = "command not found"


def reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def ssh_arguments(key: Path, port: int) -> list[str]:
    return [
        "ssh", "-i", str(key),
        "-o", "IdentitiesOnly=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        # Named explicitly: a developer's ~/.ssh/config that turns public key
        # authentication off for 127.0.0.1 otherwise leaves the client
        # loading the key and never offering it, on that machine only.
        "-o", "PubkeyAuthentication=yes",
        "-o", "PreferredAuthentications=publickey",
        "-o", "PasswordAuthentication=no",
        "-o", "ConnectTimeout=20",
        "-o", "LogLevel=ERROR",
        "-p", str(port), "admin@127.0.0.1",
    ]


def run_ssh(key: Path, port: int, command: str,
            timeout: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(ssh_arguments(key, port) + [command], cwd=ROOT,
                          text=True, stdin=subprocess.DEVNULL,
                          capture_output=True, timeout=timeout, check=False)


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


def distinct_accepted_sockets(log: str) -> list[int]:
    return sorted({int(value) for value in
                   re.findall(r"net_accept listenfd=\d+ connfd=(\d+)", log)})


def main() -> int:
    gate_dir = BUILD / f"ssh-session-exhaustion{SUFFIX}"
    # Everything from a previous run goes, not just the key.
    #
    # The key is regenerated per run and baked into the image, but
    # /etc/xaios_authorized_keys is read from the durable volume once the
    # guest has one -- so a persistent.img left over from an earlier run
    # holds the *earlier* key, and the guest refuses the new one with
    # "presented public key was not authorized". That is a stale volume
    # reporting itself as an authentication failure, and it cost this gate a
    # boot before it was fixed.
    if gate_dir.exists():
        shutil.rmtree(gate_dir)
    gate_dir.mkdir(parents=True, exist_ok=True)
    key = gate_dir / "admin"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
                    "xaios-ssh-session-exhaustion-gate", "-f", str(key)],
                   cwd=ROOT, check=True, timeout=30)
    build(key)

    port = reserve_port()
    log_path = BUILD / f"qemu-ssh-session-exhaustion{SUFFIX}.log"
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

    failures: list[str] = []
    checks: dict[str, object] = {"connections": CONNECTIONS,
                                 "session_slots": SESSION_SLOTS}
    per_command = float(smoke_timeout(ARCH, 60))
    try:
        wait_for_marker(log_path, READY_MARKER,
                        float(smoke_timeout(ARCH, 240)), qemu)
        wait_for_ssh(port, qemu, float(smoke_timeout(ARCH, 180)))

        baseline = run_ssh(key, port, "pwd", per_command)
        checks["baseline_pwd"] = baseline.stdout.strip()
        if baseline.returncode != 0 or not baseline.stdout.startswith("/"):
            raise RuntimeError(
                f"the guest could not answer `pwd` before the gate began: "
                f"rc={baseline.returncode} {baseline.stdout!r} "
                f"{baseline.stderr!r}")

        # The refusal, confirmed before it is relied on.
        probe = run_ssh(key, port, REFUSED_COMMAND, per_command)
        checks["refused_command"] = REFUSED_COMMAND
        checks["refused_reply"] = (probe.stdout + probe.stderr).strip()[:200]
        if REFUSED_REPLY not in (probe.stdout + probe.stderr):
            raise RuntimeError(
                f"this guest no longer refuses {REFUSED_COMMAND!r}, so the "
                f"gate cannot open a session whose command fails and would "
                f"prove nothing: {checks['refused_reply']!r}")

        started = time.monotonic()
        for index in range(CONNECTIONS):
            run_ssh(key, port, REFUSED_COMMAND, per_command)
        checks["exhaustion_seconds"] = round(time.monotonic() - started, 1)

        # The symptom, as reported: an ordinary command, on a guest that has
        # done nothing but answer refusals.
        after = run_ssh(key, port, "pwd", per_command)
        checks["pwd_after"] = after.stdout.strip()
        checks["pwd_after_rc"] = after.returncode
        if after.returncode != 0 or not after.stdout.startswith("/"):
            failures.append(
                f"after {CONNECTIONS} connections the guest could not answer "
                f"`pwd`: rc={after.returncode} stdout={after.stdout!r} "
                f"stderr={after.stderr!r}")
        if "Command execution failed" in (after.stdout + after.stderr):
            failures.append(
                "the guest answered an ordinary command with `Command "
                "execution failed`, which is B-25's signature exactly")
        listing = run_ssh(key, port, "ls /", per_command)
        if listing.returncode != 0 or "state" not in listing.stdout:
            failures.append(
                f"after {CONNECTIONS} connections `ls /` did not answer: "
                f"rc={listing.returncode} {listing.stdout!r}")
    finally:
        stop_process(qemu)
        handle.close()

    whole_log = log_path.read_text(errors="replace")
    # Only what happened after sshd came up.
    #
    # The kernel's own self-test deliberately fills the session table at boot
    # to prove the eviction backstop works, and it logs the same line this
    # gate looks for. Reading the whole console would fail every run on the
    # evidence that the backstop exists.
    ready_at = whole_log.find(READY_MARKER)
    if ready_at < 0:
        raise RuntimeError("the console never reported sshd ready")
    log = whole_log[ready_at:]

    # Were these really distinct sessions? The session id is the socket
    # handle. If the stack recycled handles, the whole exercise would be one
    # session run eighty times, and it would pass for a reason that has
    # nothing to do with the defect.
    accepted = distinct_accepted_sockets(log)
    checks["distinct_accepted_sockets"] = len(accepted)
    if len(accepted) <= SESSION_SLOTS:
        failures.append(
            f"only {len(accepted)} distinct socket handles were accepted, "
            f"which is not more than the {SESSION_SLOTS} session slots -- so "
            f"the guest was never asked to hold more sessions than it has, "
            f"and this run proves nothing about exhaustion")

    # The assertion that pins the fix rather than the symptom. The kernel now
    # evicts rather than refusing, so a leaking sshd would still answer
    # commands; what it cannot do is fill the table without saying so.
    full = [line for line in log.splitlines()
            if "session table full" in line]
    checks["session_table_full_lines"] = len(full)
    if full:
        failures.append(
            f"the kernel's session table filled {len(full)} time(s) during "
            f"{CONNECTIONS} connections, so sshd is not closing the sessions "
            f"it opens: {full[0].strip()!r}")

    # And the backstop itself is present, so a future leak degrades instead
    # of bricking the guest. A gate that only checked for absence would pass
    # on a kernel where the eviction path had been deleted.
    if "evicts its oldest entry rather than refusing" not in whole_log:
        failures.append(
            "the kernel did not report the full-table eviction self-test, so "
            "nothing proves a table that does fill would recover")

    report = {
        "schema": "xaios.ssh.session-exhaustion.v1",
        "status": "pass" if not failures else "fail",
        "architecture": ARCH,
        "checks": checks,
        "failures": failures,
        "guest_log": str(log_path),
    }
    report_path = BUILD / f"qemu-ssh-session-exhaustion{SUFFIX}.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    if failures:
        for failure in failures:
            print(f"qemu-ssh-session-exhaustion-gate: FAIL {failure}")
        print(f"qemu-ssh-session-exhaustion-gate: report={report_path}")
        return 1
    print(f"qemu-ssh-session-exhaustion-gate: {CONNECTIONS} connections whose "
          f"command the kernel refused ({checks['refused_command']!r}), "
          f"{checks['distinct_accepted_sockets']} distinct sessions, table "
          f"never filled, guest still answering; report={report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
