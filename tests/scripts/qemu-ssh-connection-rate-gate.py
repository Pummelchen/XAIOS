#!/usr/bin/env python3
"""B-28: what refuses an SSH session under sustained load, and does it say so.

B-28 was one SFTP session refused in 586 on a Fusion soak -- `sftp exited 255
('Connection closed')` at round 61 -- with the guest answering normally either
side of it and nothing on its console. Two years of "sshd occasionally refuses
right after a session closes" had no mechanism behind it.

There is a mechanism, and it is arithmetic. sshd rate-limits accepts per client
address: `SSHD_CONNECTION_RATE_LIMIT` connections per `SSHD_CONNECTION_RATE_WINDOW`.
Each soak round opens *two* connections -- the SFTP transfer and the
`recovery status` probe that follows it -- so round 61's transfer is the 121st
connection from that address, and the limit is 120. The 121st is refused before
a byte of SSH is spoken, which is exactly what "Connection closed" with no
banner looks like from the far end.

This gate puts that to the test, and it does not need Fusion to do it. The
limiter runs on accept, before any protocol work, so a bare TCP connection
exercises it as well as a full session does and far more quickly -- which
matters, because 121 connections have to fit inside the window or the counter
resets and nothing is proven.

What is asserted, and why each part is here:

  * Connections up to the limit are served -- each one is answered with an
    SSH version banner. Without this the gate would pass against a guest that
    refused everything.
  * The connection past the limit is closed with no banner. That is the
    client-visible shape of B-28.
  * The guest names the reason on its console: `reason=rate-limit`. The
    original refusal was invisible because the rate-limit path wrote only to
    the audit file on the durable volume, which nothing reads. A refusal that
    cannot be attributed is indistinguishable from a defect, so the fix is as
    much this line as it is the counter behind it.
  * A short run well under the limit produces no refusal and no marker. This
    is the control on the whole gate: it is what says the refusal above was
    caused by crossing the limit rather than by the guest disliking the load.
  * A peer that authenticates is not throttled. The window bounds a flood
    from a peer that has proved nothing; a peer holding a credential this
    machine accepts has proved something, and counting it breaks the workload
    the machine exists for. sshd credits an authenticated connection back to
    the window, and this case is arranged so that it can fail: the window is
    first loaded to one short of the limit with bare connections, and then two
    authenticated sessions are opened. Without the credit the second is
    refused. With it, both are served.

The loading step is why that case can fail at all -- authenticated sessions on
their own take longer than the window and would pass against any
implementation, credit or no credit. It is also why the case is kept as small
as it can be: everything in it has to fit inside one window, and a real SSH
session against a TCG guest is not cheap. The gate checks that it did fit and
declines to conclude anything if it did not, rather than reporting a pass it
has not earned.
"""

from __future__ import annotations

import json
import os
import re
import select
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
sys.path.insert(0, str(ROOT / "tests" / "scripts"))
from qemu_gate_lib import qemu_boot_environment, qemu_runner, smoke_timeout

REPORT = BUILD / "qemu-ssh-connection-rate-gate.json"
ARCH = os.environ.get("XAIOS_SSH_RATE_ARCH", "aarch64")
READY = "SSH server: up and running (tcp/22)"
HOST_PORT = int(os.environ.get("XAIOS_SSH_RATE_PORT", "2452"))

# Read from the source rather than repeated here: a gate carrying its own copy
# of a constant passes after someone changes the real one.
HEADER = ROOT / "userspace" / "sshd" / "sshd.h"


def sshd_constant(name: str) -> int:
    text = HEADER.read_text(encoding="utf-8")
    found = re.search(rf"#define\s+{name}\s+(?:UINT64_C\()?(\d+)", text)
    if not found:
        raise SystemExit(f"qemu-ssh-connection-rate-gate: {name} not found in "
                         f"{HEADER.relative_to(ROOT)}; the gate cannot check a "
                         f"limit it cannot read")
    return int(found.group(1))


LIMIT = sshd_constant("SSHD_CONNECTION_RATE_LIMIT")
WINDOW_NS = sshd_constant("SSHD_CONNECTION_RATE_WINDOW")
WINDOW_SECONDS = WINDOW_NS / 1_000_000_000.0


def probe(port: int, timeout: float = 4.0) -> str:
    """One TCP connection: served (banner), refused (closed), or unreachable."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                data = s.recv(64)
            except socket.timeout:
                # Accepted and then neither served nor closed. Distinct from
                # both other outcomes and worth reporting under its own name.
                return "silent"
            if not data:
                return "closed"
            return "banner" if data.startswith(b"SSH-") else "other"
    except (ConnectionRefusedError, ConnectionResetError):
        return "refused"
    except OSError:
        return "unreachable"


def wait_for_ready(process, deadline: float) -> tuple[bool, list[str]]:
    output: list[str] = []
    descriptor = process.stdout.fileno()
    while time.time() < deadline:
        ready, _, _ = select.select([descriptor], [], [], 0.2)
        if ready:
            chunk = os.read(descriptor, 8192).decode("utf-8", errors="replace")
            if not chunk:
                break
            output.append(chunk)
            if READY in "".join(output):
                return True, output
        elif process.poll() is not None:
            break
    return False, output


def drain(process, output: list[str], seconds: float) -> None:
    """Collect whatever the guest printed, without blocking on a quiet console."""
    descriptor = process.stdout.fileno()
    end = time.time() + seconds
    while time.time() < end:
        ready, _, _ = select.select([descriptor], [], [], 0.2)
        if not ready:
            if process.poll() is not None:
                return
            continue
        chunk = os.read(descriptor, 65536).decode("utf-8", errors="replace")
        if not chunk:
            return
        output.append(chunk)


KEY = BUILD / "ssh-connection-rate-key"
KEY_PUBLIC = KEY.with_suffix(".pub")


def build_guest() -> None:
    """Build the image this gate boots, with a key it can authenticate with.

    Both halves matter. The key is what makes the authenticated case possible
    at all -- paramiko cannot negotiate with this sshd, and the real OpenSSH
    client needs a credential the image accepts. Building here rather than
    leaning on whatever is in build/ is the other half: a gate that boots an
    artefact it did not build tests whatever ran last, which is the defect
    recorded as B-31 and is not one to repeat in a new gate.
    """
    if not (KEY.is_file() and KEY_PUBLIC.is_file()):
        KEY.unlink(missing_ok=True)
        KEY_PUBLIC.unlink(missing_ok=True)
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                        "-f", str(KEY)], check=True, cwd=ROOT)
        KEY.chmod(0o600)
    environment = os.environ.copy()
    environment.update({"XAIOS_BOOT_TEST_APPS": "1",
                        "XAIOS_BOOT_VERBOSE": "1",
                        "XAIOS_AUTHORIZED_KEYS_FILE": str(KEY_PUBLIC)})
    subprocess.run(["./scripts/build-image.sh"], check=True, cwd=ROOT,
                   env=environment, stdout=subprocess.DEVNULL)


def authenticate(port: int, timeout: float = 40.0) -> str:
    """One real SSH session: connect, authenticate, run a command, close."""
    try:
        finished = subprocess.run(
            ["ssh", "-F", "/dev/null", "-i", str(KEY),
             "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
             "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
             "-p", str(port), "admin@127.0.0.1", "recovery status"],
            capture_output=True, text=True, timeout=timeout, check=False,
            cwd=ROOT)
    except subprocess.TimeoutExpired:
        return "timeout"
    if finished.returncode == 0:
        return "authenticated"
    detail = finished.stderr.strip().splitlines()
    reason = detail[-1][:80] if detail else "no stderr"
    # An authentication failure is not a refusal on accept, and calling it one
    # would be the exact mistake this gate exists to stop: it would report a
    # broken credential as a rate limit. Kept as its own outcome so a run that
    # cannot log in says so instead of blaming the limiter.
    if "Permission denied" in reason or "Too many authentication" in reason:
        return f"auth-failed:{reason}"
    # 255 with no banner is what a refusal on accept looks like from here, and
    # is what B-28 reported.
    return f"refused:{finished.returncode}:{reason}"


def run_case(name: str, attempts: int, port: int, *, preload: int = 0,
             authenticated: bool = False) -> dict[str, object]:
    # Its own durable volume and its own state, created fresh.
    #
    # build/xaios-persistent.img is shared: every QEMU boot writes to it, and
    # the kernel deliberately keeps a persisted /etc/xaios_authorized_keys over
    # the one in the image. So a gate that baked a key into its image and then
    # booted the shared volume authenticated against whichever unrelated gate
    # wrote that file last, and got `Permission denied` for a key the image
    # plainly contained. It also inherits the lifecycle record, which is how a
    # boot lands in rescue mode for reasons that have nothing to do with it
    # (B-08).
    case_dir = BUILD / f"ssh-connection-rate-{name}"
    if case_dir.exists():
        shutil.rmtree(case_dir)
    case_dir.mkdir(parents=True)
    persistent = case_dir / "persistent.img"
    volume_env = os.environ.copy()
    volume_env["XAIOS_PERSISTENT_IMAGE"] = str(persistent)
    subprocess.run(["./scripts/create-persistent-image.sh"], check=True,
                   cwd=ROOT, env=volume_env, stdout=subprocess.DEVNULL)
    env = qemu_boot_environment(ARCH, os.environ.copy(),
                                persistent=persistent,
                                state_dir=case_dir / "state",
                                hostfwd_port=str(port), serial_to_stdout=True)
    process = subprocess.Popen(
        [qemu_runner(ARCH)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1, env=env, cwd=ROOT, start_new_session=True)
    outcomes: list[str] = []
    preloaded: list[str] = []
    elapsed = 0.0
    try:
        ready, output = wait_for_ready(
            process, time.time() + smoke_timeout(ARCH, 240))
        if not ready:
            return {"case": name, "booted": False, "outcomes": [],
                    "preloaded": [], "console": "".join(output)}
        started = time.monotonic()
        for _ in range(preload):
            preloaded.append(probe(port))
        for _ in range(attempts):
            outcomes.append(authenticate(port) if authenticated else probe(port))
        elapsed = time.monotonic() - started
        # The guest prints from its own loop; give it a moment to say why.
        drain(process, output, 6.0)
    finally:
        if process.poll() is None:
            try:
                os.killpg(process.pid, 15)
                process.wait(timeout=10)
            except Exception:  # noqa: BLE001 - the boot is over either way
                try:
                    os.killpg(process.pid, 9)
                except ProcessLookupError:
                    pass
    console = "".join(output)
    log = BUILD / f"qemu-ssh-connection-rate-{name}.log"
    log.write_text(console, encoding="utf-8")
    return {"case": name, "booted": True, "outcomes": outcomes,
            "preloaded_served": sum(1 for o in preloaded if o == "banner"),
            "preloaded": len(preloaded),
            "seconds": round(elapsed, 2), "console_path": str(log.relative_to(ROOT)),
            "console": console}


def main() -> int:
    BUILD.mkdir(parents=True, exist_ok=True)
    build_guest()
    failures: list[str] = []
    results: list[dict[str, object]] = []

    # Case one: cross the limit. One connection past it is the whole point, so
    # the count is derived rather than written down.
    over = run_case("over-limit", LIMIT + 1, HOST_PORT)
    # Case two: the control. Comfortably under the limit, same everything else.
    under = run_case("under-limit", max(4, LIMIT // 4), HOST_PORT + 1)
    # Case three: authentication credits the window back. The preload is what
    # makes this able to fail -- see the module docstring.
    # The smallest arrangement that can still fail, because a real SSH session
    # against a TCG guest costs tens of seconds and the whole case has to fit
    # inside the window. With the window one short of the limit, the first
    # session is served either way and the second is served only if the first
    # was credited back -- so two sessions is the minimum that distinguishes
    # the two implementations, and any more only risks running out of window.
    headroom = 1
    authed_sessions = 2
    authed = run_case("authenticated", authed_sessions, HOST_PORT + 2,
                      preload=LIMIT - headroom, authenticated=True)

    for case in (over, under, authed):
        entry = {k: v for k, v in case.items() if k != "console"}
        results.append(entry)
        if not case["booted"]:
            failures.append(f"the {case['case']} boot never reported "
                            f"{READY!r}, so nothing was tested")

    if over["booted"] and under["booted"] and authed["booted"]:
        outcomes = list(over["outcomes"])
        served = [i for i, o in enumerate(outcomes) if o == "banner"]
        refused = [i for i, o in enumerate(outcomes) if o in ("closed", "refused")]

        if float(over["seconds"]) >= WINDOW_SECONDS:
            failures.append(
                f"the {LIMIT + 1} connections took {over['seconds']}s, which is "
                f"not inside the {WINDOW_SECONDS:.0f}s window the limiter counts "
                f"over -- the counter reset part way and this run proves nothing")

        if len(served) < LIMIT:
            failures.append(
                f"only {len(served)} of the first {LIMIT} connections were "
                f"answered with an SSH banner; a guest refusing everything "
                f"would satisfy a check that only looked for a refusal")
        if not refused:
            failures.append(
                f"all {LIMIT + 1} connections were served, so the rate limit "
                f"at {LIMIT} did not fire and the B-28 mechanism is not what "
                f"this gate assumed")
        elif refused[0] != LIMIT:
            failures.append(
                f"the first refusal was connection {refused[0] + 1}, not "
                f"{LIMIT + 1}: the limit that fired is not the one in "
                f"SSHD_CONNECTION_RATE_LIMIT")

        if "reason=rate-limit" not in str(over["console"]):
            failures.append(
                "the guest refused a connection and its console did not say "
                "why. That silence is B-28's other half: a refusal nobody can "
                "attribute is indistinguishable from a defect")

        under_outcomes = list(under["outcomes"])
        if any(o != "banner" for o in under_outcomes):
            failures.append(
                f"the control run of {len(under_outcomes)} connections -- well "
                f"under the limit -- did not serve all of them: "
                f"{sorted(set(under_outcomes))}. Something other than the rate "
                f"limit is refusing connections, and the over-limit result "
                f"cannot be attributed to the limit")
        if "reason=rate-limit" in str(under["console"]):
            failures.append(
                "the control run stayed under the limit and the guest still "
                "reported a rate-limit refusal, so the marker does not mean "
                "what this gate reads it to mean")

        served_preload = int(authed["preloaded_served"])
        if served_preload != LIMIT - headroom:
            failures.append(
                f"the authenticated case meant to load the window to "
                f"{LIMIT - headroom} but only {served_preload} of its bare "
                f"connections were served, so the window was not where the "
                f"case needs it and the result proves nothing")
        elif float(authed["seconds"]) >= WINDOW_SECONDS:
            failures.append(
                f"the authenticated case took {authed['seconds']}s, past the "
                f"{WINDOW_SECONDS:.0f}s window, so its counter reset part way "
                f"and it would pass with or without the credit")
        else:
            refused_auth = [i for i, o in enumerate(authed["outcomes"])
                            if o != "authenticated"]
            first = refused_auth[0] if refused_auth else None
            if first is not None and str(
                    authed["outcomes"][first]).startswith(("timeout",
                                                           "refused:255:ssh: connect")):
                failures.append(
                    f"session {first + 1} timed out rather than being answered "
                    f"({authed['outcomes'][first]}). The guest was too slow to "
                    f"say yes or no, which is a loaded host rather than a "
                    f"result -- re-run this on a quiet machine")
            elif first is not None and str(
                    authed["outcomes"][first]).startswith("auth-failed"):
                failures.append(
                    f"session {first + 1} could not authenticate at all "
                    f"({authed['outcomes'][first]}), so this case tested the "
                    f"credential rather than the rate limit and says nothing "
                    f"about either")
            elif first is not None:
                failures.append(
                    f"with the window {headroom} short of the limit, "
                    f"authenticated session {first + 1} of "
                    f"{authed_sessions} was not served "
                    f"({authed['outcomes'][first]}). A peer holding a "
                    f"credential this machine accepts is being counted against "
                    f"a limit meant for peers that have proved nothing")

    report = {"schema": "xaios.qemu.ssh_connection_rate.v1",
              "status": "pass" if not failures else "fail",
              "architecture": ARCH,
              "limit": LIMIT,
              "window_seconds": WINDOW_SECONDS,
              "results": results,
              "failures": failures}
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                      encoding="utf-8")
    if failures:
        for failure in failures:
            print(f"qemu-ssh-connection-rate-gate: FAIL {failure}")
        print(f"qemu-ssh-connection-rate-gate: report={REPORT}")
        return 1
    print(f"qemu-ssh-connection-rate-gate: {authed_sessions} authenticated "
          f"sessions are all served with the window {headroom} short of the "
          f"limit, where session {headroom + 1} would be refused without the "
          f"credit; "
          f"{LIMIT} connections from one address "
          f"inside {WINDOW_SECONDS:.0f}s are served and the next is refused, "
          f"named on the console as reason=rate-limit; a control run of "
          f"{len(under['outcomes'])} is served with no refusal. This is the "
          f"mechanism behind B-28: a soak round opens two connections, so its "
          f"round {LIMIT // 2 + 1} carries connection {LIMIT + 1}. "
          f"report={REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
