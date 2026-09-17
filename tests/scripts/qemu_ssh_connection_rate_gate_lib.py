#!/usr/bin/env python3
"""Harness for qemu-ssh-connection-rate-gate.py (B-28).

The gate's own docstring states the claim it tests. This module holds the
machinery that makes the measurement: the limiter constants read out of
userspace/sshd/sshd.h, each guest-reported gap placed on the host's clock, the
bare-TCP probe that exercises the limiter on accept, the guest build step with
the key it authenticates with, the real SSH session, and the per-case boot that
produces one result.

It is imported by the gate and is not itself a program: `python3
tests/scripts/qemu-ssh-connection-rate-gate.py` remains the only entry point.
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
sys.path.insert(0, str(ROOT / "tests" / "scripts"))
from qemu_gate_lib import Console, qemu_boot_environment, qemu_runner, smoke_timeout

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


# A gap the guest reports after the fact: the number is how long it lasted, and
# the line arrives once it is over.
GAP_PATTERNS = (
    re.compile(r"network: stack was not polled for ms=(\d+)"),
    re.compile(r"sshd: service loop stalled ms=(\d+) phase=(\w+)"),
)


def gaps_on_the_host_clock(console: Console) -> list[dict[str, object]]:
    """Each reported gap placed on the host's clock.

    The line is printed when the gap ends, so its arrival time is the end and
    the start is that minus the duration the guest measured. The arrival is
    known only to the chunk that carried it, which is close enough: chunks
    arrive every few hundred milliseconds and the gaps in question are tens of
    seconds.
    """
    # A line can be split across two chunks, so each chunk is searched together
    # with a little of the text before it. That re-finds the previous chunk's
    # matches, so each one is keyed by where it sits in the whole console: the
    # same match found twice has the same offset, and the first arrival is the
    # one that carried it.
    found: dict[int, dict[str, object]] = {}
    seen = ""
    for arrived, chunk in console.arrivals():
        region_start = max(0, len(seen) - 200)
        seen += chunk
        for pattern in GAP_PATTERNS:
            for match in pattern.finditer(seen[region_start:]):
                offset = region_start + match.start()
                if offset in found:
                    continue
                milliseconds = int(match.group(1))
                found[offset] = {
                    "line": match.group(0),
                    "ms": milliseconds,
                    "ended_at": round(arrived, 3),
                    "started_at": round(arrived - milliseconds / 1000.0, 3),
                }
    return sorted(found.values(), key=lambda g: g["started_at"])


# Every open this gate makes, on the same clock the gaps are placed on.
OPENS: list[dict[str, object]] = []


def probe(port: int, timeout: float = 4.0) -> str:
    """One TCP connection: served (banner), refused (closed), or unreachable."""
    started = time.monotonic()
    outcome = _probe(port, timeout)
    OPENS.append({"outcome": outcome, "started_at": round(started, 3),
                  "ended_at": round(time.monotonic(), 3)})
    return outcome


def _probe(port: int, timeout: float = 4.0) -> str:
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


def wait_for_ready(process, console: "Console", deadline: float) -> bool:
    """Wait for sshd to announce itself, while the console keeps being read."""
    while time.time() < deadline:
        if READY in console.text():
            return True
        if process.poll() is not None:
            return READY in console.text()
        time.sleep(0.2)
    return False


def drain(process, console: "Console", seconds: float) -> None:
    """Let the guest finish saying why. The reader thread is already reading."""
    end = time.time() + seconds
    while time.time() < end:
        if process.poll() is not None:
            return
        time.sleep(0.2)


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


def order_of(opens: list[dict[str, object]],
             gaps: list[dict[str, object]]) -> dict[str, object]:
    """Which came first: the host's failed opens, or the guest's outage.

    B-50 could not choose between two readings. Either the guest stopped
    polling and the host's opens failed because of it, or the opens failed
    first -- each costing the host a 4 s timeout -- and the guest's gap is the
    consequence rather than the cause. Both fit the same evidence, and they
    call for entirely different fixes.

    The answer is an ordering, so this reports the ordering and nothing more.
    It draws no conclusion: "the first failed open was inside the gap" and
    "the gap began after every open had failed" are different findings, and
    naming which one happened is the whole of what this row asked for.
    """
    failed = [o for o in opens
              if o["outcome"] in ("unreachable", "silent", "refused")]
    if not gaps:
        return {"verdict": "no gap reported", "failed_opens": len(failed)}
    if not failed:
        return {"verdict": "gap reported with no failed open",
                "gaps": len(gaps)}
    first_failure = min(float(o["started_at"]) for o in failed)
    widest = max(gaps, key=lambda g: float(g["ms"]))
    start, end = float(widest["started_at"]), float(widest["ended_at"])
    if first_failure < start:
        verdict = ("the first failed open preceded the widest gap by "
                   f"{round(start - first_failure, 2)}s, so the gap follows "
                   f"the failures")
    elif first_failure > end:
        verdict = ("every failed open came after the widest gap ended, by "
                   f"{round(first_failure - end, 2)}s")
    else:
        verdict = ("the first failed open fell inside the widest gap, "
                   f"{round(first_failure - start, 2)}s after it began, so "
                   f"the outage was already under way")
    return {"verdict": verdict,
            "first_failed_open_at": round(first_failure, 3),
            "widest_gap": widest, "failed_opens": len(failed),
            "gaps": len(gaps)}


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
    OPENS.clear()
    reader = Console(process)
    try:
        ready = wait_for_ready(
            process, reader, time.time() + smoke_timeout(ARCH, 240))
        if not ready:
            return {"case": name, "booted": False, "outcomes": [],
                    "preloaded": [], "console": reader.text()}
        started = time.monotonic()
        for _ in range(preload):
            preloaded.append(probe(port))
        for _ in range(attempts):
            outcomes.append(authenticate(port) if authenticated else probe(port))
        elapsed = time.monotonic() - started
        # The guest prints from its own loop; give it a moment to say why.
        drain(process, reader, 6.0)
        gaps = gaps_on_the_host_clock(reader)
        opens = list(OPENS)
    finally:
        reader.close()
        if process.poll() is None:
            try:
                os.killpg(process.pid, 15)
                process.wait(timeout=10)
            except Exception:  # noqa: BLE001 - the boot is over either way
                try:
                    os.killpg(process.pid, 9)
                except ProcessLookupError:
                    pass
    console = reader.text()
    log = BUILD / f"qemu-ssh-connection-rate-{name}.log"
    log.write_text(console, encoding="utf-8")
    return {"case": name, "booted": True, "outcomes": outcomes,
            "preloaded_served": sum(1 for o in preloaded if o == "banner"),
            "preloaded": len(preloaded),
            "seconds": round(elapsed, 2), "console_path": str(log.relative_to(ROOT)),
            "opens": opens, "gaps": gaps,
            "ordering": order_of(opens, gaps),
            "console": console}
