#!/usr/bin/env python3
"""Fusion under sustained storage and network load, rather than repeated boots.

F-04's remaining item: "long-duration storage and network load, which is a
different shape of run from repeat boot." `vmware-fusion-boot-soak` boots the
guest forty times and shuts it down cleanly each time; every one of those is a
fresh machine, so nothing it does can accumulate. The failures this is for are
the ones that need a machine to stay up: a handle that is not returned, a
buffer that grows, a filesystem that fragments, a socket table that fills.

So this boots once and keeps the machine working.

What it asserts, and why each is separate:

  * The guest answers every round. A machine that stops answering half way
    through is the plainest failure and needs no interpretation.
  * Every file put comes back byte-identical. Storage under load is worth
    nothing if the bytes change, and a round trip is the only way to know.
  * Free memory does not trend downwards across the run. This is the whole
    reason for a long run rather than a long list of short ones: a leak of a
    page per operation is invisible in a boot and obvious in a thousand
    operations. It is a trend test, not a threshold -- the figure moves around
    as caches fill, so a single low reading proves nothing and a steady
    decline over the whole run proves a great deal.
  * The console carries no fault marker at the end, including rescue mode,
    which a guest can enter while still answering SSH.

What it deliberately does not claim: any of this as a throughput or latency
figure. The bytes moved and the seconds taken are printed because a run that
reports nothing is hard to judge, but this is one laptop running one
hypervisor, and docs/BENCHMARK-CONTRACT.md is where performance claims live.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import re
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location(
    "vmware_fusion_smoke", Path(__file__).with_name("vmware-fusion-smoke.py"))
smoke = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(smoke)

BUILD = ROOT / "build"
REPORT = BUILD / "vmware-fusion" / "fusion-load-soak.json"
WORK = BUILD / "vmware-fusion" / "load-soak"

# Ten minutes by default: long enough for a per-operation leak to show as a
# trend, short enough to sit inside a gate run. XAIOS_FUSION_LOAD_SECONDS
# raises it for a real soak.
DURATION_S = int(os.environ.get("XAIOS_FUSION_LOAD_SECONDS", "600"))
# 256 KiB per round: bigger than the filesystem's staging buffer, so each
# transfer crosses more than one block and exercises the multi-sector path
# rather than the fast case.
PAYLOAD_BYTES = int(os.environ.get("XAIOS_FUSION_LOAD_PAYLOAD", str(256 * 1024)))


def free_pages(console: str) -> int | None:
    """The guest's own account of free memory, from its last telemetry line."""
    marker = "pmm_free="
    last = None
    for line in console.splitlines():
        index = line.find(marker)
        if index < 0:
            continue
        digits = ""
        for character in line[index + len(marker):]:
            if not character.isdigit():
                break
            digits += character
        if digits:
            last = int(digits)
    return last


# What the guest says about a session, as opposed to what the client concluded.
#
# B-28 is "an SSH session is refused once in several hundred under sustained
# load", and its whole difficulty is that the only evidence so far is the
# client's exit code: `sftp exited 255 ('Connection closed')` on round 61 of
# 586. That says a connection ended. It does not say whether the guest refused
# it, accepted it and dropped it, never saw it, or closed it while it was still
# being set up -- and those are four different defects. Closing the row needs
# the guest's own account of the round that failed.
#
# These are the prefixes that carry that account. `remote-login:` is the one
# the row names, because that is the subsystem that hands a session a shell and
# whose table filling was B-25. The others are here because a refusal that
# never reaches remote-login would leave it silent: sshd's audit lines say what
# the daemon did with the connection, `user: rejected` says a syscall was
# denied, and the socket syscall traces say whether the listener accepted
# anything at all. A marker set that looked only for the expected line would
# find nothing and prove nothing in every case where the cause is elsewhere.
# The console session, and whatever the last probe left in flight.
SESSION_TALLY_ALLOWANCE = 4

SESSION_MARKERS = (
    "remote-login:",
    "sshd:",
    "user: rejected",
    "syscall: net_accept",
    "syscall: net_listen",
    "syscall: net_close",
    "network: listener",
)


def sshd_idle_timeout_ns() -> int:
    """The reclaim this soak has to outwait, read from the source.

    Not written down here. A gate carrying its own copy of a constant passes
    after someone changes the real one -- the same reason the connection-rate
    gate reads SSHD_CONNECTION_RATE_LIMIT rather than repeating 120.
    """
    header = ROOT / "userspace" / "sshd" / "sshd.h"
    found = re.search(r"#define\s+SSHD_TIMEOUT_IDLE\s+UINT64_C\((\d+)\)",
                      header.read_text(encoding="utf-8"))
    if not found:
        raise SystemExit(
            f"vmware-fusion-load-soak: SSHD_TIMEOUT_IDLE not found in "
            f"{header}; the tally cannot outwait a reclaim it cannot read")
    return int(found.group(1))


def session_lines(text: str) -> list[str]:
    """The session-relevant console lines in one slice of console output."""
    return [line.rstrip()
            for line in text.splitlines()
            if any(marker in line for marker in SESSION_MARKERS)]


def console_slice(console: str, cursor: int) -> tuple[str, int, bool]:
    """The console produced since `cursor`, and where the cursor now is.

    Correlation is by position in the console rather than by timestamp, and
    that is a deliberate substitution for what B-28's close condition asks
    for. Neither the kernel log nor sshd's audit log carries a timestamp --
    klog prints a subsystem prefix and sshd prints `[INFO]`/`[WARN]` -- so
    there is nothing to match a host clock against. Position gives what the
    timestamp was wanted for, and gives it exactly: the console is written in
    order, so everything between the offset before a round and the offset
    after it was printed during that round, with no clock skew between two
    machines to reason about.

    The third return value says the console got shorter, which means the file
    was rotated or the guest restarted underneath us. The cursor is then
    meaningless and the slice would silently be wrong, so the caller records
    that rather than attributing stale text to a round.
    """
    if len(console) < cursor:
        return console, len(console), True
    return console[cursor:], len(console), False


def round_trip(address: str, index: int, payload: bytes) -> dict[str, object]:
    """One file out and back, verified byte for byte."""
    WORK.mkdir(parents=True, exist_ok=True)
    source = WORK / f"upload-{index % 4}.bin"
    returned = WORK / f"download-{index % 4}.bin"
    source.write_bytes(payload)
    returned.unlink(missing_ok=True)
    remote = f"/state/load-soak-{index % 4}.bin"
    batch = f"put {source} {remote}\nget {remote} {returned}\nrm {remote}\n"
    started = time.monotonic()
    result = subprocess.run(
        ["sftp", "-F", "/dev/null", "-i", str(smoke.TEST_KEY),
         "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
         "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
         "-o", "LogLevel=ERROR", "-b", "-", f"admin@{address}"],
        input=batch, cwd=ROOT, text=True, capture_output=True, timeout=180,
        check=False)
    identical = (returned.is_file() and returned.read_bytes() == payload)
    return {"round": index,
            "exit_code": result.returncode,
            "identical": identical,
            "seconds": round(time.monotonic() - started, 2),
            "stderr": result.stderr.strip()[:200]}


def main() -> int:
    # The correlation checks run everywhere, including on the machines that
    # skip the soak itself.
    #
    # A skip that returns zero having executed nothing is how a harness rots:
    # the B-28 correlation would otherwise be exercised only on a macOS host
    # with a free Fusion licence, which is the rarest machine in this project
    # and the one least likely to run first. These checks need neither, so
    # there is no reason for a Linux CI runner to learn nothing from this
    # file. It also fails fast on a machine that can run the soak -- ten
    # minutes of load is a poor way to discover that the reporting is wrong.
    correlation_status = self_test()
    if correlation_status != 0:
        return correlation_status
    if sys.platform != "darwin":
        print("vmware-fusion-load-soak: needs macOS with VMware Fusion; the "
              "correlation self-test above is what this machine can check")
        return 0
    if not smoke.VMRUN.is_file():
        print(f"vmware-fusion-load-soak: no vmrun at {smoke.VMRUN}; skipping "
              f"the soak, correlation self-test above still ran")
        return 0

    smoke.build_guest()
    smoke.stop_hard()
    address, _ = smoke.start_vm(0)

    payload = bytes((index * 31 + 7) & 0xFF for index in range(PAYLOAD_BYTES))
    rounds: list[dict[str, object]] = []
    free_samples: list[int] = []
    failures: list[str] = []
    # Each entry is one round's own console: what the guest printed between the
    # start of that round and the start of the next. Kept for the round that
    # failed and the rounds either side of it, and discarded otherwise -- a
    # ten-minute run produces hundreds of these and the only interesting ones
    # are next to a failure.
    correlation: list[dict[str, object]] = []
    previous_record: dict[str, object] | None = None
    capture_next = 0
    console_cursor = len(smoke.serial_text())
    deadline = time.monotonic() + DURATION_S
    index = 0
    try:
        while time.monotonic() < deadline:
            index += 1
            round_started = time.time()
            entry = round_trip(address, index, payload)
            rounds.append(entry)
            round_failure = None
            if entry["exit_code"] != 0:
                round_failure = (
                    f"round {index}: sftp exited {entry['exit_code']} "
                    f"({entry['stderr']!r})")
            elif not entry["identical"]:
                round_failure = (
                    f"round {index}: the file came back different from the "
                    f"one sent")
            if round_failure is not None:
                failures.append(round_failure)
            # The guest's own view, asked over the network it is being loaded
            # through -- a machine that cannot describe itself under load is a
            # different failure from one that stops answering.
            #
            # This probe cannot itself witness B-28: smoke.ssh retries a failed
            # command for up to a minute, so one refused session here is
            # swallowed and reported as success. That is right for what it
            # asserts -- whether the machine is still there -- and it is also
            # why the sftp round above is the only thing in this soak that can
            # see the defect at all.
            status = smoke.ssh(address, "recovery status")
            console = smoke.serial_text()
            printed, console_cursor, console_reset = console_slice(
                console, console_cursor)
            record = {"round": index,
                      "host_time_unix": round_started,
                      "sftp_exit_code": entry["exit_code"],
                      "console_reset": console_reset,
                      "console_bytes": len(printed),
                      "guest_lines": session_lines(printed)}
            # The round before a failure matters as much as the failing one.
            # The informal account of B-28 has always been "it refuses right
            # after a session closes", so what the guest printed while the
            # previous session was ending is evidence rather than context.
            if round_failure is not None:
                if previous_record is not None:
                    correlation.append(previous_record)
                correlation.append(record)
                capture_next = 1
            elif capture_next > 0:
                correlation.append(record)
                capture_next -= 1
            previous_record = record
            if "rescue=" not in status:
                failures.append(
                    f"round {index}: the guest stopped answering commands: "
                    f"{status.strip()[:120]!r}")
                break
            if "rescue=1" in status:
                failures.append(
                    f"round {index}: the guest entered rescue mode under load")
                break
            sample = free_pages(console)
            if sample is not None:
                free_samples.append(sample)
    finally:
        console = smoke.serial_text()
        kept = BUILD / "vmware-fusion" / "fusion-load-soak.log"
        kept.write_text(console, encoding="utf-8")
        smoke.stop_hard()

    fatal = [marker for marker in smoke.FATAL_MARKERS if marker in console]
    if fatal:
        failures.append(f"the console carries fault markers {fatal}")

    # B-38: accepted against closed, over the whole run rather than a slice.
    #
    # This soak kept the guest's console for the failing round and the rounds
    # either side of it -- about 1.4 seconds. A session the server abandons is
    # reclaimed by SSHD_TIMEOUT_IDLE, which is 300 seconds, some four hundred
    # rounds later, so "no net_close in that round or the next" was read as an
    # orphaned socket when it is exactly what an idle reclaim looks like
    # through a window two orders of magnitude too small. The tally does not
    # care about windows.
    #
    # The wait is what makes it mean anything. Idle out the last sessions with
    # the guest up and nothing driving it, and every accept that still has no
    # close is a socket the server genuinely never reclaimed.
    idle_ns = sshd_idle_timeout_ns()
    settle = idle_ns / 1_000_000_000.0 + 30.0
    print(f"vmware-fusion-load-soak: idling {settle:.0f}s so the reclaim can "
          f"run before accepts and closes are tallied", flush=True)
    time.sleep(settle)
    console = smoke.serial_text()
    accepted = console.count("syscall: net_accept")
    closed = console.count("syscall: net_close")
    outstanding = accepted - closed
    session_tally = {
        "accepted": accepted,
        "closed": closed,
        "outstanding": outstanding,
        "idle_timeout_s": round(idle_ns / 1_000_000_000.0),
        "settled_for_s": round(settle),
    }
    # The console session and the probe that ran last are legitimately open.
    if outstanding > SESSION_TALLY_ALLOWANCE:
        failures.append(
            f"{outstanding} sessions were accepted and never closed, after "
            f"{round(settle)}s of idle -- longer than the "
            f"{round(idle_ns / 1_000_000_000.0)}s reclaim. {accepted} accepted "
            f"against {closed} closed. A socket still outstanding here was "
            f"not reclaimed by any timeout, which is the orphan B-38 was "
            f"originally read as")

    # A trend, not a threshold. Compare the first quarter of the samples with
    # the last: caches fill early and the figure wanders, so one low reading
    # says nothing, while a steady decline across a ten-minute run is a leak.
    trend: dict[str, object] = {"samples": len(free_samples)}
    if len(free_samples) >= 8:
        quarter = len(free_samples) // 4
        early = sum(free_samples[:quarter]) / quarter
        late = sum(free_samples[-quarter:]) / quarter
        trend.update({"early_mean_pages": round(early),
                      "late_mean_pages": round(late),
                      "delta_pages": round(late - early)})
        # 2% of the early mean: enough to ignore ordinary movement, small
        # enough to catch a page-per-operation leak over hundreds of rounds.
        if late < early * 0.98:
            failures.append(
                f"free memory declined across the run: {round(early)} pages "
                f"early against {round(late)} late. Over {index} rounds that "
                f"is a leak rather than a cache filling")

    report = {
        "schema": "xaios.vmware-fusion.load_soak.v1",
        "status": "pass" if not failures else "fail",
        "fusion_version": smoke.fusion_version(),
        "revision": smoke.git_revision(),
        "duration_requested_s": DURATION_S,
        "payload_bytes": PAYLOAD_BYTES,
        "rounds": len(rounds),
        "bytes_moved": len(rounds) * PAYLOAD_BYTES * 2,
        "free_page_trend": trend,
        "session_tally": session_tally,
        # B-28's close condition: the guest's own console for the failing
        # round and the rounds either side of it, so a refusal can be read as
        # what the machine did rather than as what the client concluded. Empty
        # on a clean run, and empty is also a real answer on a failing one --
        # if the guest printed nothing at all while a session was refused,
        # that narrows the defect to a path with no logging in it, and the row
        # should say so rather than the run being repeated until something
        # appears.
        "session_correlation": correlation,
        "failures": failures,
        "not_claimed": [
            "throughput or latency: one laptop, one hypervisor, and "
            "docs/BENCHMARK-CONTRACT.md is where performance claims live",
        ],
        "round_detail": rounds[-20:],
    }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                      encoding="utf-8")
    if failures:
        for failure in failures:
            print(f"vmware-fusion-load-soak: FAIL {failure}")
        for record in correlation:
            lines = record["guest_lines"]
            print(f"vmware-fusion-load-soak: guest console during round "
                  f"{record['round']} (sftp exit {record['sftp_exit_code']}, "
                  f"{record['console_bytes']} bytes, "
                  f"{len(lines)} session lines)"
                  + ("" if lines else " -- the guest printed nothing about a "
                                      "session during this round"))
            for line in lines:
                print(f"    {line}")
        print(f"vmware-fusion-load-soak: report={REPORT}")
        return 1
    print(f"vmware-fusion-load-soak: {len(rounds)} verified round trips of "
          f"{PAYLOAD_BYTES} bytes over {DURATION_S}s on one boot, every file "
          f"identical, the guest answering throughout, free memory "
          f"{trend.get('delta_pages', 'n/a')} pages against its early mean; "
          f"report={REPORT}")
    return 0


def self_test() -> int:
    """Check the correlation itself, on a machine with no hypervisor.

    The soak needs macOS and a Fusion licence, so on every other machine --
    including the one this was written on, where another process owns Fusion --
    the correlation added for B-28 would ship having never executed. That is
    the shape of bug this repository keeps finding in its own harnesses: a
    check that looks right, runs nowhere, and reports the bench's damage as
    the guest's. The slicing and the filtering are pure functions of text, so
    they can be run against a console that is written here rather than booted,
    and that is what this does.

    Every assertion has its negative control, because "the failing round's
    lines were found" is worth nothing on its own -- a function returning the
    whole console would satisfy it. Each case therefore also asserts what must
    NOT be attributed to the round.
    """
    failures: list[str] = []

    def check(name: str, condition: bool) -> None:
        if condition:
            print(f"    ok   {name}")
        else:
            failures.append(name)
            print(f"    FAIL {name}")

    round_60 = ("remote-login: ssh-compatible session opened user=admin\n"
                "xaibootfs: write path=/state/load-soak-0.bin size=262144\n"
                "remote-login: session complete authenticated=1 commands=1 "
                "bytes=262144\n")
    round_61 = ("sshd: connection capacity rejection observed\n"
                "syscall: net_close sockfd=9\n")
    round_62 = ("remote-login: ssh-compatible session opened user=admin\n")

    console = round_60
    cursor = 0
    printed_60, cursor, reset_60 = console_slice(console, cursor)
    console += round_61
    printed_61, cursor, reset_61 = console_slice(console, cursor)
    console += round_62
    printed_62, cursor, _ = console_slice(console, cursor)

    lines_61 = session_lines(printed_61)
    check("the failing round's own lines are attributed to it",
          lines_61 == ["sshd: connection capacity rejection observed",
                       "syscall: net_close sockfd=9"])
    # The negative control for that: the round before ended a session, and if
    # its lines leaked into round 61 the correlation would invent exactly the
    # story B-28's informal account already assumes -- a refusal next to a
    # close -- out of nothing but a bad offset.
    check("the previous round's lines are not attributed to the failing round",
          not any("session complete" in line for line in lines_61))
    check("the next round's lines are not attributed to the failing round",
          not any("session opened" in line for line in lines_61))
    check("the previous round is still available for its own record",
          session_lines(printed_60)[-1].startswith(
              "remote-login: session complete"))
    check("the round after the failure is captured separately",
          session_lines(printed_62) == [
              "remote-login: ssh-compatible session opened user=admin"])
    # Not every console line is evidence about a session, and a filter that
    # kept them all would bury the two lines that matter in a soak's worth of
    # filesystem chatter.
    check("unrelated console output is filtered out",
          not any("xaibootfs" in line for line in session_lines(printed_60)))
    check("a quiet round yields an empty list rather than a stray line",
          session_lines("pmm_free=487807\nkernel: idle\n") == [])
    # A console that shrank means the file rotated or the guest restarted; the
    # cursor no longer refers to the same text and the slice must not be
    # presented as one round's output.
    _, shrunk_cursor, reset_shrunk = console_slice("short", 10_000)
    check("a shorter console is reported as a reset", reset_shrunk)
    check("a growing console is not reported as a reset",
          not reset_60 and not reset_61)
    check("the cursor follows a reset rather than staying ahead of the file",
          shrunk_cursor == len("short"))

    if failures:
        print(f"vmware-fusion-load-soak: self-test FAILED {len(failures)} of "
              f"the correlation checks")
        return 1
    print("vmware-fusion-load-soak: self-test passed; the B-28 correlation "
          "attributes each console line to the round that produced it. This "
          "asserts the correlation code, not the guest: only a Fusion run can "
          "say what the machine prints when a session is refused.")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv[1:]:
        raise SystemExit(self_test())
    raise SystemExit(main())
