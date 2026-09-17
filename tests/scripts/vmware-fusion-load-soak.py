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

from vmware_fusion_load_soak_lib import (ACCEPT_RE, CLOSE_RE,
                                         SESSION_MARKERS,
                                         SESSION_TALLY_ALLOWANCE,
                                         console_slice, free_pages,
                                         resolve_stranded_sockets,
                                         self_test, session_lines,
                                         sshd_idle_timeout_ns)

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
            "stderr": result.stderr.strip()[:200],
            # B-63: the summary above is what the report carries for the 1256
            # uneventful rounds. The whole of it is kept here, and retained
            # only for the rounds that matter -- the one round that failed is
            # the one whose detail was being cut off at 200 characters.
            "stderr_full": result.stderr.strip()}


def verbose_probe(address: str) -> dict[str, object]:
    """One deliberately talkative session, immediately after a failure.

    B-63 is one dropped SFTP session in 1257 on Fusion with the guest logging
    nothing unusual: no stalled service loop, no unpolled stack, worst poll gap
    159 ms. The row asks for host-side evidence, and the obvious form of it, a
    packet capture, needs root on this machine -- which this gate does not have
    and should not ask for.

    The client will say most of it for free. The rounds themselves run at
    LogLevel=ERROR because 1257 verbose transcripts are noise; this one runs at
    DEBUG3 and is kept whole. It is for the distinction the guest cannot draw:
    a server that closed the connection, a server that refuses the next one,
    and a client that gave up on its own are indistinguishable from inside the
    guest and are three different transcripts here.

    It runs after the failure rather than during it, so it records the state
    left behind and not the event. That is worth saying plainly rather than
    letting a reader assume otherwise: if this session connects and behaves, it
    establishes that the server was healthy a second later, which is evidence
    about the shape of the fault and not a capture of it.
    """
    started = time.monotonic()
    result = subprocess.run(
        ["sftp", "-F", "/dev/null", "-i", str(smoke.TEST_KEY),
         "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
         "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
         "-o", "LogLevel=DEBUG3", "-b", "-", f"admin@{address}"],
        input="pwd\n", cwd=ROOT, text=True, capture_output=True, timeout=120,
        check=False)
    return {"exit_code": result.returncode,
            "seconds": round(time.monotonic() - started, 2),
            "transcript": result.stderr.strip()}


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
            # The full transcript is used below where it matters; carrying it
            # 1257 times would bury the report it is meant to inform.
            rounds.append({k: v for k, v in entry.items()
                           if k != "stderr_full"})
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
                # Everything the client said, not the first 200 characters of
                # it, and one verbose session asking what the transport does
                # next. Both only on the round that failed.
                record["sftp_stderr_full"] = entry.get("stderr_full", "")
                record["verbose_probe"] = verbose_probe(address)
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
    # Descriptors, not line counts.
    #
    # Counting every `net_close` against every `net_accept` made the figure
    # negative -- 2515 accepted, 2516 closed -- which reads as a connection the
    # guest closed without ever accepting. It was the UDP listening socket:
    # `net_listen protocol=17 port=24002 sockfd=6`, closed at shutdown and
    # never accepted because a listener is not accepted. Any descriptor the
    # server opens itself does the same thing, so the difference was measuring
    # the wrong population.
    #
    # Matching closes to the descriptors that were actually accepted keeps the
    # number meaning what its name says: sessions taken and not given back.
    accepted_fds = set(re.findall(r"net_accept listenfd=\d+ connfd=(\d+)", console))
    closed_fds = set(re.findall(r"net_close sockfd=(\d+)", console))
    accepted = len(accepted_fds)
    closed = len(accepted_fds & closed_fds)
    outstanding = accepted - closed
    session_tally = {
        "accepted": accepted,
        "closed": closed,
        "outstanding": outstanding,
        "closes_of_unaccepted_descriptors": len(closed_fds - accepted_fds),
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

    # How the failing rounds' sockets actually ended, read from the whole
    # console rather than from the round's own window -- see the helper above.
    resolve_stranded_sockets(correlation, smoke.serial_text())

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


if __name__ == "__main__":
    if "--self-test" in sys.argv[1:]:
        raise SystemExit(self_test())
    raise SystemExit(main())
