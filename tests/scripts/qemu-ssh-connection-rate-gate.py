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

The machinery that carries this out -- the limiter constants, the bare-TCP
probe, the guest build step and the per-case boot -- lives in the sibling
module `qemu_ssh_connection_rate_gate_lib`; `main` below is the gate proper.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "scripts"))
from qemu_ssh_connection_rate_gate_lib import (ARCH, BUILD, HOST_PORT, LIMIT,
                                               READY, REPORT, WINDOW_SECONDS,
                                               build_guest, run_case)


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

        # Before any verdict: did the host actually open the connections?
        #
        # `unreachable` is the host failing to connect at all and `silent` is a
        # connection accepted and then neither served nor closed. Neither is
        # the guest turning anything away, and neither counts as a refusal --
        # so a run carrying them produced *both* "only 113 of the first 120
        # were answered" and "all 121 were served, so the limit did not fire",
        # which cannot both be true. That is this gate accusing the guest of a
        # defect the host caused, which is the failure it was written to stop
        # other gates making.
        #
        # It stays a non-zero exit. An inconclusive run that exits 0 is a gate
        # that cannot fail. It names the host instead.
        stillborn = [o for o in outcomes if o in ("unreachable", "silent")]
        if stillborn:
            failures.append(
                f"INCONCLUSIVE, not a guest defect: {len(stillborn)} of "
                f"{len(outcomes)} connections never reached a verdict -- "
                f"{outcomes.count('unreachable')} could not be opened by this "
                f"host and {outcomes.count('silent')} were accepted and then "
                f"neither served nor closed. The guest cannot be judged on a "
                f"run whose connections did not arrive; re-run on a quieter "
                f"machine, or open them more slowly")
        elif len(served) < LIMIT:
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
        authed_stillborn = [o for o in authed["outcomes"]
                            if isinstance(o, str)
                            and ("Operation timed out" in o or "timeout" in o)]
        if authed_stillborn and served_preload != LIMIT - headroom:
            failures.append(
                f"INCONCLUSIVE, not a guest defect: the authenticated case "
                f"loaded {served_preload} of the {LIMIT - headroom} it needs "
                f"and its sessions timed out reaching the host. The window was "
                f"not where the case requires and nothing about the credit is "
                f"shown either way")
        elif served_preload != LIMIT - headroom:
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
