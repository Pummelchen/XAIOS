"""Evidence for cluster-partition runs that never happened.

Moved verbatim out of `qemu-cluster-partition-gate.py` so that the gate itself
is the live run and nothing else. `self_test` builds a healthy
partition-and-heal transcript, asserts that `analyse` raises nothing on it,
then mutates it once per check and asserts that the matching check goes red.
It is the only way to show that a check which should never fire in practice --
the split-brain one -- is capable of firing at all, and it runs in a second
with no emulator.

The report grammar and the port tables it fabricates come from
`cluster_partition_protocol.py`; the assertions it drives and the list of
checks the control run requires to go red come from
`cluster_partition_analysis.py`.
"""

from __future__ import annotations

import copy

from cluster_partition_protocol import (  # noqa: E402
    ARCH,
    BACK_PORT,
    GUEST_PORT,
    NODES,
    PAIRS,
    RELAY_PORT,
)
from cluster_partition_analysis import REQUIRED_RED, analyse  # noqa: E402


# ---------------------------------------------------------------- self test
#
# Evidence for runs that never happened, so that every check can be shown to
# fire. A gate whose assertions have only ever been seen passing is a gate
# nobody has tested.


def _synthetic(before=(3, 3, 1, 2, 3, 1, 3, 2),
               after=(1, 2, 1, 2, 1, 1, 2, 2)) -> dict:
    before_text = ",".join(str(o) for o in before)
    after_text = ",".join(str(o) for o in after)

    def report(node, version, live, quorum, reason, members, owners):
        return (f"/bin/clustertest: mesh report node={node} version={version} "
                f"live={live} total=3 quorum={quorum} reason={reason} "
                f"members={members} owners={owners}\n")

    logs: dict[int, list[str]] = {}
    windows: dict[str, dict[int, list[int]]] = {
        name: {} for name in ("quiet", "symmetric", "heal", "asymmetric",
                              "heal2")}
    for node in NODES:
        peers = [p for p in NODES if p != node]
        lines = [f"/bin/clustertest: mesh node={node} of=3 heartbeat_ms=500 "
                 f"silence_deadline_ms=20000 mode=hold\n",
                 f"/bin/clustertest: mesh listening port={GUEST_PORT[node]}\n"]
        for peer in peers:
            lines.append(f"/bin/clustertest: mesh dial node={peer} "
                         f"port={RELAY_PORT[(node, peer)]} result=ok "
                         f"took_ms=1\n")
        lines.append(report(node, 1, 3, 1, "formed", "1,2,3", before_text))
        logs[node] = lines
    text_of = {node: "".join(logs[node]) for node in NODES}

    def append(node: int, more: str) -> None:
        text_of[node] += more

    def open_window(name: str) -> None:
        for node in NODES:
            windows[name][node] = [len(text_of[node]), None]

    def close_window(name: str) -> None:
        for node in NODES:
            windows[name][node][1] = len(text_of[node])

    open_window("quiet")
    for node in NODES:
        append(node, report(node, 2, 3, 1, "periodic", "1,2,3", before_text))
    close_window("quiet")

    open_window("symmetric")
    for node in (1, 2):
        append(node, "/bin/clustertest: mesh peer-lost node=3 reason=silence "
                     "silent_for_ms=20004 deadline_ms=20000\n")
        append(node, report(node, 3, 2, 1, "peer-lost", "1,2", after_text))
        append(node, report(node, 4, 2, 1, "periodic", "1,2", after_text))
    for peer in (1, 2):
        append(3, f"/bin/clustertest: mesh peer-lost node={peer} "
                  f"reason=silence silent_for_ms=20003 deadline_ms=20000\n")
    append(3, report(3, 3, 1, 0, "peer-lost", "3", "withheld"))
    append(3, report(3, 4, 1, 0, "periodic", "3", "withheld"))
    close_window("symmetric")

    open_window("heal")
    for node in (1, 2):
        append(node, "/bin/clustertest: mesh peer-found node=3\n")
        append(node, report(node, 5, 3, 1, "peer-found", "1,2,3", before_text))
    for peer in (1, 2):
        append(3, f"/bin/clustertest: mesh peer-found node={peer}\n")
    append(3, report(3, 5, 3, 1, "peer-found", "1,2,3", before_text))
    close_window("heal")

    open_window("asymmetric")
    for node in (1, 2):
        append(node, "/bin/clustertest: mesh peer-lost node=3 reason=silence "
                     "silent_for_ms=20002 deadline_ms=20000\n")
        append(node, report(node, 6, 2, 1, "peer-lost", "1,2", after_text))
    # The behaviour a correct engine would show: node 3 hears the others, and
    # knows from what they say that they are no longer counting it, so it
    # stands down rather than going on owning what they have reassigned.
    append(3, report(3, 6, 1, 0, "periodic", "3", "withheld"))
    close_window("asymmetric")

    open_window("heal2")
    for node in (1, 2):
        append(node, "/bin/clustertest: mesh peer-found node=3\n")
        append(node, report(node, 7, 3, 1, "peer-found", "1,2,3", before_text))
    append(3, report(3, 7, 3, 1, "periodic", "1,2,3", before_text))
    close_window("heal2")

    for node in NODES:
        append(node, "/bin/clustertest: mesh worst_dial_ms=9 "
                     "deadline_ms=20000\n")

    phases = {}
    for name in windows:
        phases[name] = {
            "windows": {str(node): list(windows[name][node])
                        for node in NODES},
            "cut_links": [],
            "detect_seconds": {},
            "alive": {str(node): True for node in NODES},
            "exited": [],
            "bytes": {f"{a}->{b}": 1000 for a, b in PAIRS},
            "refused": {f"{a}->{b}": 0 for a, b in PAIRS},
        }
    phases["symmetric"]["cut_links"] = [f"{a}->{b}" for a, b in PAIRS
                                        if 3 in (a, b)]
    phases["symmetric"]["detect_seconds"] = {"1": 20.1, "2": 20.2, "3": 20.3}
    phases["symmetric"]["refused"] = {
        f"{a}->{b}": (5 if a == 3 else 0) for a, b in PAIRS}
    phases["symmetric"]["bytes"] = {
        f"{a}->{b}": (0 if 3 in (a, b) else 1000) for a, b in PAIRS}
    phases["asymmetric"]["cut_links"] = [f"3->{b}" for b in (1, 2)]
    phases["asymmetric"]["detect_seconds"] = {"1": 20.4, "2": 20.5}
    phases["asymmetric"]["bytes"] = {
        f"{a}->{b}": (0 if a == 3 else 1000) for a, b in PAIRS}

    return {
        "config": {
            "arch": ARCH,
            "deadline_ms": 20000,
            "guest_port": {str(node): GUEST_PORT[node] for node in NODES},
            "relay_port": {f"{a}->{b}": RELAY_PORT[(a, b)] for a, b in PAIRS},
            "skip_cut": False,
        },
        "nodes": {str(node): {"log": text_of[node]} for node in NODES},
        "phases": phases,
    }


def self_test() -> int:
    failures: list[str] = []

    healthy = _synthetic()
    found = analyse(healthy)
    if found:
        failures.append(
            "the healthy transcript did not pass: "
            + "; ".join(f"[{check}] {message}" for check, message in found))

    demonstrated: set[str] = set()

    def mutate(name: str, expect: str, change) -> None:
        """One transcript, one thing wrong with it, one check that must fire.

        Collateral reds are not an error: a transcript in which a survivor
        never noticed the partition is also a transcript in which its
        membership is wrong, and demanding that exactly one check fire would
        mean writing mutations that are less like real failures rather than
        more.
        """
        evidence = copy.deepcopy(healthy)
        change(evidence)
        red = {check for check, _ in analyse(evidence)}
        if expect not in red:
            failures.append(
                f"mutation {name!r} did not make [{expect}] fail; it made "
                f"{sorted(red) or 'nothing'} fail")
        else:
            demonstrated.add(expect)

    def replace(evidence: dict, node: int, old: str, new: str) -> None:
        """Rewrite the first occurrence of one line, keeping the windows valid.

        The windows are byte offsets into the log, so a substitution of a
        different length moves every window that starts after it. Shifting
        them here rather than forbidding the substitution keeps each mutation
        to the one thing it is demonstrating: a mutation that had to be
        padded to the original length would be describing the padding as well.
        It raises rather than silently doing nothing if the text is absent,
        because a mutation that changed nothing would "prove" that a check
        cannot fire.
        """
        log = evidence["nodes"][str(node)]["log"]
        at = log.find(old)
        if at < 0:
            raise AssertionError(f"nothing to replace: {old!r}")
        evidence["nodes"][str(node)]["log"] = \
            log[:at] + new + log[at + len(old):]
        delta = len(new) - len(old)
        if delta == 0:
            return
        end = at + len(old)
        for phase in evidence["phases"].values():
            bounds = phase["windows"][str(node)]
            for index, offset in enumerate(bounds):
                if offset is not None and offset >= end:
                    bounds[index] = offset + delta

    # A survivor that never noticed the peer stop arriving.
    mutate("survivor never noticed", "symmetric-majority-noticed",
           lambda e: replace(e, 1, "mesh peer-lost node=3 reason=silence",
                             "mesh peer-lost node=9 reason=silence"))
    # A survivor that moved membership the instant the socket died.
    mutate("membership moved on the socket", "symmetric-detected-by-silence",
           lambda e: replace(e, 1, "silent_for_ms=20004", "silent_for_ms=00204"))
    mutate("detection was immediate", "symmetric-detection-not-immediate",
           lambda e: e["phases"]["symmetric"]["detect_seconds"].update(
               {"1": 0.4}))
    # Two survivors that do not agree on who owns what.
    mutate("survivors disagree", "symmetric-majority-agree",
           lambda e: replace(e, 2, "reason=periodic members=1,2 owners=1,2,1,2,1,1,2,2",
                             "reason=periodic members=1,2 owners=2,2,1,2,1,1,2,2"))
    # An expert still owned by the node nobody can reach.
    mutate("dead node keeps an expert", "symmetric-reassignment",
           lambda e: [replace(e, node,
                              "reason=periodic members=1,2 owners=1,2,1,2,1,1,2,2",
                              "reason=periodic members=1,2 owners=3,2,1,2,1,1,2,2")
                      for node in (1, 2)])
    # An expert that moved although neither end of it was partitioned.
    mutate("untouched expert moves", "symmetric-reassignment",
           lambda e: [replace(e, node,
                              "reason=periodic members=1,2 owners=1,2,1,2,1,1,2,2",
                              "reason=periodic members=1,2 owners=1,2,2,2,1,1,2,2")
                      for node in (1, 2)])
    # A minority that answered ownership anyway.
    mutate("minority answers ownership", "symmetric-minority-stands-down",
           lambda e: replace(e, 3,
                             "reason=periodic members=3 owners=withheld",
                             "reason=periodic members=3 owners=3,3,3,3,3,3,3"))
    # A minority that was not there at all: a death, not a partition.
    mutate("minority was dead", "symmetric-minority-alive-and-trying",
           lambda e: e["phases"]["symmetric"]["alive"].update({"3": False}))
    mutate("minority stopped dialling", "symmetric-minority-alive-and-trying",
           lambda e: e["phases"]["symmetric"]["refused"].update(
               {"3->1": 0, "3->2": 0}))
    # Both sides of the partition claiming quorum: the outcome this whole
    # gate exists to detect, and the only way to see the check work.
    mutate("both sides claim quorum", "symmetric-no-split-brain",
           lambda e: replace(e, 3,
                             "live=1 total=3 quorum=0 reason=periodic members=3 owners=withheld",
                             "live=1 total=3 quorum=1 reason=periodic members=3 owners=3,3,3,3"))
    mutate("both sides own the same expert", "symmetric-no-double-ownership",
           lambda e: replace(
               e, 3,
               "node=3 version=4 live=1 total=3 quorum=0 reason=periodic members=3 owners=withheld",
               "node=3 version=4 live=2 total=3 quorum=1 reason=periodic members=1,2 owners=3,2,1,2,1,1,2,2"))
    # A cluster that never came back together.
    mutate("heal never happened", "heal-rejoined",
           lambda e: replace(e, 1, "mesh peer-found node=3\n",
                             "mesh peer-found node=9\n"))
    mutate("heal left a stale membership", "heal-membership",
           lambda e: replace(
               e, 2,
               "node=2 version=5 live=3 total=3 quorum=1 reason=peer-found members=1,2,3",
               "node=2 version=5 live=2 total=3 quorum=1 reason=peer-found members=1,2  "))
    # A healed cluster whose ownership map is not the one it started with.
    mutate("heal changed the map", "heal-ownership-restored",
           lambda e: [replace(
               e, node,
               "reason=peer-found members=1,2,3 owners=3,3,1,2,3,1,3,2",
               "reason=peer-found members=1,2,3 owners=3,3,1,2,3,1,3,1")
               for node in NODES])
    # An asymmetric cut that was not asymmetric.
    mutate("asymmetric cut both ways", "asymmetric-one-way-silence",
           lambda e: _append(
               e, 3, "/bin/clustertest: mesh peer-lost node=1 reason=silence "
                     "silent_for_ms=20001 deadline_ms=20000\n", "asymmetric"))
    mutate("relay carried what it had cut", "asymmetric-relay-directionality",
           lambda e: e["phases"]["asymmetric"]["bytes"].update({"3->1": 42}))
    # The defect this gate was written to look for: a node nobody can hear
    # that goes on owning what the majority has already reassigned.
    mutate("silenced node keeps quorum", "asymmetric-no-double-ownership",
           lambda e: replace(
               e, 3,
               "node=3 version=6 live=1 total=3 quorum=0 reason=periodic members=3 owners=withheld",
               "node=3 version=6 live=3 total=3 quorum=1 reason=periodic members=1,2,3 owners=3,3,1,2,3,1,3,2"))
    # And the plumbing checks.
    mutate("built without the hold", "identity",
           lambda e: replace(e, 1, " mode=hold\n", "\n         "))
    mutate("dialled around the relay", "dial-through-relay",
           lambda e: replace(e, 1,
                             f"mesh dial node=2 port={RELAY_PORT[(1, 2)]} ",
                             f"mesh dial node=2 port={BACK_PORT[2]} "))
    mutate("a node died in the quiet window", "quiet-window",
           lambda e: e["phases"]["quiet"]["exited"].append(2))
    mutate("a death was declared while healthy", "quiet-window",
           lambda e: _append(e, 1,
                             "/bin/clustertest: mesh peer-lost node=2 "
                             "reason=silence silent_for_ms=20000 "
                             "deadline_ms=20000\n", "quiet"))
    mutate("a dial that could starve the deadline", "dial-margin",
           lambda e: replace(e, 1, "mesh worst_dial_ms=9 deadline_ms=20000",
                             "mesh worst_dial_ms=19000 deadline_ms=20000"))
    mutate("a cyan screen", "console-clean",
           lambda e: _append(e, 2, "CYAN SCREEN OF DEATH\n", "heal2"))
    # A survivor whose settled view of the partition is still the whole
    # cluster: it noticed nothing and went on serving as three.
    mutate("survivor kept the whole membership",
           "symmetric-majority-membership",
           lambda e: replace(
               e, 1,
               "node=1 version=4 live=2 total=3 quorum=1 reason=periodic members=1,2",
               "node=1 version=4 live=3 total=3 quorum=1 reason=periodic members=1,2,3"))
    # The cut-off node never noticing that it had been cut off.
    mutate("minority never noticed", "symmetric-minority-noticed",
           lambda e: replace(e, 3, "mesh peer-lost node=1 reason=silence",
                             "mesh peer-lost node=9 reason=silence"))
    # The second repair failing where the first one worked.
    mutate("second heal never happened", "heal2-rejoined",
           lambda e: replace(
               e, 2,
               "mesh peer-found node=3\n/bin/clustertest: mesh report node=2 version=7",
               "mesh peer-found node=9\n/bin/clustertest: mesh report node=2 version=7"))
    mutate("second heal left a stale membership", "heal2-membership",
           lambda e: replace(
               e, 3,
               "node=3 version=7 live=3 total=3 quorum=1 reason=periodic members=1,2,3",
               "node=3 version=7 live=2 total=3 quorum=1 reason=periodic members=1,2"))

    # Every check that the live control run demands go red has to have been
    # shown, here, to be capable of going red at all. A check nobody has ever
    # seen fail is a check nobody has tested, and this is the list the control
    # run leans on.
    for check in REQUIRED_RED:
        if check not in demonstrated:
            failures.append(
                f"[{check}] is required to go red in the control run and no "
                f"mutation here demonstrates that it can fail at all")

    for message in failures:
        print(f"cluster-partition: SELF-TEST FAIL {message}")
    if failures:
        return 1
    print("cluster-partition: self-test passed: a healthy partition-and-heal "
          "transcript raises nothing, and every check goes red for a "
          "transcript describing the failure it is there to catch")
    return 0


def _append(evidence: dict, node: int, line: str, phase: str) -> None:
    """Insert a line inside one phase's window and shift the later ones.

    Windows are byte offsets, so appending inside one means every window that
    starts after it moves by the same amount. Doing that here rather than
    rebuilding the transcript keeps each mutation to the one thing it is
    demonstrating.
    """
    windows = evidence["phases"][phase]["windows"][str(node)]
    at = windows[1]
    log = evidence["nodes"][str(node)]["log"]
    evidence["nodes"][str(node)]["log"] = log[:at] + line + log[at:]
    for other_phase in evidence["phases"].values():
        bounds = other_phase["windows"][str(node)]
        for index, offset in enumerate(bounds):
            if offset is not None and offset >= at:
                bounds[index] = offset + len(line)
    windows[1] = at + len(line)
