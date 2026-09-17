#!/usr/bin/env python3
"""Three XAIOS machines, all alive, and the links between them cut.

What this adds to the three-node gate
-------------------------------------

`qemu-cluster-three-node-gate` partitions a cluster by SIGKILLing an
emulator, and that is the failure a LEAVE cannot cover. It is also only half
of the problem, and the half that is easier on the cluster: a killed process
stops answering AND stops sending. Nobody on the other side of it is deciding
anything.

A partition is the other half. Both machines are alive, both are heartbeating,
each hears nothing from the other, and each has to decide on its own what it
is entitled to do. If both sides decide they are in charge, that is split
brain: one expert with two owners, which is not an error anybody detects. It
is work done twice and a result nobody reconciles.

So this gate puts a relay between the nodes -- `cluster_fault_relay.py`, one
listener per ordered pair -- and breaks the links rather than the machines.
Three faults, in one boot:

  symmetric 2-1   every link into and out of node 3 is cut. Nodes 1 and 2 are
                  a majority and must keep serving; node 3 is a minority and
                  must withhold ownership, while STILL RUNNING and still
                  trying to talk -- which is what makes it a partition and not
                  a death, and which the relay's refused-connection counters
                  prove independently of anything node 3 says.

  heal            the links come back and the three have to converge on one
                  membership and one ownership map again -- the same map they
                  had before, because the assignment is a hash and nothing
                  about it should remember the outage.

  asymmetric      only node 3's OUTBOUND links are cut. Nodes 1 and 2 stop
                  hearing it; it goes on hearing them. Its view of the
                  cluster is therefore unchanged while the other two have
                  already written it off, and if it still believes it holds
                  quorum then two different memberships are both deciding
                  ownership at once. This is the case that breaks quorum logic
                  written as though silence were mutual, and it is not
                  reachable by killing anything.

then a second heal, so the asymmetric fault is repaired and checked too.

What is asserted, and how each assertion can fail
-------------------------------------------------

Relationships between the three logs, never a literal: the two sides of a
partition must name the same members and the same owners as each other, the
experts that move must be exactly the ones the departed node owned, and the
map after a heal must equal the map before the cut. A node that cached its
answer, one that recomputed from a stale membership, and one that reshuffled
everything each fail a different one of those.

Every check carries an id, and there are three controls:

  XAIOS_CLUSTER_PARTITION_SKIP_CUT=1
      Every phase runs, every wait waits, every check runs -- and no link is
      ever cut. The named partition checks must ALL go red, and the run is
      non-zero either way, because this configuration is never a passing
      gate. If any check in REQUIRED_RED stays green with nothing cut then
      that check does not depend on a partition and is worth nothing; the run
      says so in those words. The three-node gate's first version guarded its
      checks behind the kill having happened and produced a control run that
      passed while checking nothing, so nothing here is guarded behind the
      cut: the checks that need a partition to have happened state that as a
      conjunct of the check itself rather than as a condition on running it.

  --self-test
      The analysis is a pure function of evidence, so it can be handed
      evidence describing runs that never happened. The self test builds a
      healthy partition-and-heal transcript, asserts nothing fires, then
      mutates it once per check -- a survivor that never noticed, two sides
      that disagree, a minority that answered ownership, a heal that never
      reconverged, an ownership map that changed across a heal, and a node
      that kept quorum while the other two excluded it -- and asserts that
      the matching check goes red for each. Collateral reds are allowed: a
      transcript in which a survivor never noticed the partition is also one
      in which its membership is wrong, and demanding that exactly one check
      fire would mean writing mutations that are less like real failures
      rather than more. It also refuses to pass unless every check in
      REQUIRED_RED has a mutation demonstrating it can fail, so the live
      control run above cannot come to lean on a check nobody has ever seen
      go red. It runs in a second and needs no emulator, and it is the only
      way to show that a check which SHOULD never fire in practice -- the
      split-brain one -- is capable of firing at all.

  python3 tests/scripts/cluster_fault_relay.py --self-test
      The fault injector's own control: bytes cross a healthy link, a cut
      stops them, a heal restores them. A gate built on a relay that does not
      actually cut cannot tell "the cluster behaved" from "nothing happened".

Ports
-----

Nine host ports, all of them explicit: three that each emulator forwards
inward, and six relay listeners, one per ordered pair. The guests' own listen
ports live inside their user networks and collide with nothing. A default
port is how two gates running at once produce a guest with no console output
and an emulator that died saying it could not set up a host forwarding rule,
so every one of them is checked as free before anything starts.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tests" / "scripts"))
from cluster_partition_protocol import (  # noqa: E402
    ARCH,
    BACK_PORT,
    BOOT_TIMEOUT_S,
    DETECT_S,
    GUEST_PORT,
    HEAL_S,
    NODES,
    PAIRS,
    QUIET_S,
    RELAY_PORT,
    REPORT,
    ROOT,
    SETTLE_S,
    SKIP_CUT,
    START_RE,
    WORK,
    Run,
    build_node,
    cut,
    launch,
    port_is_busy,
    stop,
)
from cluster_partition_analysis import REQUIRED_RED, analyse  # noqa: E402
from cluster_partition_selftest import self_test  # noqa: E402


def main() -> int:
    if "--self-test" in sys.argv:
        return self_test()

    for port in list(BACK_PORT.values()) + list(RELAY_PORT.values()):
        if port_is_busy(port):
            print(f"cluster-partition: FAIL host port {port} is already "
                  f"listening; another emulator or relay would silently take "
                  f"this run's traffic")
            return 1

    WORK.mkdir(parents=True, exist_ok=True)
    run = Run()
    for node in NODES:
        run.images[node] = build_node(node)

    harness: list[tuple[str, str]] = []
    binaries = {node: run.images[node]["app"].read_bytes() for node in NODES}
    for left in NODES:
        for right in NODES:
            if left < right and binaries[left] == binaries[right]:
                harness.append((
                    "identity",
                    f"nodes {left} and {right} were built from identical "
                    f"binaries, so at least one carries the wrong node id or "
                    f"the wrong port table"))

    deadline_ms = 20000
    try:
        run.relay.start()
        for node in NODES:
            run.processes[node] = launch(node, run.images[node])

        formed_deadline = time.monotonic() + BOOT_TIMEOUT_S
        formed = True
        for node in NODES:
            if run.wait_for_after(node, 0, "reason=formed",
                                  formed_deadline) is None:
                formed = False
        start = START_RE.search(run.log(1))
        if start is not None:
            deadline_ms = int(start.group(4))

        # ---- healthy, connected, and nobody declared dead
        run.open_phase("quiet")
        quiet_until = time.monotonic() + (QUIET_S if formed else 1.0)
        while time.monotonic() < quiet_until:
            time.sleep(1.0)
        run.close_phase("quiet")

        # ---- symmetric 2-1: node 3 loses every link, in both directions
        phase = run.open_phase("symmetric")
        offsets = {node: phase["windows"][str(node)][0] for node in NODES}
        phase["cut_links"] = cut(run, "isolate", 3)
        cut_moment = time.monotonic()
        deadline = cut_moment + DETECT_S
        for node in (1, 2):
            seen = run.wait_for_after(node, offsets[node],
                                      "mesh peer-lost node=3 reason=silence",
                                      deadline)
            phase["detect_seconds"][str(node)] = \
                None if seen is None else round(seen - cut_moment, 2)
        for peer in (1, 2):
            seen = run.wait_for_after(
                3, offsets[3], f"mesh peer-lost node={peer} reason=silence",
                deadline)
            phase["detect_seconds"].setdefault(
                "3", None if seen is None else round(seen - cut_moment, 2))
        time.sleep(SETTLE_S)
        run.close_phase("symmetric")

        # ---- and the repair
        phase = run.open_phase("heal")
        offsets = {node: phase["windows"][str(node)][0] for node in NODES}
        if not SKIP_CUT:
            run.relay.heal_all()
        heal_deadline = time.monotonic() + HEAL_S
        for node, peers in ((1, (3,)), (2, (3,)), (3, (1, 2))):
            for peer in peers:
                run.wait_for_after(node, offsets[node],
                                   f"mesh peer-found node={peer}",
                                   heal_deadline)
        time.sleep(SETTLE_S)
        run.close_phase("heal")

        # ---- asymmetric: node 3 is heard by nobody and hears everybody
        phase = run.open_phase("asymmetric")
        offsets = {node: phase["windows"][str(node)][0] for node in NODES}
        phase["cut_links"] = cut(run, "silence_outbound", 3)
        cut_moment = time.monotonic()
        deadline = cut_moment + DETECT_S
        for node in (1, 2):
            seen = run.wait_for_after(node, offsets[node],
                                      "mesh peer-lost node=3 reason=silence",
                                      deadline)
            phase["detect_seconds"][str(node)] = \
                None if seen is None else round(seen - cut_moment, 2)
        time.sleep(SETTLE_S)
        run.close_phase("asymmetric")

        # ---- and its repair, which is the faster one: node 3 never wrote
        # its peers off, so it is still dialling them every couple of seconds
        phase = run.open_phase("heal2")
        offsets = {node: phase["windows"][str(node)][0] for node in NODES}
        if not SKIP_CUT:
            run.relay.heal_all()
        heal_deadline = time.monotonic() + HEAL_S
        for node in (1, 2):
            run.wait_for_after(node, offsets[node], "mesh peer-found node=3",
                               heal_deadline)
        time.sleep(SETTLE_S)
        run.close_phase("heal2")
    finally:
        for node in NODES:
            if node in run.processes:
                stop(run.processes[node])
        run.relay.stop()

    evidence = run.evidence(deadline_ms)
    failures = harness + analyse(evidence)

    relay_snapshot = run.relay.snapshot()
    report = {
        "schema": "xaios.cluster-partition.v1",
        "arch": ARCH,
        "skip_cut": SKIP_CUT,
        "guest_port": {str(node): GUEST_PORT[node] for node in NODES},
        "back_port": {str(node): BACK_PORT[node] for node in NODES},
        "relay_port": {f"{a}->{b}": RELAY_PORT[(a, b)] for a, b in PAIRS},
        "relay": relay_snapshot,
        "deadline_ms": deadline_ms,
        "phases": {name: {key: value for key, value in phase.items()}
                   for name, phase in run.phases.items()},
        "logs": {str(node): str(run.images[node]["log"].relative_to(ROOT))
                 for node in NODES},
        "failures": [{"check": check, "message": message}
                     for check, message in failures],
        "passed": not failures and not SKIP_CUT,
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    red = {check for check, _ in failures}
    if SKIP_CUT:
        for check, message in failures:
            print(f"cluster-partition: EXPECTED-FAIL [{check}] {message}")
        missing = [check for check in REQUIRED_RED if check not in red]
        print(f"cluster-partition: control run: {len(failures)} checks went "
              f"red with nothing cut")
        if missing:
            print("cluster-partition: CONTROL DID NOT WORK: these checks "
                  "stayed green with no link cut, so they do not depend on a "
                  "partition: " + ", ".join(missing))
        else:
            print("cluster-partition: every partition check went red with "
                  "nothing cut, and the quiet-window check stayed green, so "
                  "the checks depend on the fault rather than on time "
                  "passing")
        print(f"cluster-partition: report={REPORT}")
        return 1
    if failures:
        for check, message in failures:
            print(f"cluster-partition: FAIL [{check}] {message}")
        if red == {"asymmetric-no-double-ownership"}:
            # Said at length because a red gate whose only red is a defect in
            # the thing under test invites being "fixed" by relaxing the
            # check, and this one must not be.
            print(
                "cluster-partition: everything else passed, and the one "
                "failure is a defect in the cluster rather than in this "
                "gate. Membership here is decided from inbound silence "
                "alone: a node judges its peers by whether their frames "
                "arrive, and nothing tells it whether its own frames are "
                "arriving anywhere. Cut only one node's outbound links and "
                "that asymmetry becomes two clusters -- the majority stops "
                "hearing it and reassigns its experts, while it goes on "
                "hearing the majority, goes on counting three live nodes, "
                "and goes on owning what has already been taken from it. "
                "Both sides hold a quorum by their own arithmetic and one "
                "expert has two owners, which is the outcome quorum exists "
                "to prevent.")
            print(
                "cluster-partition: the shape of a fix, for whoever takes "
                "it: a heartbeat that carries the sender's own member list, "
                "so a node that is named by nobody learns it has been "
                "excluded and stands down -- liveness becomes mutual rather "
                "than something each node decides alone. Do not relax this "
                "check to make the gate green; it is reporting the truth.")
        print(f"cluster-partition: report={REPORT}")
        return 1
    print("cluster-partition: three XAIOS machines formed a cluster; every "
          "link to one of them was cut while it kept running, the majority "
          "kept serving and moved only that node's experts, the minority "
          "withheld ownership, the repair put both back to one membership "
          "and the ownership it started with, and a one-way cut left no node "
          "claiming a quorum the others had already taken from it")
    print(f"cluster-partition: passed report={REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
