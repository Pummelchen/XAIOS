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

import copy
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
sys.path.insert(0, str(ROOT / "tests" / "scripts"))
from qemu_gate_lib import arch_from_argv, qemu_runner, smoke_timeout  # noqa: E402
from cluster_fault_relay import FaultRelay  # noqa: E402

ARCH = arch_from_argv(sys.argv)
SUFFIX = "" if ARCH == "aarch64" else f"-{ARCH}"
WORK = BUILD / f"cluster-partition{SUFFIX}"
REPORT = BUILD / f"qemu-cluster-partition-gate{SUFFIX}.json"

NODES = (1, 2, 3)
PAIRS = tuple((a, b) for a in NODES for b in NODES if a != b)

# Inside each guest. Nothing on the host binds these, so they may be the same
# numbers on all three machines in principle -- they are not, because a log
# line saying which port a node listened on is then also a statement about
# which node it thinks it is.
GUEST_PORT = {node: int(os.environ.get(f"XAIOS_CLUSTER_PARTITION_GUEST_PORT_{node}",
                                       7800 + node))
              for node in NODES}
# On the host: what each emulator forwards inward, and therefore what the
# relay dials to reach that guest. No guest is built knowing these, so the
# only way to a guest is through a relay listener.
BACK_PORT = {node: int(os.environ.get(f"XAIOS_CLUSTER_PARTITION_BACK_PORT_{node}",
                                      2900 + node))
             for node in NODES}
# On the host: one listener per ordered pair, which is what gives the fault
# injector its direction. Node a is built to dial b here.
RELAY_PORT = {
    (a, b): int(os.environ.get(f"XAIOS_CLUSTER_PARTITION_RELAY_PORT_{a}_{b}",
                               2910 + a * 10 + b - 10))
    for a, b in PAIRS
}

BOOT_TIMEOUT_S = smoke_timeout(
    ARCH, int(os.environ.get("XAIOS_CLUSTER_PARTITION_TIMEOUT", "600")))
# All three healthy, for longer than their own silence deadline, before
# anything is cut. A detector that fires on time passing rather than on
# silence is caught here rather than mistaken for a working one.
QUIET_S = float(os.environ.get("XAIOS_CLUSTER_PARTITION_QUIET_S", "30"))
# How long a side of a partition is given to notice, and how long a healed
# cluster is given to find itself again. The guests use a twenty second
# deadline; a node that has written a peer off retries the dial every thirty
# seconds, so a heal is the slower of the two.
DETECT_S = float(os.environ.get("XAIOS_CLUSTER_PARTITION_DETECT_S", "120"))
HEAL_S = float(os.environ.get("XAIOS_CLUSTER_PARTITION_HEAL_S", "180"))
# After the thing being waited for has happened, let every node emit at least
# one periodic report describing the settled state. Comparing the two sides of
# a partition means comparing what they believed at the same moment, and a
# window that closes the instant one of them noticed contains one settled
# view and one that is still catching up.
SETTLE_S = float(os.environ.get("XAIOS_CLUSTER_PARTITION_SETTLE_S", "12"))
# A budget worth checking before raising any of the numbers above. The mesh
# gives itself fifteen minutes from the moment it starts and then exits with
# "mesh run limit reached", which this gate reads as a forbidden line. The
# control run is the long one, because every wait above runs to its timeout
# with nothing cut: 30 + 120 + 12 + 180 + 12 + 120 + 12 + 180 + 12 is 678
# seconds, and formation happens inside the first twenty. Adding to any of
# these without adding to MESH_RUN_LIMIT_NS in clustertest.c turns a control
# run into a run that fails for a reason of its own making -- loudly, since
# that line is forbidden, but confusingly.
SKIP_CUT = os.environ.get("XAIOS_CLUSTER_PARTITION_SKIP_CUT", "0") == "1"

ARCHITECTURES = {
    "aarch64": {
        "build": [["./scripts/build-image.sh"]],
        "runner_env": {
            "boot": "XAIOS_AARCH64_IMAGE",
            "initfs": "XAIOS_TEST_BLOCK_IMAGE",
            "xaifs": "XAIOS_XAI_FS_IMAGE",
            "system": "XAIOS_SYSTEM_VOLUME_IMAGE",
            "persistent": "XAIOS_PERSISTENT_IMAGE",
        },
        "hostfwd_env": "XAIOS_QEMU_HOSTFWD_PORT",
        "volumes": {
            "boot": BUILD / "xaios-aarch64.img",
            "initfs": BUILD / "xaios-virtio-test.img",
            "xaifs": BUILD / "xaios-xaifs.img",
            "system": BUILD / "xaios-system.img",
        },
        "app": BUILD / "init" / "clustertest.elf",
    },
    "riscv64": {
        "build": [["./scripts/build-riscv64.sh"],
                  ["./scripts/build-riscv64-image.sh"]],
        "runner_env": {
            "boot": "XAIOS_RISCV64_IMAGE",
            "initfs": "XAIOS_TEST_BLOCK_IMAGE",
            "xaifs": "XAIOS_XAI_FS_IMAGE",
            "system": "XAIOS_SYSTEM_VOLUME_IMAGE",
            "persistent": "XAIOS_PERSISTENT_IMAGE",
        },
        "hostfwd_env": "XAIOS_RISCV64_SSH_PORT",
        "volumes": {
            "boot": BUILD / "xaios-riscv64.img",
            "initfs": BUILD / "xaios-riscv64-initfs.img",
            "xaifs": BUILD / "xaios-xaifs.img",
            "system": BUILD / "xaios-riscv64-system.img",
        },
        "app": BUILD / "riscv64-userspace" / "clustertest.elf",
    },
}

REPORT_RE = re.compile(
    r"mesh report node=(\d+) version=(\d+) live=(\d+) total=(\d+) "
    r"quorum=(\d+) reason=(\S+) members=([\d,]+) owners=(\S+)")
LOST_RE = re.compile(
    r"mesh peer-lost node=(\d+) reason=(\w+) silent_for_ms=(\d+) "
    r"deadline_ms=(\d+)")
FOUND_RE = re.compile(r"mesh peer-found node=(\d+)")
START_RE = re.compile(
    r"mesh node=(\d+) of=(\d+) heartbeat_ms=(\d+) silence_deadline_ms=(\d+)"
    r"(?P<mode> mode=hold)?")
LISTEN_RE = re.compile(r"mesh listening port=(\d+)")
DIAL_RE = re.compile(r"mesh dial node=(\d+) port=(\d+) result=(\w+)")
WORST_DIAL_RE = re.compile(r"mesh worst_dial_ms=(\d+) deadline_ms=(\d+)")

FORBIDDEN = (
    "CYAN SCREEN OF DEATH",
    "ERROR: assertion failed",
    "mesh never formed",
    "mesh run limit reached",
    "mesh cluster init failed",
    "mesh could not listen",
    "mesh inbound table full",
    "mesh impossible frame length",
)

# The checks that exist only because a link was cut. With
# XAIOS_CLUSTER_PARTITION_SKIP_CUT=1 every one of these must go red; one that
# stays green is a check that does not depend on a partition, which is the
# failure mode this gate is written to be proof against.
REQUIRED_RED = (
    "symmetric-majority-noticed",
    "symmetric-detected-by-silence",
    "symmetric-detection-not-immediate",
    "symmetric-majority-membership",
    "symmetric-majority-agree",
    "symmetric-reassignment",
    "symmetric-minority-noticed",
    "symmetric-minority-stands-down",
    "symmetric-minority-alive-and-trying",
    "symmetric-no-split-brain",
    "symmetric-no-double-ownership",
    "heal-rejoined",
    "heal-membership",
    "heal-ownership-restored",
    "asymmetric-one-way-silence",
    "asymmetric-relay-directionality",
    "asymmetric-no-double-ownership",
    "heal2-rejoined",
    "heal2-membership",
)


# ------------------------------------------------------------------ parsing


def reports(text: str) -> list[dict[str, object]]:
    found = []
    for node, version, live, total, quorum, reason, members, owners in \
            REPORT_RE.findall(text):
        found.append({
            "node": int(node), "version": int(version), "live": int(live),
            "total": int(total), "quorum": int(quorum), "reason": reason,
            "members": [int(m) for m in members.split(",")],
            "owners": None if owners == "withheld"
            else [int(o) for o in owners.split(",")],
            "owners_raw": owners,
        })
    return found


def last_report(text: str) -> dict[str, object] | None:
    """What this node believed at the end of the window.

    The last one rather than the first: a window opens while the cluster is
    still converging and the interesting statement is the settled one. The
    gate lets a whole periodic interval pass before closing a window, so a
    settled node has said something inside it.
    """
    found = reports(text)
    return found[-1] if found else None


def first_report_with(text: str, **fields: object) -> dict[str, object] | None:
    for entry in reports(text):
        if all(entry[key] == value for key, value in fields.items()):
            return entry
    return None


def lost_events(text: str) -> dict[int, tuple[str, int, int]]:
    """node -> (reason, silent_for_ms, deadline_ms), last one wins."""
    events: dict[int, tuple[str, int, int]] = {}
    for node, reason, silent, deadline in LOST_RE.findall(text):
        events[int(node)] = (reason, int(silent), int(deadline))
    return events


def found_events(text: str) -> set[int]:
    return {int(node) for node in FOUND_RE.findall(text)}


# ----------------------------------------------------------------- analysis
#
# A pure function of evidence, so that --self-test can hand it transcripts of
# runs that never happened and check that each assertion is capable of going
# red. Nothing in here reads a clock, a socket or a file.


def analyse(evidence: dict) -> list[tuple[str, str]]:
    failures: list[tuple[str, str]] = []

    def fail(check: str, message: str) -> None:
        failures.append((check, message))

    config = evidence["config"]
    nodes = evidence["nodes"]
    phases = evidence["phases"]
    deadline_ms = int(config["deadline_ms"])

    def log(node: int) -> str:
        return nodes[str(node)]["log"]

    def window(phase: str, node: int) -> str:
        bounds = phases[phase]["windows"][str(node)]
        return log(node)[bounds[0]:bounds[1]]

    # ---- the machines are the machines they were built to be
    for node in NODES:
        console = log(node)
        for banned in FORBIDDEN:
            if banned in console:
                fail("console-clean", f"node {node} reported: {banned}")
        start = START_RE.search(console)
        listening = LISTEN_RE.search(console)
        if start is None or listening is None:
            fail("identity", f"node {node} never announced itself")
            continue
        if int(start.group(1)) != node or int(start.group(2)) != 3:
            fail("identity",
                 f"node {node} announced itself as node {start.group(1)} of "
                 f"{start.group(2)}")
        if start.group("mode") is None:
            # Without the hold this node leaves the moment it loses quorum,
            # taking the heal half of the run with it and failing in a way
            # that reads like a cluster that would not reconverge.
            fail("identity",
                 f"node {node} was not built to hold through a minority")
        if int(listening.group(1)) != config["guest_port"][str(node)]:
            fail("identity",
                 f"node {node} listened on {listening.group(1)} rather than "
                 f"{config['guest_port'][str(node)]}")

        # Every peer must be dialled through this pair's relay listener and
        # nowhere else. A node that reached its peer directly would be
        # unaffected by any cut, and every partition check below would be
        # measuring a fault that was never injected.
        dialled: dict[int, set[int]] = {}
        for peer, port, _result in DIAL_RE.findall(console):
            dialled.setdefault(int(peer), set()).add(int(port))
        for peer in NODES:
            if peer == node:
                continue
            expected = config["relay_port"][f"{node}->{peer}"]
            seen = dialled.get(peer, set())
            if not seen:
                fail("dial-through-relay",
                     f"node {node} never dialled node {peer} at all")
            elif seen != {expected}:
                fail("dial-through-relay",
                     f"node {node} dialled node {peer} on ports "
                     f"{sorted(seen)} rather than only the relay's "
                     f"{expected}: traffic that does not pass the relay "
                     f"cannot be partitioned by it")

    # ---- formation: one cluster, one ownership map, and something to move
    formed = {node: first_report_with(log(node), reason="formed")
              for node in NODES}
    if any(formed[node] is None for node in NODES):
        fail("formed",
             "not every machine reported a three-node membership: "
             + ", ".join(str(n) for n in NODES if formed[n] is None))
        before = None
    else:
        for node in NODES:
            entry = formed[node]
            if entry["members"] != [1, 2, 3] or entry["quorum"] != 1 or \
                    entry["total"] != 3 or entry["live"] != 3:
                fail("formed",
                     f"node {node}'s formed report is not a whole cluster: "
                     f"{entry}")
        maps = [formed[node]["owners"] for node in NODES]
        if maps[0] is None or maps[1] != maps[0] or maps[2] != maps[0]:
            fail("formed-agreement",
                 f"the three machines disagreed about who owns what while "
                 f"all three were online: {maps}")
            before = None
        else:
            before = maps[0]
            if 3 not in before:
                # Without this the reassignment check proves nothing: if the
                # node that gets cut off owned no experts, nothing has to move
                # and a completely static answer would pass.
                fail("formed-agreement",
                     f"node 3 owned none of the experts before the partition, "
                     f"so cutting it off demonstrates no reassignment: "
                     f"{before}")

    # ---- the quiet window: nobody dies while everybody is healthy
    quiet = phases["quiet"]
    if quiet["exited"]:
        fail("quiet-window",
             f"emulators exited before anything was cut: {quiet['exited']}")
    if any("peer-lost" in window("quiet", node) for node in NODES):
        fail("quiet-window",
             "a node was declared dead while all three were healthy and "
             "connected: the silence deadline fires on time passing rather "
             "than on silence")

    # ---- the symmetric 2-1 partition
    sym = phases["symmetric"]
    majority_lost = {}
    for node in (1, 2):
        majority_lost[node] = lost_events(window("symmetric", node))
    minority_lost = lost_events(window("symmetric", 3))

    for node in (1, 2):
        if 3 not in majority_lost[node]:
            fail("symmetric-majority-noticed",
                 f"node {node} never noticed that node 3 had stopped "
                 f"arriving, although the link between them was cut")
            # Stated here rather than left out, because a check that only
            # runs when a loss happened is a check that passes for free when
            # nothing did -- which is how the three-node gate's first control
            # run came back green while testing nothing.
            fail("symmetric-detected-by-silence",
                 f"node {node} declared no loss at all, so nothing was "
                 f"learned about whether membership moves on silence")
        else:
            reason, silent, node_deadline = majority_lost[node][3]
            if reason != "silence":
                fail("symmetric-detected-by-silence",
                     f"node {node} lost node 3 for reason={reason} rather "
                     f"than silence: membership moved on something other "
                     f"than the absence of frames")
            if silent < node_deadline:
                fail("symmetric-detected-by-silence",
                     f"node {node} declared node 3 gone after {silent}ms of "
                     f"silence, less than its own {node_deadline}ms deadline")
    for peer in (1, 2):
        if peer not in minority_lost:
            fail("symmetric-minority-noticed",
                 f"node 3 never noticed that node {peer} had stopped "
                 f"arriving, although the link between them was cut")

    # The link was reset, not merely quiet: a node that moved membership when
    # its socket died would notice within milliseconds. Membership is supposed
    # to move on silence and on nothing else, so the detection has to have
    # taken most of the deadline.
    floor_s = 0.6 * deadline_ms / 1000.0
    for node, seconds in sorted(sym["detect_seconds"].items()):
        if seconds is None:
            continue
        if seconds < floor_s:
            fail("symmetric-detection-not-immediate",
                 f"node {node} declared its peer gone {seconds:.1f}s after "
                 f"the cut, well inside the {deadline_ms}ms deadline: "
                 f"membership is moving on the socket dying rather than on "
                 f"silence")
    if not any(value is not None for value in sym["detect_seconds"].values()):
        fail("symmetric-detection-not-immediate",
             "no node detected anything after the links were cut, so nothing "
             "was learned about how the detection happened")

    survivors = {node: last_report(window("symmetric", node))
                 for node in (1, 2)}
    minority = last_report(window("symmetric", 3))
    after = None
    majority_view = True
    for node in (1, 2):
        entry = survivors[node]
        if entry is None:
            majority_view = False
            fail("symmetric-majority-membership",
                 f"node {node} said nothing at all during the partition")
        elif entry["members"] != [1, 2] or entry["quorum"] != 1 or \
                entry["live"] != 2 or entry["total"] != 3:
            majority_view = False
            fail("symmetric-majority-membership",
                 f"node {node}'s settled view during the partition is not a "
                 f"two-of-three majority: {entry}")
    if not majority_view:
        # The agreement check is about two nodes that have each survived the
        # partition agreeing with each other. Two nodes that never noticed a
        # partition also agree, and reporting that as a pass would be the
        # check passing for free.
        fail("symmetric-majority-agree",
             "there was no majority side that had noticed the partition, so "
             "its two members agreeing about ownership says nothing")
    elif survivors[1]["owners"] != survivors[2]["owners"]:
        fail("symmetric-majority-agree",
             f"the majority disagreed about who owns what: "
             f"{survivors[1]['owners']} against {survivors[2]['owners']}")
    elif survivors[1]["owners"] is None:
        fail("symmetric-majority-agree",
             "the majority withheld ownership although it had quorum: a "
             "two-of-three side that will not decide is a cluster that "
             "stops serving on any single failure")
    else:
        after = survivors[1]["owners"]

    if before is None or after is None:
        fail("symmetric-reassignment",
             "ownership could not be compared across the partition")
    elif len(before) != len(after):
        fail("symmetric-reassignment",
             f"the ownership maps are different lengths: {before} against "
             f"{after}")
    else:
        moved = 0
        for index, owner in enumerate(before):
            if after[index] == 3:
                fail("symmetric-reassignment",
                     f"expert {index} is still owned by node 3, which the "
                     f"majority can no longer reach")
            elif owner == 3:
                moved += 1
            elif after[index] != owner:
                fail("symmetric-reassignment",
                     f"expert {index} moved from node {owner} to node "
                     f"{after[index]} although neither was cut off: a "
                     f"partition cost the cluster more than the partitioned "
                     f"node's share")
        if moved == 0:
            fail("symmetric-reassignment",
                 "no expert changed owner across the partition, so nothing "
                 "about reassignment was tested")

    if minority is None:
        fail("symmetric-minority-stands-down",
             "node 3 said nothing at all while it was cut off")
    else:
        if minority["members"] != [3] or minority["quorum"] != 0 or \
                minority["live"] != 1:
            fail("symmetric-minority-stands-down",
                 f"node 3's settled view while cut off is not a minority of "
                 f"one: {minority}")
        if minority["owners_raw"] != "withheld":
            fail("symmetric-minority-stands-down",
                 f"node 3 answered ownership without a quorum: "
                 f"{minority['owners_raw']}")

    # The whole distinction this gate exists for. A killed node stops
    # answering and stops sending; a partitioned one keeps sending into a link
    # that goes nowhere. Both facts are needed: that it was still running (it
    # kept reporting) and that it was still trying to reach the others, which
    # is measured at the relay rather than taken from the node's own account
    # of itself.
    minority_reports = [entry for entry in reports(window("symmetric", 3))
                        if entry["reason"] == "periodic"]
    knocking = sum(sym["refused"].get(f"3->{peer}", 0) for peer in (1, 2))
    if not sym["alive"].get("3", False):
        fail("symmetric-minority-alive-and-trying",
             "node 3's emulator was gone during the partition, so this was a "
             "death and not a partition")
    elif not minority_reports:
        fail("symmetric-minority-alive-and-trying",
             "node 3 stopped reporting while cut off, so it cannot be shown "
             "to have been alive and standing down rather than simply gone")
    elif knocking == 0:
        fail("symmetric-minority-alive-and-trying",
             "the relay refused no connection from node 3 while its links "
             "were cut: the minority stopped trying to reach anyone, which "
             "is a death by another name and not the partition being tested")

    # ---- split brain, stated as a conjunction so it cannot pass vacuously
    partitioned = bool(sym["cut_links"])
    views = {node: survivors[node] for node in (1, 2)}
    views[3] = minority
    memberships, conflicts = quorum_conflicts(views)
    if not partitioned:
        fail("symmetric-no-split-brain",
             "no link was cut, so nothing was learned about whether two "
             "sides of a partition can both claim a quorum")
        fail("symmetric-no-double-ownership",
             "no link was cut, so nothing was learned about whether one "
             "expert can end up with two owners")
    else:
        if len(memberships) > 1:
            fail("symmetric-no-split-brain",
                 f"two sides of one partition both claimed quorum, with "
                 f"different memberships: {memberships}")
        for message in conflicts:
            fail("symmetric-no-double-ownership", message)

    # ---- the two heals
    #
    # A heal is a transition, not a state. Every node reporting a whole
    # cluster is also true of a cluster that was never broken, so what is
    # required is that each node actually FOUND the peer it had lost inside
    # this window -- and the state checks say so as a conjunct rather than
    # running only when it happened.
    for name, expect_found in (("heal", {1: {3}, 2: {3}, 3: {1, 2}}),
                               ("heal2", {1: {3}, 2: {3}, 3: set()})):
        rejoined = True
        for node in NODES:
            missing = expect_found[node] - found_events(window(name, node))
            if missing:
                rejoined = False
                fail(f"{name}-rejoined",
                     f"node {node} never found node(s) {sorted(missing)} "
                     f"again after the links were repaired")
        settled = {node: last_report(window(name, node)) for node in NODES}
        if not rejoined:
            fail(f"{name}-membership",
                 "no node rejoined anything in this window, so a whole "
                 "cluster here is a cluster that was never divided rather "
                 "than one that reconverged")
            fail("heal-ownership-restored",
                 "nothing reconverged, so nothing was learned about whether "
                 "the ownership map comes back to what it was")
        for node in NODES:
            entry = settled[node]
            if entry is None:
                fail(f"{name}-membership",
                     f"node {node} said nothing after the heal")
            elif entry["members"] != [1, 2, 3] or entry["live"] != 3 or \
                    entry["quorum"] != 1:
                fail(f"{name}-membership",
                     f"node {node} did not converge back on the whole "
                     f"cluster: {entry}")
        maps = [settled[node]["owners"] if settled[node] else None
                for node in NODES]
        if rejoined and all(entry is not None for entry in maps):
            if maps[0] != maps[1] or maps[1] != maps[2]:
                fail(f"{name}-membership",
                     f"the healed cluster does not agree on ownership: "
                     f"{maps}")
            elif before is not None and maps[0] != before:
                # The assignment is a hash of identity against membership, so
                # the same membership must produce the same map. A different
                # one means something remembered the outage, and two nodes
                # that remembered different things would diverge silently.
                fail("heal-ownership-restored",
                     f"the healed cluster's ownership is not the ownership "
                     f"it had before the partition: {maps[0]} against "
                     f"{before}")

    # ---- the asymmetric partition
    asym = phases["asymmetric"]
    asym_lost = {node: lost_events(window("asymmetric", node))
                 for node in NODES}
    one_way = True
    for node in (1, 2):
        if 3 not in asym_lost[node]:
            one_way = False
            fail("asymmetric-one-way-silence",
                 f"node {node} went on hearing node 3 although node 3's "
                 f"outbound links were cut")
    if asym_lost[3]:
        one_way = False
        fail("asymmetric-one-way-silence",
             f"node 3 lost peers {sorted(asym_lost[3])} although only its "
             f"OUTBOUND links were cut: the fault was not asymmetric, so "
             f"nothing here is about asymmetry")

    # The relay's own account of the same claim, which does not depend on the
    # guests being honest: bytes kept crossing towards node 3 and stopped
    # crossing away from it.
    inbound = sum(asym["bytes"].get(f"{peer}->3", 0) for peer in (1, 2))
    outbound = sum(asym["bytes"].get(f"3->{peer}", 0) for peer in (1, 2))
    if outbound != 0:
        fail("asymmetric-relay-directionality",
             f"{outbound} bytes crossed node 3's outbound links while they "
             f"were cut")
    if inbound == 0:
        fail("asymmetric-relay-directionality",
             "no bytes crossed towards node 3 during the asymmetric "
             "partition, so its links were down in both directions and this "
             "phase tested the symmetric case again")

    asym_views = {node: last_report(window("asymmetric", node))
                  for node in NODES}
    asym_memberships, asym_conflicts = quorum_conflicts(asym_views)
    if not asym["cut_links"]:
        fail("asymmetric-no-double-ownership",
             "no link was cut, so nothing was learned about a node that is "
             "heard by nobody and hears everybody")
    else:
        if len(asym_memberships) > 1:
            fail("asymmetric-no-double-ownership",
                 f"a node that nobody could hear went on claiming quorum "
                 f"while the majority had already excluded it: two "
                 f"memberships both deciding at once: {asym_memberships}")
        for message in asym_conflicts:
            fail("asymmetric-no-double-ownership", message)
        if not one_way:
            fail("asymmetric-no-double-ownership",
                 "the fault was not one-way, so a node heard by nobody and "
                 "hearing everybody was never actually produced and nothing "
                 "was learned about what it would do")

    # ---- the margin that makes the deadline safe
    for node in NODES:
        dials = WORST_DIAL_RE.findall(log(node))
        if not dials:
            fail("dial-margin", f"node {node} never reported its worst dial")
            continue
        worst, node_deadline = (int(value) for value in dials[-1])
        if worst * 2 >= node_deadline:
            fail("dial-margin",
                 f"the worst dial on node {node} took {worst}ms against a "
                 f"{node_deadline}ms deadline: a stall that long starves the "
                 f"heartbeats this node owes the peers it can still reach")

    return failures


def quorum_conflicts(views: dict[int, dict | None]
                     ) -> tuple[list[list[int]], list[str]]:
    """What the nodes claiming a quorum disagree about.

    Two returns, because there are two different harms. The first is two
    quorum-holding nodes with different memberships: each is acting for a
    cluster the other does not believe in. The second is the harm that
    actually reaches a user -- two quorum-holding nodes naming different
    owners for the same expert, which means that expert has two owners, work
    is done twice, and nobody reconciles the results.

    A node without quorum is excluded, which is the entire practical content
    of withholding: it has an opinion and it is not acting on it.
    """
    holders = {node: entry for node, entry in views.items()
               if entry is not None and entry["quorum"] == 1}
    memberships: list[list[int]] = []
    for entry in holders.values():
        if entry["members"] not in memberships:
            memberships.append(entry["members"])
    conflicts: list[str] = []
    owners = {node: entry["owners"] for node, entry in holders.items()
              if entry["owners"] is not None}
    ordered = sorted(owners)
    for left_index, left in enumerate(ordered):
        for right in ordered[left_index + 1:]:
            for expert, (a, b) in enumerate(zip(owners[left], owners[right])):
                if a != b:
                    conflicts.append(
                        f"expert {expert} is owned by node {a} according to "
                        f"node {left} and by node {b} according to node "
                        f"{right}, and both of them believe they have "
                        f"quorum: one expert with two owners is not an error "
                        f"anybody detects")
    return memberships, conflicts


# ------------------------------------------------------------------ running


def build_node(node: int) -> dict[str, Path]:
    profile = ARCHITECTURES[ARCH]
    environment = dict(os.environ)
    environment["XAIOS_BOOT_VERBOSE"] = "1"
    environment["XAIOS_BOOT_TEST_APPS"] = "1"
    environment["XAIOS_CLUSTER_TEST"] = "1"
    environment["XAIOS_CLUSTER_ROLE_SERVER"] = "0"
    environment["XAIOS_CLUSTER_MESH_NODES"] = "3"
    environment["XAIOS_CLUSTER_MESH_HOLD"] = "1"
    environment["XAIOS_CLUSTER_NODE_ID"] = str(node)
    # This node's own table: its own entry is the port it listens on inside
    # its guest, and every other entry is the relay listener for that ordered
    # pair. The tables therefore differ per node, which is what puts a
    # separately controllable link under every direction of every pair.
    for other in NODES:
        port = GUEST_PORT[node] if other == node else RELAY_PORT[(node, other)]
        environment[f"XAIOS_CLUSTER_MESH_PORT_{other}"] = str(port)
    for command in profile["build"]:
        subprocess.run(command, cwd=ROOT, env=environment, check=True)

    app = profile["app"].read_bytes()
    if b"mesh node=" not in app:
        raise SystemExit(
            f"error: node {node} was built without the three-node mesh; "
            f"XAIOS_CLUSTER_MESH_NODES did not reach the compiler")
    if b"mode=hold" not in app:
        raise SystemExit(
            f"error: node {node} was built without the minority hold; "
            f"XAIOS_CLUSTER_MESH_HOLD did not reach the compiler, and a node "
            f"that exits on losing quorum cannot demonstrate a heal")

    images = {"app": WORK / f"node{node}-clustertest.elf"}
    shutil.copyfile(profile["app"], images["app"])
    for name, source in profile["volumes"].items():
        target = WORK / f"node{node}-{name}.img"
        shutil.copyfile(source, target)
        images[name] = target
    images["persistent"] = WORK / f"node{node}-persistent.img"
    images["persistent"].unlink(missing_ok=True)
    images["log"] = WORK / f"node{node}.log"
    return images


def launch(node: int, images: dict[str, Path]) -> subprocess.Popen:
    profile = ARCHITECTURES[ARCH]
    environment = dict(os.environ)
    for name, variable in profile["runner_env"].items():
        environment[variable] = str(images[name])
    environment[profile["hostfwd_env"]] = "none"
    environment["XAIOS_RISCV64_STATE"] = str(images["log"].with_suffix(".state"))
    environment["XAIOS_RISCV64_SERIAL"] = "stdio"
    # The emulator's forward is the relay's target, and no guest knows this
    # number: the only route to this machine is through a relay listener.
    environment["XAIOS_QEMU_CLUSTER_HOSTFWD_PORT"] = str(BACK_PORT[node])
    environment["XAIOS_QEMU_CLUSTER_GUEST_PORT"] = str(GUEST_PORT[node])
    images["log"].unlink(missing_ok=True)
    with images["log"].open("wb") as sink:
        return subprocess.Popen(
            [str(ROOT / qemu_runner(ARCH))],
            cwd=ROOT, env=environment, stdout=sink,
            stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            start_new_session=True)


def text(log: Path) -> str:
    if not log.is_file():
        return ""
    return log.read_bytes().decode("utf-8", "replace")


def stop(process: subprocess.Popen) -> None:
    if process.poll() is None:
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            pass


def port_is_busy(port: int) -> bool:
    result = subprocess.run(
        ["/usr/sbin/lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN"],
        capture_output=True, text=True, check=False)
    return bool(result.stdout.strip())


class Run:
    """The live half: emulators, the relay, and the windows into the logs."""

    def __init__(self) -> None:
        self.images = {node: None for node in NODES}
        self.processes: dict[int, subprocess.Popen] = {}
        self.relay = FaultRelay()
        for a, b in PAIRS:
            self.relay.add_link(a, b, RELAY_PORT[(a, b)], BACK_PORT[b])
        self.phases: dict[str, dict] = {}

    def log(self, node: int) -> str:
        return text(self.images[node]["log"])

    def mark(self) -> dict[str, int]:
        return {str(node): len(self.log(node)) for node in NODES}

    def wait_for_after(self, node: int, offset: int, pattern: str,
                       deadline: float) -> float | None:
        """When this pattern first appeared in this node's log after `offset`.

        Returns the moment it was observed, or None. Polling rather than
        following the file: the emulators write through a pipe into a file and
        a line can be a second old before it lands, which is why the detection
        floor below is a fraction of the deadline and not a tight bound.
        """
        while time.monotonic() < deadline:
            if pattern in self.log(node)[offset:]:
                return time.monotonic()
            time.sleep(0.3)
        return time.monotonic() if pattern in self.log(node)[offset:] else None

    def open_phase(self, name: str) -> dict:
        phase = {
            "windows": {str(node): [len(self.log(node)), None]
                        for node in NODES},
            "cut_links": [],
            "detect_seconds": {},
            "bytes_start": self.relay.bytes_by_link(),
            "refused_start": {key: value["refused_while_cut"]
                              for key, value in self.relay.snapshot().items()},
            "alive": {},
            "exited": [],
        }
        self.phases[name] = phase
        return phase

    def close_phase(self, name: str) -> None:
        phase = self.phases[name]
        for node in NODES:
            phase["windows"][str(node)][1] = len(self.log(node))
            phase["alive"][str(node)] = \
                self.processes[node].poll() is None
            if not phase["alive"][str(node)]:
                phase["exited"].append(node)
        end_bytes = self.relay.bytes_by_link()
        end_refused = {key: value["refused_while_cut"]
                       for key, value in self.relay.snapshot().items()}
        phase["bytes"] = {key: end_bytes[key] - phase["bytes_start"][key]
                          for key in end_bytes}
        phase["refused"] = {key: end_refused[key] - phase["refused_start"][key]
                            for key in end_refused}
        phase["cut_links"] = self.relay.cut_links()

    def evidence(self, deadline_ms: int) -> dict:
        return {
            "config": {
                "arch": ARCH,
                "deadline_ms": deadline_ms,
                "guest_port": {str(node): GUEST_PORT[node] for node in NODES},
                "back_port": {str(node): BACK_PORT[node] for node in NODES},
                "relay_port": {f"{a}->{b}": RELAY_PORT[(a, b)]
                               for a, b in PAIRS},
                "skip_cut": SKIP_CUT,
            },
            "nodes": {str(node): {"log": self.log(node)} for node in NODES},
            "phases": self.phases,
        }


def cut(run: Run, action: str, *args: int) -> list[str]:
    """Inject a fault, unless this is the control run.

    The control does everything else -- the same waits, the same windows, the
    same checks -- and simply never cuts anything. Which is why the cut is
    skipped HERE, at the injection, and nowhere near the checking.
    """
    if SKIP_CUT:
        print(f"cluster-partition: SKIP_CUT set; not applying {action}"
              f"{args}", flush=True)
        return []
    getattr(run.relay, action)(*args)
    return run.relay.cut_links()


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


if __name__ == "__main__":
    raise SystemExit(main())
