"""What the cluster-partition gate's evidence proves.

Moved verbatim out of `qemu-cluster-partition-gate.py`. `analyse` is a pure
function of evidence -- no clock, socket or file -- so `--self-test` can hand
it transcripts of runs that never happened and check that each assertion is
capable of going red. The mesh grammar it reads comes from
`cluster_partition_protocol.py`; `REQUIRED_RED` is the list of checks the
control run demands must go red when nothing is cut.
"""

from __future__ import annotations

from cluster_partition_protocol import (  # noqa: E402
    DIAL_RE, FORBIDDEN, LISTEN_RE, NODES, START_RE, WORST_DIAL_RE,
    first_report_with, found_events, last_report, lost_events, reports)


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
