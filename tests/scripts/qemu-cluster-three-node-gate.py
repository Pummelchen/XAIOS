#!/usr/bin/env python3
"""Three XAIOS machines, a heartbeat, and two of them killed outright.

`qemu-cluster-two-node-gate` runs two machines that tell each other what they
are doing: a LEAVE takes a node offline and a JOIN brings it back. That is a
real claim about the data plane and it leaves the two things a cluster is
actually judged on untested. A machine that fails does not send a LEAVE -- it
loses power, or panics, or has its network cut, and the only evidence the
survivors get is that nothing arrives any more. And at two nodes there is no
quorum question to ask: a survivor cannot tell a dead peer from a cut wire,
and whatever it decides is as defensible as the other node deciding the
opposite.

So this is three machines, each heartbeating to both others over its own TCP
connection, and no polite departures anywhere in it. The gate kills one
emulator with SIGKILL -- no shutdown, no last frame, the closest thing to
pulling a plug that an emulator offers -- and requires the two survivors to
notice by the deadline running out, to agree on who is left, and to agree on
who owns what now. Then it kills a second one and requires the last machine to
say it has lost quorum and to refuse to answer ownership at all, because
somewhere on the other side of that silence there might be two nodes that can
still see each other, and they are the ones entitled to decide.

What is checked is a relationship between three logs rather than anything one
of them says on its own, which is why the checking is here and not in the
guests. A node that cached its first answer passes the agreement check and
fails the reassignment one; a node that recomputed from a stale membership
fails the stability one; a node that expired peers eagerly fails before the
kill ever happens.

The negative controls this gate carries, and how to run them:

  XAIOS_CLUSTER_THREE_NODE_SKIP_KILL=1
      Everything runs, nothing is killed. The checks all still run, and every
      failure-detection one must then go red -- while the quiet-window check
      must still pass. That pair is what says the detector fires because of
      the kill rather than because time passed. The run exits non-zero either
      way, because this configuration is never a passing gate: failures here
      mean the control worked, and no failures would mean those checks do not
      depend on a node actually failing and are worth nothing. Guarding them
      behind the kill instead -- which the first version of this file did --
      produced a control run that passed while checking nothing.

  XAIOS_CLUSTER_THREE_NODE_QUIET_S=<seconds>
      How long all three must run healthily, after forming, without any node
      declaring any other dead. It defaults to comfortably more than the
      guests' silence deadline, so a detector that fired on a live cluster
      would be caught here rather than mistaken for a pass.

The emulators and the grammar they print live in
`cluster_three_node_harness.py`, which is deliberately the half that does not
decide anything: this file is the half that says what the three logs prove.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "scripts"))

from cluster_three_node_harness import (  # noqa: E402
    ARCH,
    BOOT_TIMEOUT_S,
    DETECT_S,
    DIAL_RE,
    FORBIDDEN,
    LISTEN_RE,
    LOST_RE,
    NODES,
    PORTS,
    QUIET_S,
    REPORT,
    SKIP_KILL,
    START_RE,
    WORK,
    build_node,
    first_report,
    launch,
    port_is_busy,
    stop,
    text,
    wait_for,
)


def main() -> int:
    for node in NODES:
        if port_is_busy(PORTS[node]):
            print(f"cluster-three-node: FAIL host port {PORTS[node]} is "
                  f"already listening; another emulator would silently take "
                  f"this run's forward")
            return 1

    WORK.mkdir(parents=True, exist_ok=True)
    images = {node: build_node(node) for node in NODES}

    failures: list[str] = []

    # Three machines built as the same node would be three copies of one
    # binary. The node id is not a string in the ELF, so this is the artefact
    # check that catches it.
    binaries = {node: images[node]["app"].read_bytes() for node in NODES}
    for left in NODES:
        for right in NODES:
            if left < right and binaries[left] == binaries[right]:
                failures.append(
                    f"nodes {left} and {right} were built from identical "
                    f"binaries, so at least one carries the wrong node id")

    processes: dict[int, subprocess.Popen] = {}
    killed: list[int] = []
    quiet_window_log = ""
    detected_at: dict[int, float] = {}
    try:
        for node in NODES:
            processes[node] = launch(node, images[node])

        # Formation: every machine has to have heard from both others.
        deadline = time.monotonic() + BOOT_TIMEOUT_S
        for node in NODES:
            if not wait_for(images[node]["log"], "reason=formed", deadline,
                            processes[node]):
                failures.append(
                    f"node {node} never formed a three-node membership")
        if failures:
            raise SystemExit(0)

        # The false-positive control, and it runs inside the same boot as
        # everything else: all three are healthy and heartbeating, so for as
        # long as this window lasts nobody may declare anybody dead. A
        # detector with too short a deadline, or one that fires on a timer
        # rather than on silence, is caught here -- before the kill that the
        # rest of the gate is about.
        quiet_until = time.monotonic() + QUIET_S
        while time.monotonic() < quiet_until:
            time.sleep(1.0)
            for node in NODES:
                if processes[node].poll() is not None:
                    failures.append(
                        f"node {node}'s emulator exited during the quiet "
                        f"window, before anything was killed")
        quiet_window_log = "".join(text(images[node]["log"]) for node in NODES)
        if "peer-lost" in quiet_window_log:
            failures.append(
                "a node was declared dead while all three were healthy: the "
                "silence deadline fires on time passing rather than on "
                "silence")

        if SKIP_KILL:
            print("cluster-three-node: XAIOS_CLUSTER_THREE_NODE_SKIP_KILL is "
                  "set; nothing will be killed and the failure-detection "
                  "checks below must go red")
        else:
            # SIGKILL the whole emulator process group: no shutdown, no last
            # frame, no LEAVE. This is the case a LEAVE cannot cover and the
            # one that happens in reality.
            stop(processes[3])
            killed.append(3)
            kill_moment = time.monotonic()
            deadline = kill_moment + DETECT_S
            for node in (1, 2):
                if wait_for(images[node]["log"],
                            "mesh peer-lost node=3 reason=silence", deadline,
                            processes[node]):
                    detected_at[node] = time.monotonic() - kill_moment
                else:
                    failures.append(
                        f"node {node} never noticed that node 3 had stopped "
                        f"answering")
            for node in (1, 2):
                wait_for(images[node]["log"], "live=2", deadline,
                         processes[node])

            # And now the quorum question, which is the one that does not
            # exist at two nodes: take the majority away and the last machine
            # must decline to decide rather than carry on alone.
            stop(processes[2])
            killed.append(2)
            deadline = time.monotonic() + DETECT_S
            if not wait_for(images[1]["log"],
                            "mesh three-node membership passed", deadline,
                            processes[1]):
                failures.append(
                    "the last surviving node never reported losing quorum")
    except SystemExit:
        pass
    finally:
        for node in NODES:
            if node in processes:
                stop(processes[node])

    logs = {node: text(images[node]["log"]) for node in NODES}

    for node in NODES:
        for banned in FORBIDDEN:
            if banned in logs[node]:
                failures.append(f"node {node} reported: {banned}")

    # Each machine has to be the node it was built as, on the port that node
    # owns. Three machines all believing they are node 1 would still form
    # nothing, but they would fail in a way that took an hour to read.
    for node in NODES:
        start = START_RE.search(logs[node])
        listening = LISTEN_RE.search(logs[node])
        if start is None or listening is None:
            failures.append(f"node {node} never announced itself")
            continue
        if int(start.group(1)) != node or int(start.group(2)) != 3:
            failures.append(
                f"node {node} announced itself as node {start.group(1)} of "
                f"{start.group(2)}")
        if int(listening.group(1)) != PORTS[node]:
            failures.append(
                f"node {node} listened on {listening.group(1)} rather than "
                f"{PORTS[node]}")

    formed = {node: first_report(logs[node], 3) for node in NODES}
    ownership: dict[str, object] = {
        "formed": {node: formed[node] for node in NODES}}
    if any(formed[node] is None for node in NODES):
        failures.append(
            "not every machine reported a three-node membership: "
            + ", ".join(str(n) for n in NODES if formed[n] is None))
    else:
        for node in NODES:
            entry = formed[node]
            if entry["members"] != [1, 2, 3] or entry["quorum"] != 1 or \
                    entry["total"] != 3:
                failures.append(
                    f"node {node}'s formed report is not a whole cluster: "
                    f"{entry}")
        owners = [formed[node]["owners"] for node in NODES]
        if owners[0] is None or owners[1] != owners[0] or \
                owners[2] != owners[0]:
            failures.append(
                f"the three machines disagreed about who owns what while all "
                f"three were online: {owners}")
        elif 3 not in owners[0]:
            # Without this the survivor comparison below proves nothing: if
            # the node that dies owned none of the experts, nothing has to
            # move and a completely static answer would pass.
            failures.append(
                f"node 3 owned none of the experts before it was killed, so "
                f"killing it demonstrates no reassignment: {owners[0]}")

    survivor = {node: first_report(logs[node], 2) for node in (1, 2)}
    ownership["survivors"] = survivor
    lost: dict[int, tuple[int, int, int]] = {}
    for node in (1, 2):
        match = LOST_RE.search(logs[node])
        if match is not None and int(match.group(1)) == 3:
            lost[node] = (int(match.group(1)), int(match.group(3)),
                          int(match.group(4)))

    # These run whether or not anything was killed, and that is the whole
    # point of the control: with XAIOS_CLUSTER_THREE_NODE_SKIP_KILL set they
    # must all go red. Guarding them behind the kill -- which is what the
    # first version of this file did -- produced a control run that passed
    # while checking nothing, which is the exact failure this gate is
    # supposed to be proof against.
    if True:
        for node in (1, 2):
            if node not in lost:
                failures.append(
                    f"node {node} never declared node 3 lost to silence")
            elif lost[node][1] < lost[node][2]:
                failures.append(
                    f"node {node} declared node 3 dead after "
                    f"{lost[node][1]}ms of silence, which is less than its "
                    f"own {lost[node][2]}ms deadline")
        if any(survivor[node] is None for node in (1, 2)):
            failures.append(
                "a survivor never reported a two-node membership")
        elif formed[1] is not None and formed[2] is not None:
            for node in (1, 2):
                entry = survivor[node]
                if entry["members"] != [1, 2] or entry["quorum"] != 1:
                    failures.append(
                        f"node {node}'s surviving membership is wrong: "
                        f"{entry}")
            if survivor[1]["owners"] != survivor[2]["owners"]:
                failures.append(
                    f"the survivors disagreed about who owns what: "
                    f"{survivor[1]['owners']} against "
                    f"{survivor[2]['owners']}")
            else:
                before = formed[1]["owners"]
                after = survivor[1]["owners"]
                moved = 0
                if before is None or after is None or len(before) != len(after):
                    failures.append("ownership could not be compared across "
                                    "the failure")
                else:
                    for index, owner in enumerate(before):
                        if after[index] == 3:
                            failures.append(
                                f"expert {index} is still owned by the dead "
                                f"node 3 after the failure")
                        elif owner == 3:
                            moved += 1
                        elif after[index] != owner:
                            failures.append(
                                f"expert {index} moved from node {owner} to "
                                f"node {after[index]} although neither was "
                                f"the node that died")
                    if moved == 0:
                        failures.append(
                            "no expert changed owner across the failure, so "
                            "nothing about reassignment was tested")

        minority = first_report(logs[1], 1)
        ownership["minority"] = minority
        if minority is None:
            failures.append(
                "the last survivor never reported a one-node membership")
        else:
            if minority["quorum"] != 0 or minority["members"] != [1]:
                failures.append(
                    f"the last survivor's report is not a minority: "
                    f"{minority}")
            if minority["owners_raw"] != "withheld":
                failures.append(
                    f"the last survivor answered ownership without a "
                    f"quorum: {minority['owners_raw']}")
        if "mesh three-node membership passed" not in logs[1]:
            failures.append(
                "the last survivor never finished its run")

    # The margin that makes the deadline safe, measured rather than assumed: a
    # dial to a peer that has vanished blocks this node's loop, and a stall as
    # long as the deadline would have each survivor declare the other dead
    # while it was busy dialling the corpse.
    worst_dial = None
    dial = DIAL_RE.search(logs[1])
    if dial is not None:
        worst_dial = {"worst_dial_ms": int(dial.group(1)),
                      "deadline_ms": int(dial.group(2))}
        if worst_dial["worst_dial_ms"] * 2 >= worst_dial["deadline_ms"]:
            failures.append(
                f"the worst dial on the surviving node took "
                f"{worst_dial['worst_dial_ms']}ms against a "
                f"{worst_dial['deadline_ms']}ms deadline: a stall that long "
                f"can starve the heartbeats this node owes its living peers")
    else:
        failures.append("the surviving node never reported its worst dial")

    report = {
        "schema": "xaios.cluster-three-node.v1",
        "arch": ARCH,
        "ports": PORTS,
        "skip_kill": SKIP_KILL,
        "quiet_window_s": QUIET_S,
        "killed": killed,
        "detection_seconds_after_kill": detected_at,
        "peer_lost": {str(k): v for k, v in lost.items()},
        "worst_dial": worst_dial,
        "ownership": ownership,
        "logs": {str(node): str(images[node]["log"].relative_to(ROOT))
                 for node in NODES},
        "failures": failures,
        "passed": not failures,
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    if SKIP_KILL:
        # A control run is never a passing gate. It is red either way, and the
        # two reds mean opposite things: failures here are the control
        # working, and no failures means the checks below the kill do not
        # depend on the kill and are worth nothing.
        for message in failures:
            print(f"cluster-three-node: EXPECTED-FAIL {message}")
        if failures:
            print(f"cluster-three-node: control run: {len(failures)} checks "
                  f"went red with nothing killed, which is what a working "
                  f"control looks like")
            if "peer-lost" in quiet_window_log:
                print("cluster-three-node: but a death was declared during "
                      "the quiet window, so the deadline is firing on time "
                      "passing rather than on silence")
            else:
                print("cluster-three-node: and no node declared any other "
                      "dead while all three were healthy, so the deadline "
                      "fires on silence rather than on time passing")
        else:
            print("cluster-three-node: CONTROL DID NOT WORK: every check "
                  "passed with nothing killed, so none of them depends on a "
                  "node actually failing")
        print(f"cluster-three-node: report={REPORT}")
        return 1
    if failures:
        for message in failures:
            print(f"cluster-three-node: FAIL {message}")
        print(f"cluster-three-node: report={REPORT}")
        return 1
    print("cluster-three-node: three XAIOS machines formed a cluster over "
          "heartbeats; one was killed outright and the survivors detected it "
          "by silence, agreed on the membership left and moved only the dead "
          "node's experts; a second kill left a minority that refused to "
          "decide ownership at all")
    print(f"cluster-three-node: passed report={REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
