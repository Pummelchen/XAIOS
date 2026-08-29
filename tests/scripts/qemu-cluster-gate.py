#!/usr/bin/env python3
"""Carry a sealed cluster frame between two nodes over a real network.

engine/src/cluster.c has had framing, sealing, peer state and owner selection
since it was written, and no transport: nothing in it ever opened a socket. Every
test of it handed a buffer from one function to another inside one process,
which proves the framing and nothing about a cluster -- a cluster is two nodes
or it is not one.

This runs both ends. A peer on the host opens what the guest sends and seals a
reply addressed back to it; the guest opens that and then refuses it a second
time, because a data plane that accepts a replayed frame is worse than one with
no transport at all.

The host peer is written against the format rather than against the
implementation -- an independent reading of the layout in cluster.c -- so the
two agreeing says the wire format is what that file documents, rather than
saying one program can read its own output.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
REPORT = BUILD / "qemu-cluster-gate.json"
PEER_PORT = int(os.environ.get("XAIOS_CLUSTER_PEER_PORT", "7799"))
TIMEOUT_S = int(os.environ.get("XAIOS_CLUSTER_TIMEOUT", "240"))

EXPECTED = (
    ("a frame was sealed",
     re.compile(r"/bin/clustertest: sealed frame bytes=[1-9]\d+")),
    ("the peer opened it and replied",
     re.compile(r"/bin/clustertest: round trip verified bytes=[1-9]\d+ "
                r"opcode=1")),
    ("the data plane passed, replay included",
     re.compile(r"/bin/clustertest: cluster data plane over TCP passed")),
)

FORBIDDEN = (
    ("no peer was reachable",
     re.compile(r"/bin/clustertest: no cluster peer reachable")),
    ("the round trip failed",
     re.compile(r"/bin/clustertest: (?!cluster data plane over TCP\b)"
                r"(?!sealed frame)(?!round trip)[a-z]")),
    ("kernel panic", re.compile(r"CYAN SCREEN OF DEATH")),
)


def fail(message: str) -> int:
    print(f"cluster-gate: {message}")
    return 1


def main() -> int:
    peer_log = BUILD / "cluster-peer.log"
    peer_log.unlink(missing_ok=True)
    with peer_log.open("wb") as handle:
        peer = subprocess.Popen(
            [sys.executable, str(ROOT / "tests/scripts/cluster-peer.py"),
             str(PEER_PORT)],
            cwd=str(ROOT), stdout=handle, stderr=subprocess.STDOUT,
            start_new_session=True)
    # The peer has to be listening before the guest reaches it; a guest that
    # connects first sees a refusal and skips, and the gate would then be
    # measuring a race rather than the data plane.
    time.sleep(2)

    try:
        boot = subprocess.run(["make", "qemu-smoke"], cwd=str(ROOT),
                              stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True,
                              timeout=TIMEOUT_S * 2, check=False)
        text = boot.stdout
    except subprocess.TimeoutExpired as expired:
        text = expired.stdout or ""
        if isinstance(text, bytes):
            text = text.decode("utf-8", "replace")
    finally:
        peer.terminate()
        try:
            peer.wait(timeout=15)
        except subprocess.TimeoutExpired:
            peer.kill()

    peer_text = peer_log.read_text(encoding="utf-8", errors="replace")
    checks = [{"name": n, "passed": bool(p.search(text))} for n, p in EXPECTED]
    # What the other end saw. A guest reporting success while the peer saw
    # nothing would mean the frame never left the machine.
    peer_opened = bool(re.search(r"cluster-peer: opened opcode=1", peer_text))
    peer_replied = bool(re.search(r"cluster-peer: sealed a reply", peer_text))
    checks.append({"name": "the peer verified the guest's frame",
                   "passed": peer_opened})
    checks.append({"name": "the peer sealed a reply", "passed": peer_replied})
    faults = [{"name": n, "seen": bool(p.search(text))}
              for n, p in FORBIDDEN[:1] + FORBIDDEN[2:]]

    passed = all(c["passed"] for c in checks) and \
        not any(f["seen"] for f in faults)
    for check in checks:
        print(f"  {'ok  ' if check['passed'] else 'MISS'} {check['name']}")
    for fault in faults:
        if fault["seen"]:
            print(f"  FAULT {fault['name']}")

    REPORT.write_text(json.dumps({
        "target": "qemu-aarch64-cluster",
        "peer": "host, independent implementation of the wire format",
        "checks": checks,
        "faults": faults,
        "passed": passed,
    }, indent=2) + "\n", encoding="utf-8")
    print(f"cluster-gate: report written to {REPORT}")
    if not passed:
        return fail("the cluster data plane did not complete")
    print("cluster-gate: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
