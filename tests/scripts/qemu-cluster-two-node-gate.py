#!/usr/bin/env python3
"""Two XAIOS machines, one listening and one dialling, exchanging a sealed frame.

`qemu-cluster-gate` proves the wire format against an independent reading of
it: XAIOS seals, a Python peer written from the header layout opens, and the
two agreeing says the format is what `cluster.c` documents. That is a real
claim and it is not this one.

This is XAIOS on both ends. One machine listens, the other dials, and the frame
that crosses is sealed and opened by the same implementation on two separate
machines with a network between them -- which is what a cluster is, and what
"the peer is a host process rather than a second XAIOS machine" was recorded
against.

The two images are the same source built with XAIOS_CLUSTER_ROLE_SERVER set or
not. Each guest gets its own copy of every volume: two emulators cannot open
one disk image, and discovering that as a mid-run failure wastes a boot.
"""

from __future__ import annotations

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
WORK = BUILD / "cluster-two-node"
REPORT = BUILD / "qemu-cluster-two-node-gate.json"
CLUSTER_PORT = int(os.environ.get("XAIOS_CLUSTER_PEER_PORT", "7799"))
BOOT_TIMEOUT_S = int(os.environ.get("XAIOS_CLUSTER_TWO_NODE_TIMEOUT", "600"))
# The node ids clustertest.c gives each role.
SERVER_NODE_ID = 2
CLIENT_NODE_ID = 1

# What each end has to say. The server's lines are the ones that could not be
# produced by the old host-process peer, so they are the evidence that the
# thing on the other end was XAIOS.
SERVER_MARKERS = (
    "/bin/clustertest: listening port=",
    "/bin/clustertest: opened peer frame bytes=",
    "/bin/clustertest: sealed reply bytes=",
    "/bin/clustertest: cluster data plane over TCP passed",
    "/bin/clustertest: membership join/partition/recovery passed",
)
CLIENT_MARKERS = (
    "/bin/clustertest: sealed frame bytes=",
    "/bin/clustertest: round trip verified bytes=",
    "/bin/clustertest: cluster data plane over TCP passed",
    "/bin/clustertest: membership join/partition/recovery passed",
)

# The membership half. Each end logs the owner of one fixed expert at three
# points, and what has to hold is a relationship between the two logs rather
# than anything either one says alone -- which is why it is checked here and
# not inside the guests.
OWNERSHIP = re.compile(
    r"/bin/clustertest: ownership phase=(\w+) version=(\d+) owner=(\d+) "
    r"peer_online=(\d+)")
FORBIDDEN = (
    "/bin/clustertest: no cluster peer",
    "CYAN SCREEN OF DEATH",
    "ERROR: assertion failed",
)


def build_role(server: bool) -> dict[str, Path]:
    """Build one end and set its images aside.

    /bin does not live in the boot image -- it is read from the initial
    filesystem volume -- so preserving only the boot image gives two machines
    that boot differently and run the same applications. That is exactly how
    the first attempt at this produced a 'server' that dialled.
    """
    label = "server" if server else "client"
    environment = dict(os.environ)
    environment["XAIOS_BOOT_VERBOSE"] = "1"
    environment["XAIOS_BOOT_TEST_APPS"] = "1"
    environment["XAIOS_CLUSTER_TEST"] = "1"
    environment["XAIOS_CLUSTER_ROLE_SERVER"] = "1" if server else "0"
    subprocess.run(["./scripts/build-image.sh"], cwd=ROOT, env=environment,
                   check=True)

    # The role is a compile-time choice, so check the artefact rather than
    # trusting that the variable reached the compiler.
    app = (BUILD / "init" / "clustertest.elf").read_bytes()
    listens = b"listening port=" in app
    if listens != server:
        raise SystemExit(
            f"error: the {label} image was built with the wrong role "
            f"(listening={listens}, expected {server})")

    images = {}
    for name, source in (
        ("boot", BUILD / "xaios-aarch64.img"),
        ("initfs", BUILD / "xaios-virtio-test.img"),
        ("xaifs", BUILD / "xaios-xaifs.img"),
        ("system", BUILD / "xaios-system.img"),
    ):
        target = WORK / f"{label}-{name}.img"
        shutil.copyfile(source, target)
        images[name] = target
    # Persistent volumes are created fresh by the runner; a stale one from
    # another build fails sshd provisioning.
    images["persistent"] = WORK / f"{label}-persistent.img"
    images["persistent"].unlink(missing_ok=True)
    images["log"] = WORK / f"{label}.log"
    return images


def launch(images: dict[str, Path], serve: bool) -> subprocess.Popen:
    environment = dict(os.environ)
    environment.update({
        "XAIOS_AARCH64_IMAGE": str(images["boot"]),
        "XAIOS_TEST_BLOCK_IMAGE": str(images["initfs"]),
        "XAIOS_XAI_FS_IMAGE": str(images["xaifs"]),
        "XAIOS_SYSTEM_VOLUME_IMAGE": str(images["system"]),
        "XAIOS_PERSISTENT_IMAGE": str(images["persistent"]),
        # Neither end needs ssh, and a fixed host port is how one stale
        # emulator anywhere turns a run into a boot that never happened.
        "XAIOS_QEMU_HOSTFWD_PORT": "none",
    })
    if serve:
        # The listener's port has to leave the guest, which is the whole
        # difference between a peer on this machine and a peer on another.
        environment["XAIOS_QEMU_CLUSTER_HOSTFWD_PORT"] = str(CLUSTER_PORT)
        environment["XAIOS_QEMU_CLUSTER_GUEST_PORT"] = str(CLUSTER_PORT)
    images["log"].unlink(missing_ok=True)
    with images["log"].open("wb") as sink:
        return subprocess.Popen(
            [str(ROOT / "platform/qemu/run-qemu-aarch64.sh")],
            cwd=ROOT, env=environment, stdout=sink,
            stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            start_new_session=True)


def wait_for(log: Path, marker: str, deadline: float,
             process: subprocess.Popen) -> bool:
    while time.monotonic() < deadline:
        if log.is_file() and marker.encode() in log.read_bytes():
            return True
        if process.poll() is not None:
            return log.is_file() and marker.encode() in log.read_bytes()
        time.sleep(0.2)
    return False


def stop(process: subprocess.Popen) -> None:
    if process.poll() is None:
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        process.wait(timeout=30)


def main() -> int:
    WORK.mkdir(parents=True, exist_ok=True)
    server_images = build_role(server=True)
    client_images = build_role(server=False)

    failures: list[str] = []
    server = launch(server_images, serve=True)
    client = None
    try:
        deadline = time.monotonic() + BOOT_TIMEOUT_S
        if not wait_for(server_images["log"],
                        "/bin/clustertest: listening port=", deadline, server):
            failures.append("the listening machine never reached its listener")
        else:
            client = launch(client_images, serve=False)
            deadline = time.monotonic() + BOOT_TIMEOUT_S
            wait_for(client_images["log"],
                     "/bin/clustertest: cluster data plane over TCP passed",
                     deadline, client)
            # The reply is sent before the client finishes, so by the time the
            # client has passed the server has said everything it will say.
            wait_for(server_images["log"],
                     "/bin/clustertest: cluster data plane over TCP passed",
                     time.monotonic() + 60, server)
    finally:
        if client is not None:
            stop(client)
        stop(server)

    server_log = server_images["log"].read_bytes()
    client_log = client_images["log"].read_bytes() if \
        client_images["log"].is_file() else b""
    for marker in SERVER_MARKERS:
        if marker.encode() not in server_log:
            failures.append(f"the listening machine never said: {marker}")
    for marker in CLIENT_MARKERS:
        if marker.encode() not in client_log:
            failures.append(f"the dialling machine never said: {marker}")
    for banned in FORBIDDEN:
        if banned.encode() in server_log:
            failures.append(f"the listening machine reported: {banned}")
        if banned.encode() in client_log:
            failures.append(f"the dialling machine reported: {banned}")

    # Ownership, compared across the two machines. Neither log can be judged
    # on its own: the claim is that two independent nodes name the same owner
    # while both are online, each names itself while partitioned, and the
    # original answer returns when the peer does. A node that simply cached
    # its first answer would satisfy the first and third and fail the second;
    # one that recomputed from a stale membership would fail the third.
    def phases(log: bytes) -> dict[str, dict[str, int]]:
        found: dict[str, dict[str, int]] = {}
        for phase, version, owner, online in OWNERSHIP.findall(
                log.decode("utf-8", "replace")):
            found[phase] = {"version": int(version), "owner": int(owner),
                            "online": int(online)}
        return found

    server_phases = phases(server_log)
    client_phases = phases(client_log)
    ownership = {"server": server_phases, "client": client_phases}
    for name, seen in (("listening", server_phases), ("dialling",
                                                      client_phases)):
        missing = [p for p in ("joined", "partitioned", "recovered")
                   if p not in seen]
        if missing:
            failures.append(
                f"the {name} machine never reported ownership for {missing}")
    if not [f for f in failures if "ownership" in f]:
        if server_phases["joined"]["owner"] != client_phases["joined"]["owner"]:
            failures.append(
                f"the two machines disagreed about who owns the expert while "
                f"both were online: listening said "
                f"{server_phases['joined']['owner']}, dialling said "
                f"{client_phases['joined']['owner']}")
        if server_phases["partitioned"]["owner"] != SERVER_NODE_ID:
            failures.append(
                f"the listening machine did not take ownership when "
                f"partitioned; it named "
                f"{server_phases['partitioned']['owner']}")
        if client_phases["partitioned"]["owner"] != CLIENT_NODE_ID:
            failures.append(
                f"the dialling machine did not take ownership when "
                f"partitioned; it named "
                f"{client_phases['partitioned']['owner']}")
        for name, seen in (("listening", server_phases),
                           ("dialling", client_phases)):
            if seen["partitioned"]["online"] != 0:
                failures.append(
                    f"the {name} machine still called the peer online while "
                    f"partitioned")
            if seen["recovered"]["owner"] != seen["joined"]["owner"]:
                failures.append(
                    f"the {name} machine did not restore the original owner "
                    f"after the peer returned: {seen['joined']['owner']} "
                    f"became {seen['recovered']['owner']}")
            if not (seen["joined"]["version"] < seen["partitioned"]["version"]
                    < seen["recovered"]["version"]):
                failures.append(
                    f"the {name} machine's ownership version did not advance "
                    f"across the three phases: {seen}")

    report = {
        "schema": "xaios.cluster-two-node.v1",
        "cluster_port": CLUSTER_PORT,
        "server_log": str(server_images["log"].relative_to(ROOT)),
        "client_log": str(client_images["log"].relative_to(ROOT)),
        "ownership": ownership,
        "failures": failures,
        "passed": not failures,
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")

    if failures:
        for message in failures:
            print(f"cluster-two-node: FAIL {message}")
        return 1
    print("cluster-two-node: a sealed frame crossed between two XAIOS "
          "machines, was opened and verified by the far end, answered, and "
          "the answer verified back")
    print(f"cluster-two-node: passed report={REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
