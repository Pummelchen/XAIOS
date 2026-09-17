"""The cluster-partition gate's mesh protocol and its live run harness.

Moved verbatim out of `qemu-cluster-partition-gate.py` so that neither file
has to carry the whole thing. This half is everything that touches a machine
or the wire: the report grammar the guests print, the host and guest port map,
the per-architecture build/run table, and the emulator-and-relay harness that
starts the three machines and opens windows into their logs.

`analyse` -- what the evidence proves -- lives in
`cluster_partition_analysis.py` and reads the grammar from here.
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

from qemu_gate_lib import (  # noqa: E402
    BUILD,
    ROOT,
    arch_from_argv,
    qemu_runner,
    smoke_timeout,
)
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
