"""The three-node gate's QEMU harness and the mesh grammar it reads.

Moved verbatim out of `qemu-cluster-three-node-gate.py`: the per-architecture
build and run table, the per-node port map, and everything that touches an
emulator -- building a machine's images, starting it, waiting on its log, and
killing it. What the evidence proves stays in the gate, which is the half that
has to be read beside the gate's own account of it.

The grammar and the four process helpers are the same ones the partition gate
already uses: both gates start the same three-node `clustertest` binary and
read the same lines out of it, so `reports`, `text`, `stop`, `port_is_busy`,
the report regexes and `FORBIDDEN` come from `cluster_partition_protocol.py`
rather than being copied a second time. `DIAL_RE` here is that module's
`WORST_DIAL_RE`, under the name this gate has always used for it. `START_RE`
is the shared grammar as well: it carries an optional `mode=hold` tail that
the partition gate reads and this one does not, and the two groups the
three-node gate does read -- node and total -- are unchanged by it.
"""

from __future__ import annotations

import os
import shutil
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
from cluster_partition_protocol import (  # noqa: E402
    FORBIDDEN,
    LISTEN_RE,
    LOST_RE,
    REPORT_RE,
    START_RE,
    WORST_DIAL_RE as DIAL_RE,
    first_report_with,
    port_is_busy,
    reports,
    stop,
    text,
)

ARCH = arch_from_argv(sys.argv)
SUFFIX = "" if ARCH == "aarch64" else f"-{ARCH}"
WORK = BUILD / f"cluster-three-node{SUFFIX}"
REPORT = BUILD / f"qemu-cluster-three-node-gate{SUFFIX}.json"

# Per-machine build and volume layout, taken from the two-node gate: the claim
# is about the implementation rather than the instruction set, so it has to be
# checkable on every board that runs it. What differs per board is the
# builder, the boot medium's name, and which volumes exist.
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

NODES = (1, 2, 3)
# One port per node, on the host and inside its guest alike. A guest reaches a
# peer by dialling the user network's gateway on the peer's port, which the
# peer's emulator forwards inward -- so the two numbers being the same is what
# makes one compile-time table describe both ends. Explicit and unusual,
# because a default port is how two gates running at once produce a guest with
# no console output at all and an emulator that died saying it could not set
# up a host forwarding rule.
DEFAULT_PORTS = {1: 2461, 2: 2462, 3: 2463}
PORTS = {node: int(os.environ.get(f"XAIOS_CLUSTER_MESH_PORT_{node}",
                                  DEFAULT_PORTS[node]))
         for node in NODES}

BOOT_TIMEOUT_S = smoke_timeout(
    ARCH, int(os.environ.get("XAIOS_CLUSTER_THREE_NODE_TIMEOUT", "600")))
# Longer than the guests' silence deadline (20s), so that a run in which
# nothing was killed would have had every chance to declare a healthy peer
# dead. Shortening this weakens the one check that says the detector is not
# simply firing on a timer.
QUIET_S = float(os.environ.get("XAIOS_CLUSTER_THREE_NODE_QUIET_S", "30"))
# How long a survivor is given to notice a silence, after the kill. The guests
# use a twenty second deadline and check it once per tick.
DETECT_S = float(os.environ.get("XAIOS_CLUSTER_THREE_NODE_DETECT_S", "120"))
SKIP_KILL = os.environ.get("XAIOS_CLUSTER_THREE_NODE_SKIP_KILL", "0") == "1"


def build_node(node: int) -> dict[str, Path]:
    """Build one machine's images and set them aside.

    /bin is read from the initial filesystem volume rather than the boot
    image, so every volume is copied per node. Preserving only the boot image
    is how the two-node gate once produced a 'server' that dialled.
    """
    profile = ARCHITECTURES[ARCH]
    environment = dict(os.environ)
    environment["XAIOS_BOOT_VERBOSE"] = "1"
    environment["XAIOS_BOOT_TEST_APPS"] = "1"
    environment["XAIOS_CLUSTER_TEST"] = "1"
    environment["XAIOS_CLUSTER_ROLE_SERVER"] = "0"
    environment["XAIOS_CLUSTER_MESH_NODES"] = "3"
    environment["XAIOS_CLUSTER_NODE_ID"] = str(node)
    for other in NODES:
        environment[f"XAIOS_CLUSTER_MESH_PORT_{other}"] = str(PORTS[other])
    for command in profile["build"]:
        subprocess.run(command, cwd=ROOT, env=environment, check=True)

    # The mode is a compile-time choice, so look at what was built rather than
    # trust that the variable reached the compiler. The node id cannot be
    # grepped for -- it is an immediate in the code, not a string -- so it is
    # checked at run time against what the machine says about itself, and the
    # images are compared with each other below, where three identical
    # binaries would mean three machines built as the same node.
    app = profile["app"].read_bytes()
    if b"mesh node=" not in app:
        raise SystemExit(
            f"error: node {node} was built without the three-node mesh; "
            f"XAIOS_CLUSTER_MESH_NODES did not reach the compiler")

    images = {"app": WORK / f"node{node}-clustertest.elf"}
    shutil.copyfile(profile["app"], images["app"])
    for name, source in profile["volumes"].items():
        target = WORK / f"node{node}-{name}.img"
        shutil.copyfile(source, target)
        images[name] = target
    # The runner creates persistent volumes fresh; a stale one from another
    # build fails sshd provisioning.
    images["persistent"] = WORK / f"node{node}-persistent.img"
    images["persistent"].unlink(missing_ok=True)
    images["log"] = WORK / f"node{node}.log"
    return images


def launch(node: int, images: dict[str, Path]) -> subprocess.Popen:
    profile = ARCHITECTURES[ARCH]
    environment = dict(os.environ)
    for name, variable in profile["runner_env"].items():
        environment[variable] = str(images[name])
    # No ssh anywhere: three machines sharing one default ssh port is a
    # collision, and a collision here is an emulator that never boots.
    environment[profile["hostfwd_env"]] = "none"
    environment["XAIOS_RISCV64_STATE"] = str(images["log"].with_suffix(".state"))
    environment["XAIOS_RISCV64_SERIAL"] = "stdio"
    # This node's own listener, reachable from the host so the other two
    # guests can reach it through their own user networks.
    environment["XAIOS_QEMU_CLUSTER_HOSTFWD_PORT"] = str(PORTS[node])
    environment["XAIOS_QEMU_CLUSTER_GUEST_PORT"] = str(PORTS[node])
    images["log"].unlink(missing_ok=True)
    with images["log"].open("wb") as sink:
        return subprocess.Popen(
            [str(ROOT / qemu_runner(ARCH))],
            cwd=ROOT, env=environment, stdout=sink,
            stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            start_new_session=True)


def wait_for(log: Path, pattern: str, deadline: float,
             process: subprocess.Popen) -> bool:
    while time.monotonic() < deadline:
        if pattern in text(log):
            return True
        if process.poll() is not None:
            return pattern in text(log)
        time.sleep(0.3)
    return pattern in text(log)


def first_report(log: str, live: int) -> dict[str, object] | None:
    return first_report_with(log, live=live)
