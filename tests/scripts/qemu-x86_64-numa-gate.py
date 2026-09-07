#!/usr/bin/env python3
"""Validate XAIOS ACPI NUMA discovery, placement policy and allocation under QEMU TCG.

Two boots, because two nodes cannot show everything this row claims:

  two-node   SRAT, SLIT and HMAT together, HMAT's preferred-node choice, the
             usable-memory intersection, node-local allocation, local/remote
             byte accounting, the scheduler's node split, node-aware core
             leasing and the spill, and stealing that stops at the node.
  four-node  the SLIT on its own, with no HMAT at all. Distances describe a
             line, so the fallback order from node 3 is 3,2,1,0 -- the exact
             reverse of the node-id order the allocator used to walk, and the
             only arrangement here that can tell the two apart. From node 2 it
             is 2,1,3,0, where a tie at distance 20 is broken by the lower node
             id, which is what makes two boots of one machine choose alike.

Neither boot is evidence about speed. Under TCG a remote access costs what a
local one costs, so everything here is about which node the kernel chose and
nothing here is a latency or bandwidth claim.
"""

from __future__ import annotations

import os
import select
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

TWO_NODE_MARKERS = (
    "NUMA: ACPI topology nodes=2",
    "hmat_structures=2",
    "NUMA: HMAT initiator=0 preferred=0 valid=1 latency_ps=10000 bandwidth_Bps=21474836480",
    "NUMA: HMAT initiator=1 preferred=1 valid=1 latency_ps=10000 bandwidth_Bps=21474836480",
    "VMM: x86 1 GiB page and SMP address-specific invalidation self-test passed",
    "NUMA: self-test passed nodes=2",
    "ownership=verified local_bytes=64 remote_bytes=128",
    # Both nodes own CPUs. Nothing checked this before, and the way the SRAT
    # walk fails is silent: with no processor affinity matched, every CPU stays
    # on node 0 and every other assertion still holds.
    "NUMA: node=0 domain=0 cpus=2",
    "NUMA: node=1 domain=1 cpus=2",
    # The fallback order printed in full, from the node where node-id order and
    # distance order disagree.
    "fallback_order=1,0",
    # Placement accounting moved for a real allocation, on the correct side of
    # the ledger, in both directions.
    "NUMA: placement accounting cpu=0 local_node=0 far_node=1 local_delta=4096 remote_delta=4096 verified=1",
    # The scheduler's view of the machine agrees with the SRAT rather than
    # answering "node 0" for every CPU, and two nodes mean two level-2 domains.
    "topology: numa split verified cpu0 node=0",
    "numa_nodes_with_cpus=2",
    # A lease asked for by node lands on that node, fills it before spilling,
    # and spills to the node the SLIT calls nearest.
    "core-lease: owner=200 node=1 cpus=1 on_node=1 first_cpu=2 node_aware=1",
    "core-lease: node-aware spill node=1 filled=2 spill_node=0 spill_distance=20",
    "core-lease: node-aware selection self-test passed nodes=2 target_node=1 leasable_on_target=2 leasable_total=3",
    # Work is stolen from a CPU on the stealer's own node and left where it is
    # on a CPU that is not.
    "scheduler: numa steal self-test passed cpu=0 node=0 local_victim=1 stole=9004 remote_victim=2 stole=0",
)

FOUR_NODE_MARKERS = (
    "NUMA: ACPI topology nodes=4",
    # No HMAT: the metrics are absent and every node reports itself preferred,
    # which is what a machine without HMAT must produce rather than a crash or
    # a silent claim that some other node is nearer.
    "hmat_structures=0",
    "NUMA: HMAT initiator=3 preferred=3 valid=0 latency_ps=0 bandwidth_Bps=0",
    # The ordering, and not the page count beside it.
    #
    # These were pinned whole, including pages=126824 and pages=122261 on the
    # two nodes the kernel image and its early tables come out of. That figure
    # moves by a page or two whenever anything in the kernel changes size, and
    # it did: a change to the RISC-V MMU -- which this x86_64 gate has no
    # business caring about -- shifted it by one and failed the gate. The
    # figure under test is fallback_order, which is what the SLIT ordering
    # produces; the page count is incidental to it. Nodes 1 and 2 hold whole
    # 512 MiB regions and are stable, but they are matched the same way rather
    # than relying on that.
    "NUMA: node=0 domain=0 cpus=1 pages=",
    "fallback_order=0,1,2,3",
    "NUMA: node=1 domain=1 cpus=1 pages=",
    "fallback_order=1,0,2,3",
    "NUMA: node=2 domain=2 cpus=1 pages=",
    "fallback_order=2,1,3,0",
    "NUMA: node=3 domain=3 cpus=1 pages=",
    "fallback_order=3,2,1,0",
    "NUMA: self-test passed nodes=4",
    "topology: self-test passed domains=13 online=4 numa_nodes_with_cpus=4",
    # One leasable CPU per node, so the requested node is filled and the spill
    # goes to a neighbour at distance 20 rather than to node 0.
    "core-lease: owner=200 node=2 cpus=1 on_node=1 first_cpu=2 node_aware=1",
    "core-lease: node-aware spill node=2 filled=1 spill_node=1 spill_distance=20",
    "core-lease: node-aware selection self-test passed nodes=4 target_node=2 leasable_on_target=1 leasable_total=3",
    # One CPU per node means the boot CPU has no same-node neighbour, so the
    # steal test has no case to run. It has to say so: a check that skips
    # silently is indistinguishable from a check that passed.
    "scheduler: numa steal self-test skipped local_victim=4294967295 remote_victim=1",
)

SOURCES = {
    "XAIOS_X86_64_IMAGE": ROOT / "build/xaios-x86_64.img",
    "XAIOS_X86_TEST_BLOCK_IMAGE": ROOT / "build/xaios-x86-virtio-test.img",
    "XAIOS_X86_PERSISTENT_IMAGE": ROOT / "build/xaios-x86-persistent.img",
    "XAIOS_XAI_FS_IMAGE": ROOT / "build/xaios-x86-xaifs.img",
    "XAIOS_SYSTEM_VOLUME_IMAGE": ROOT / "build/xaios-x86-system.img",
    "XAIOS_X86_STORAGE_ADMIN_IMAGE": ROOT / "build/xaios-x86-storage-admin.img",
}


def run_profile(profile: str, markers: "tuple[str, ...]") -> None:
    """Boot one NUMA profile and require every marker. Raises on a miss."""
    with tempfile.TemporaryDirectory(prefix=f"xaios-numa-{profile}-") as temporary:
        environment = os.environ.copy()
        environment.update(
            {
                "XAIOS_QEMU_X86_ACCEL": "tcg",
                "XAIOS_QEMU_X86_CPU": "max",
                "XAIOS_QEMU_X86_MEMORY": "2G",
                "XAIOS_QEMU_X86_SMP": "4",
                "XAIOS_QEMU_X86_NUMA": profile,
                "XAIOS_QEMU_HOSTFWD_PORT": "none",
                "XAIOS_QEMU_RNG": "none",
            }
        )
        # A fresh copy of every image per profile. The guest writes to several
        # of them, and a second boot reading what the first left behind would
        # be testing a machine this gate did not build.
        for variable, source in SOURCES.items():
            destination = Path(temporary) / source.name
            shutil.copyfile(source, destination)
            environment[variable] = str(destination)
        process = subprocess.Popen(
            [str(ROOT / "platform/qemu/run-qemu-x86_64.sh")],
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            start_new_session=True,
        )
        output: list[str] = []
        deadline = time.monotonic() + 180.0
        try:
            assert process.stdout is not None
            while time.monotonic() < deadline:
                ready, _, _ = select.select([process.stdout], [], [], 0.5)
                line = process.stdout.readline() if ready else ""
                if line:
                    output.append(line)
                    joined = "".join(output)
                    if all(marker in joined for marker in markers):
                        return
                    if "Remaining: 0 components" in joined:
                        break
                elif process.poll() is not None:
                    break
            joined = "".join(output)
            # Name the markers that are missing. The diagnostic used to print
            # every NUMA line and leave the reader to spot which claim went
            # unmet, which is unreadable now that the gate also covers
            # topology, core leases and stealing.
            missing_markers = [item for item in markers if item not in joined]
            diagnostic = [
                line
                for line in output
                if "NUMA:" in line
                or "topology:" in line
                or "core-lease:" in line
                or "numa steal" in line
            ]
            raise RuntimeError(
                f"{profile}: markers missing:\n  "
                + "\n  ".join(missing_markers)
                + "\nobserved:\n"
                + "".join(diagnostic)
            )
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)


def main() -> int:
    entry_source = (ROOT / "kernel/arch/x86_64/entry.S").read_text()
    platform_source = (ROOT / "kernel/arch/x86_64/early.c").read_text()
    if entry_source.count("orq $0x200, %rax") < 2:
        raise RuntimeError("x86 user entry must enable RFLAGS.IF")
    if "IDT_PRESENT | UINT8_C(0x60) | IDT_TRAP_GATE" not in platform_source:
        raise RuntimeError("x86 syscall vector must use an interruptible trap gate")
    missing = [str(path) for path in SOURCES.values() if not path.exists()]
    if missing:
        raise SystemExit("missing x86_64 images: " + ", ".join(missing))
    run_profile("two-node", TWO_NODE_MARKERS)
    print(
        "qemu-x86_64-numa-gate: two-node SRAT/SLIT/HMAT placement, node-aware "
        "leasing, node-local stealing, 1-GiB mapping and SMP TLB shootdown passed"
    )
    run_profile("four-node", FOUR_NODE_MARKERS)
    print(
        "qemu-x86_64-numa-gate: four-node SLIT fallback ordering passed "
        "(3,2,1,0 from node 3; ties by node id from node 2; no HMAT present)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
