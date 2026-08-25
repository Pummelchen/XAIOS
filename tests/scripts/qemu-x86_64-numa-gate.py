#!/usr/bin/env python3
"""Validate XAIOS ACPI NUMA discovery and allocation under QEMU TCG."""

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
MARKERS = (
    "NUMA: ACPI topology nodes=2",
    "hmat_structures=2",
    "NUMA: HMAT initiator=0 preferred=0 valid=1 latency_ps=10000 bandwidth_Bps=21474836480",
    "NUMA: HMAT initiator=1 preferred=1 valid=1 latency_ps=10000 bandwidth_Bps=21474836480",
    "VMM: x86 1 GiB page and SMP address-specific invalidation self-test passed",
    "NUMA: self-test passed nodes=2",
    "ownership=verified local_bytes=64 remote_bytes=128",
)


def main() -> int:
    entry_source = (ROOT / "kernel/arch/x86_64/entry.S").read_text()
    platform_source = (ROOT / "kernel/arch/x86_64/early.c").read_text()
    if entry_source.count("orq $0x200, %rax") < 2:
        raise RuntimeError("x86 user entry must enable RFLAGS.IF")
    if "IDT_PRESENT | UINT8_C(0x60) | IDT_TRAP_GATE" not in platform_source:
        raise RuntimeError("x86 syscall vector must use an interruptible trap gate")
    sources = {
        "XAIOS_X86_64_IMAGE": ROOT / "build/xaios-x86_64.img",
        "XAIOS_X86_TEST_BLOCK_IMAGE": ROOT / "build/xaios-x86-virtio-test.img",
        "XAIOS_X86_PERSISTENT_IMAGE": ROOT / "build/xaios-x86-persistent.img",
        "XAIOS_MODEL_VOLUME_IMAGE": ROOT / "build/xaios-x86-model-volume.img",
        "XAIOS_SYSTEM_VOLUME_IMAGE": ROOT / "build/xaios-x86-system.img",
        "XAIOS_X86_STORAGE_ADMIN_IMAGE": ROOT / "build/xaios-x86-storage-admin.img",
    }
    missing = [str(path) for path in sources.values() if not path.exists()]
    if missing:
        raise SystemExit("missing x86_64 images: " + ", ".join(missing))
    with tempfile.TemporaryDirectory(prefix="xaios-numa-") as temporary:
        environment = os.environ.copy()
        environment.update(
            {
                "XAIOS_QEMU_X86_ACCEL": "tcg",
                "XAIOS_QEMU_X86_CPU": "max",
                "XAIOS_QEMU_X86_MEMORY": "2G",
                "XAIOS_QEMU_X86_SMP": "4",
                "XAIOS_QEMU_X86_NUMA": "two-node",
                "XAIOS_QEMU_HOSTFWD_PORT": "none",
                "XAIOS_QEMU_RNG": "none",
            }
        )
        for variable, source in sources.items():
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
                    if all(marker in joined for marker in MARKERS):
                        print("qemu-x86_64-numa-gate: SRAT/SLIT/HMAT placement, 1-GiB mapping, and SMP TLB shootdown passed")
                        return 0
                    if "Remaining: 0 components" in joined:
                        break
                elif process.poll() is not None:
                    break
            diagnostic = [line for line in output if "NUMA:" in line]
            raise RuntimeError("NUMA markers missing\n" + "".join(diagnostic))
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
