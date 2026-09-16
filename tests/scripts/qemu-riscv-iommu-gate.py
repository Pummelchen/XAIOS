#!/usr/bin/env python3
"""Prove RISC-V IOMMU translation, revocation, and device isolation.

The AArch64 SMMUv3 gate's sibling. What differs is the device, the format the
page tables are in, and where the fault evidence comes from: this PCI IOMMU is
MSI-only and the board routes no PCI MSI to this port, so the gate reads the
fault queue the driver drained rather than an interrupt-delivered event. The
device directory, the command queue and the fault queue are the driver's; what
is asserted here is what the machine did with them.
"""

import json
import re
import os
import select
import signal
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
SCHEMA = "xaios.qemu.riscv-iommu.v1"
MARKERS = [
    "riscv-iommu: found device=",
    "riscv-iommu: queues and ddt enabled",
    # Both formats, because the context is what the walk starts from and a
    # driver that only ever built one would be claiming a capability it never
    # used.
    "riscv-iommu: sv39 translated DMA result=0x0",
    "riscv-iommu: sv48 translated DMA result=0x0",
    "riscv-iommu: stale mapping blocked",
    "riscv-iommu: unregistered device refused",
    "riscv-iommu: isolation self-test passed authorized=1 forbidden=1 "
    "stale_mapping=blocked faults=",
]
PANIC_MARKERS = ["CYAN SCREEN OF DEATH", "System halted. Manual reset required"]


def stop_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            process.kill()
        process.wait(timeout=3)


def qemu_version(qemu: str) -> str:
    try:
        result = subprocess.run(
            [qemu, "--version"], capture_output=True, text=True, timeout=5,
            check=False,
        )
        return result.stdout.splitlines()[0] if result.stdout else "unknown"
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"


def main() -> int:
    BUILD.mkdir(parents=True, exist_ok=True)
    log_path = BUILD / "qemu-riscv-iommu-gate.log"
    report_path = BUILD / "qemu-riscv-iommu-gate-report.json"
    persistent_image = BUILD / "xaios-riscv-iommu-persistent.img"
    persistent_image.unlink(missing_ok=True)

    env = os.environ.copy()
    env.update(
        {
            "XAIOS_QEMU_IOMMU": "riscv-iommu",
            # The runner writes the console to a file by default; this gate
            # reads it from stdout, which is the switch that says so.
            "XAIOS_RISCV64_SERIAL": "stdio",
            "XAIOS_RISCV64_SSH_PORT": "none",
            "XAIOS_PERSISTENT_IMAGE": str(persistent_image),
        }
    )
    timeout = int(env.get("XAIOS_RISCV64_IOMMU_TIMEOUT", "150"))
    started = time.monotonic()
    process = subprocess.Popen(
        ["./platform/qemu/run-qemu-riscv64.sh"],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    output = bytearray()
    passed = False
    text = ""
    deadline = started + timeout
    try:
        if process.stdout is None:
            raise RuntimeError("QEMU stdout was not captured")
        descriptor = process.stdout.fileno()
        while time.monotonic() < deadline:
            ready, _, _ = select.select([descriptor], [], [], 0.2)
            if ready:
                chunk = os.read(descriptor, 8192)
                if not chunk:
                    break
                output.extend(chunk)
                try:
                    os.write(sys.stdout.fileno(), chunk)
                except (BrokenPipeError, OSError):
                    pass
                text = output.decode("utf-8", errors="replace")
                if all(marker in text for marker in MARKERS):
                    passed = not any(marker in text for marker in PANIC_MARKERS)
                    break
            elif process.poll() is not None:
                break
    finally:
        stop_process_group(process)
        text = output.decode("utf-8", errors="replace")
        log_path.write_text(text, encoding="utf-8")
        persistent_image.unlink(missing_ok=True)

    missing = [marker for marker in MARKERS if marker not in text]
    panics = [marker for marker in PANIC_MARKERS if marker in text]
    failures = [f"missing marker: {marker}" for marker in missing]
    # The summary marker only proves the line was printed. The two refusals --
    # the stale mapping and the device with no context at all -- must each have
    # left a record in the fault queue, so the total is checked separately and
    # an exact cumulative value is deliberately not pinned.
    fault_totals = [
        int(value)
        for value in re.findall(
            r"isolation self-test passed authorized=1 forbidden=1 "
            r"stale_mapping=blocked faults=(\d+)",
            text,
        )
    ]
    if fault_totals and max(fault_totals) < 2:
        failures.append("RISC-V IOMMU recorded fewer than two refused transactions")
    failures.extend(f"panic marker present: {marker}" for marker in panics)
    if not passed and not failures:
        failures.append(
            f"QEMU exited before IOMMU evidence, code={process.returncode}")

    report = {
        "schema": SCHEMA,
        "status": "pass" if passed and not failures else "fail",
        "created_unix": int(time.time()),
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "accelerator": "tcg",
        "iommu": "riscv-iommu",
        "qemu_version": qemu_version(
            env.get("QEMU_SYSTEM_RISCV64", "qemu-system-riscv64")),
        "qemu_correctness_only": True,
        "claims": [
            "an authorized PCI function's DMA was translated by a page table",
            "the same transaction after unmap and invalidate was refused",
            "a PCI function with no valid context raised DDT_INVALID",
            "both refusals were recorded in the fault queue, which was polled",
        ],
        "not_claimed": [
            "any virtio-mmio device, which this board's IOMMU cannot mediate",
            "physical IOMMU performance",
            "interrupt-delivered faults on a board with no usable PCI MSI",
        ],
        "markers": MARKERS,
        "log": "build/qemu-riscv-iommu-gate.log",
        "failures": failures,
    }
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"qemu-riscv-iommu-gate: report written to "
          f"{report_path.relative_to(ROOT)}")
    if failures:
        for failure in failures:
            print(f"qemu-riscv-iommu-gate: {failure}")
        return 1
    print("qemu-riscv-iommu-gate: PCI DMA isolation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
