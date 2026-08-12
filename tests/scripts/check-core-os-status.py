#!/usr/bin/env python3
"""Keep core-OS status claims synchronized with the QEMU capability contract."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REQUIRED = {
    "README.md": [
        "XAIOS Wiki",
        "Model support status",
        "Project Tracker",
        "PolyForm Noncommercial License 1.0.0",
    ],
    "wiki/Project-Tracker.md": [
        "Physical Apple/ARM, Intel desktop, and Xeon qualification",
        "Thread-safe libc contexts for XAIOS native threads",
        "DNSSEC, TCP fallback, complete AAAA results",
        "S-11Q QEMU NVMe async/multiqueue/SGL/cancellation/direct-buffer path",
        "S-11P Physical production NVMe qualification",
    ],
    "docs/NETWORK-SSH-STATUS.md": [
        "SACK parsing/emission",
        "Bounded IPv4 and IPv6 reassembly",
        "asynchronous resolver syscall",
    ],
    "docs/STORAGE-ARCHITECTURE.md": [
        "interrupt-dispatched with eight request slots",
        "emulated-NVMe gate negotiates four I/O queues",
    ],
    "wiki/Current-Limitations.md": [
        "external A-record resolution",
        "complete common process/thread",
        "QEMU parity is not a physical support claim",
    ],
    "wiki/Filesystem-and-Storage.md": [
        "eight-request block batching",
    ],
    "wiki/Hardware-Support.md": [
        "MADT-discovered application processors",
        "QEMU service parity with AArch64",
    ],
    "wiki/Networking-and-SSH.md": [
        "out-of-order",
        "IPv4/IPv6 fragment reassembly",
    ],
    "wiki/Testing-XAIOS.md": [
        "make qemu-outbound-fragmentation-gate",
        "6ce361b02c825b4a12a9684c47342859ee967cb2",
    ],
}

FORBIDDEN = {
    "README.md": ["two concurrent direct-or-bounce", "NVMe multiqueue and physical-device durability remain unimplemented"],
    "docs/NETWORK-SSH-STATUS.md": [
        "Active IPv4/IPv6 transport paths reject fragments",
        "there is no wired userspace resolver service",
        "No general `xaios_thread_create()` API exists",
        "AArch64 remains bypass-only",
    ],
    "docs/STORAGE-ARCHITECTURE.md": ["QEMU VirtIO path is synchronous and copied"],
    "docs/MODEL-VOLUME.md": ["QEMU VirtIO adapter remains synchronous and copied"],
    "wiki/Home.md": ["two-request block batching"],
}

CONTRACT_CAPABILITIES = {
    "fragment_reassembly",
    "outbound_fragmentation",
    "userspace_dns",
    "storage_crash_consistency",
    "translated_smmuv3_isolation",
    "emulated_nvme_io",
    "high_core_dynamic_capacity",
    "arm_fp_neon_context",
    "x86_interrupt_delivery",
    "x86_modern_pci_inventory",
    "x86_acpi_topology",
    "x86_ap_startup",
    "x86_ring3_syscall",
    "x86_xsave_state",
    "x86_virtio_dma",
    "x86_block_completion",
    "x86_full_service_stack",
    "engine_service_boundary",
    "immutable_model_mapping",
    "async_model_range_io",
    "session_lifecycle_metadata",
}


def main() -> int:
    failures: list[str] = []
    for relative, markers in REQUIRED.items():
        text = (ROOT / relative).read_text(encoding="utf-8")
        for marker in markers:
            if marker not in text:
                failures.append(f"{relative}: missing current status marker: {marker}")
    for relative, markers in FORBIDDEN.items():
        text = (ROOT / relative).read_text(encoding="utf-8")
        for marker in markers:
            if marker in text:
                failures.append(f"{relative}: stale status marker remains: {marker}")

    tracker_text = (ROOT / "wiki/Project-Tracker.md").read_text(encoding="utf-8")
    if "| `DONE` |" in tracker_text:
        failures.append("wiki/Project-Tracker.md: completed row remains in open tracker")

    contract = json.loads(
        (ROOT / "contracts/qemu-rc-v1.json").read_text(encoding="utf-8")
    )
    capabilities = set(
        contract["core_os_capability_contract"]["required_capabilities"]
    )
    missing_capabilities = sorted(CONTRACT_CAPABILITIES - capabilities)
    if missing_capabilities:
        failures.append(
            "contracts/qemu-rc-v1.json: missing core capabilities: "
            + ", ".join(missing_capabilities)
        )

    if failures:
        print("core-os-status-check: failed")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(
        "core-os-status-check: README, canonical tracker, docs, Wiki, and "
        "contract are synchronized"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
