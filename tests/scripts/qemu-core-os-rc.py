#!/usr/bin/env python3
import json
import subprocess
import time

from qemu_gate_lib import BUILD, ROOT, check_markers, run


SCHEMA = "xaios.qemu.core_os_release_candidate.v1"
COMMANDS = [
    ("compile", ["make", "compile-check"], 300),
    ("hosted", ["make", "hosted-test"], 900),
    ("sanitizers", ["make", "hosted-sanitizer-test"], 900),
    ("source_audit", ["make", "production-source-audit"], 120),
    ("docs", ["make", "docs-check"], 120),
    ("abi", ["python3", "tests/scripts/qemu-abi-contract.py"], 180),
    ("aarch64", ["make", "qemu-smoke"], 300),
    ("fault_injection", ["make", "qemu-fault-injection"], 600),
    # Two crash points against two durable volume formats, one of which is a
    # gibibyte that has to be formatted and checked under emulation. It was 700
    # when the gate ran v5 only, and overran the moment v6 was added.
    ("storage_crash", ["make", "qemu-storage-crash-test"], 1800),
    ("smmuv3", ["make", "qemu-smmu-gate"], 300),
    ("nvme", ["make", "qemu-nvme-gate"], 300),
    ("fragmentation", ["make", "qemu-outbound-fragmentation-gate"], 360),
    ("network", ["make", "qemu-network-suite"], 300),
    ("high_core", ["make", "qemu-high-core-gate"], 500),
    ("x86_64", ["make", "qemu-x86_64-smoke"], 240),
    ("operations", ["python3", "tests/scripts/qemu-operations-closure.py",
                    "--skip-docker"], 700),
]

AARCH64_CAPABILITIES = {
    "signed_ab_update_and_rollback": [
        "system-slot: self-test passed redundant_metadata=2 slots=2 active=0",
        "update: delivery self-test passed",
    ],
    "dynamic_memory_cpu_topology": [
        "NUMA: dynamic metadata bytes=",
        "no fixed RAM or CPU bitmap ceiling",
        "smp: online cpus=4/4 dynamic_capacity=4",
        "core-lease: dynamic isolation self-test passed",
    ],
    "interrupt_driven_virtio": [
        "virtio-blk: asynchronous queue self-test passed depth=8 indirect=1 direct-or-bounce=verified",
        # intid 50 is the virtio-net device, and that it registers a
        # handler at all is the point of this check. The number after
        # "handlers=" is a count of every interrupt registered so far
        # anywhere in the kernel, so pinning it made this gate fail
        # whenever an unrelated device was added to the boot -- which is
        # exactly what attaching a scratch disk to the smoke
        # configuration did. Match the registration, not the tally.
        "gic: registered interrupt intid=50 handlers=",
        "virtio-net: persistent mode initialized rx=8 tx=4 event_idx=1 indirect_sg=1",
    ],
    "general_threads": [
        "threads: runtime initialized capacity=",
        "threads: concurrent scheduler self-test passed threads=",
        "/bin/smptest: concurrent kernel-dispatched worker group passed",
    ],
    "tcp_sliding_window": [
        "network: TCP sliding-window self-test passed segments=3 cumulative_ack=1 partial_ack=1 sack=1 fast_retransmit=1 zero_window=1 reorder=1 rto_backoff=1",
        "/bin/nettest: app-callable udp/tcp path passed",
    ],
    "fragment_reassembly": [
        "ipv4: fragmentation/reassembly self-test passed",
        "ipv6: fragmentation/reassembly passed",
    ],
    # The aggregate boots the XAIOS_BOOT_TEST_APPS image, where nettest drives
    # the deterministic DNS fixture. The "resolve/cache" wording only exists in
    # the non-test build that resolves a live name, so requiring it here could
    # never be satisfied. Live resolution is covered by the network suite and
    # the external interoperability gates, not by this boot.
    "userspace_dns": [
        "/bin/nettest: userspace DNS fixture path passed",
    ],
    "arm_fp_neon_context": [
        "scheduler: SIMD/FP interrupt preservation passed",
    ],
    "immutable_model_mapping": [
        "model-arena: shared read-only arena self-test passed fixture_copy=1 immutable_mapping=1 copy=0",
    ],
}

X86_CAPABILITIES = {
    "x86_interrupt_delivery": [
        "x86_64: controlled INT3 exception round-trip passed count=1",
        "x86_64: local APIC timer interrupt passed id=0 version=20 interrupts=1",
    ],
    "x86_modern_pci_inventory": [
        "PCI: x86 enumerated ",
        "PCI: x86 enumeration self-test passed devices=",
    ],
    "portable_common_runtime": [
        "/init: service setup complete",
        "kernel: /bin/service-manager returned to kernel exit_code=0",
        "kernel: persistent network stack enabled",
    ],
    "dynamic_topology_description": [
        "smp: x86 MADT/APIC online cpus=",
        "dynamic_capacity=",
        "topology: initialized ",
    ],
    "x86_acpi_topology": [
        "x86_64: ACPI topology and NUMA tables validated",
    ],
    "x86_ap_startup": [
        "x86_64: SMP AP startup passed online=",
        "dynamic_records=1",
        "smp: x86 secondary worker barrier passed ready=",
    ],
    "x86_ring3_syscall": [
        "/bin/hello: hello world from C userspace",
        "/bin/hello: C toolchain and EL0 runtime integration passed",
        "kernel: /bin/hello returned to kernel exit_code=0",
    ],
    "x86_xsave_state": [
        "x86_64: XSAVE/XRSTOR canary passed bytes=",
        "scheduler: SIMD/FP interrupt preservation passed",
    ],
    "x86_virtio_dma": [
        "virtio-blk: modern PCI transport index=",
        "virtio-blk: read/write/error/reset self-test passed",
        "virtio-net: modern PCI transport index=",
        "virtio-net: queue/tx/parser/reset self-test passed",
    ],
    "x86_block_completion": [
        "virtio-blk: x86 completion canary passed mode=",
    ],
    "x86_full_service_stack": [
        "/bin/smptest: complete",
        "/bin/nettest: complete",
        "sshd: Phase 2 runtime ready",
        "SSH server: up and running (tcp/22)",
    ],
}

HOSTED_CAPABILITIES = {
    "engine_service_boundary": [
        "hosted engine: scalar, registry, async I/O, model cache, and session lifecycle passed",
    ],
    "async_model_range_io": [
        "hosted engine: scalar, registry, async I/O, model cache, and session lifecycle passed",
    ],
    "session_lifecycle_metadata": [
        "hosted engine: scalar, registry, async I/O, model cache, and session lifecycle passed",
    ],
}

SPECIAL_CAPABILITIES = {
    "operational_lifecycle_closure": (
        "operations",
        ["qemu-operations-closure: PASS"],
    ),
    "storage_crash_consistency": (
        "storage_crash",
        [
            # Named down to the volume format, because the gate crosses both
            # kill points with both formats and prints the format it used.
            # Without the suffix these are substrings that a v5 pass satisfies
            # on its own: a run where v5 recovered and v6 did not reported the
            # v6 point as present and the *next* point as missing, which sent
            # the reader to a kill point the run never reached. Four crossings
            # are tested, so four are required.
            "qemu-storage-crash: recovered point=system-backup-flushed "
            "volume=v5",
            "qemu-storage-crash: recovered point=system-backup-flushed "
            "volume=v6",
            "qemu-storage-crash: recovered point=system-primary-written "
            "volume=v5",
            "qemu-storage-crash: recovered point=system-primary-written "
            "volume=v6",
            "qemu-storage-crash: all metadata kill points recovered",
        ],
    ),
    "translated_smmuv3_isolation": (
        "smmuv3",
        [
            "SMMU: translated DMA self-test passed",
            # Cumulative SMMU fault total, not this test's count: unrelated
            # streams fault first, so the number varies by boot.
            "authorized=1 forbidden=1 stale_mapping=blocked faults=",
            "qemu-smmu-gate: translated DMA isolation passed",
        ],
    ),
    "emulated_nvme_io": (
        "nvme",
        [
            "nvme: async self-test passed namespaces=1",
            "rounds=8 async=38 cancelled=1",
            "qemu-nvme-gate: aarch64/x86_64 async four-queue PRP/SGL direct I/O",
        ],
    ),
    "outbound_fragmentation": (
        "fragmentation",
        [
            "PASS: AArch64/x86_64 outbound fragmentation report=",
        ],
    ),
    "high_core_dynamic_capacity": (
        "high_core",
        [
            "smp: online cpus=130/130 dynamic_capacity=130",
            "qemu-high-core-gate: dynamic capacity passed cpus=130",
        ],
    ),
}


def main() -> int:
    started = time.time()
    failures = []
    results = {}
    outputs = {}
    BUILD.mkdir(parents=True, exist_ok=True)
    for name, command, timeout in COMMANDS:
        timed_out = False
        try:
            proc = run(command, timeout=timeout)
            output = proc.stdout or ""
            exit_code = proc.returncode
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            output = exc.stdout or ""
            if isinstance(output, bytes):
                output = output.decode("utf-8", errors="replace")
            output += f"\nqemu-core-os-rc: command timed out after {timeout}s\n"
            exit_code = 124
        except OSError as exc:
            output = f"qemu-core-os-rc: command failed to start: {exc}\n"
            exit_code = 127
        outputs[name] = output
        BUILD.mkdir(parents=True, exist_ok=True)
        (BUILD / f"qemu-core-os-rc-{name}.log").write_text(
            output, encoding="utf-8"
        )
        results[name] = {
            "command": command,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "log": f"build/qemu-core-os-rc-{name}.log",
        }
        if exit_code != 0:
            failures.append(f"{name} exited {exit_code}")

    capabilities = {}
    for name, markers in AARCH64_CAPABILITIES.items():
        missing = check_markers(outputs.get("aarch64", ""), markers)
        capabilities[name] = {"passed": not missing, "missing": missing}
        failures.extend(f"{name}: missing marker: {marker}" for marker in missing)
    for name, markers in X86_CAPABILITIES.items():
        missing = check_markers(outputs.get("x86_64", ""), markers)
        capabilities[name] = {"passed": not missing, "missing": missing}
        failures.extend(f"{name}: missing marker: {marker}" for marker in missing)
    for name, markers in HOSTED_CAPABILITIES.items():
        missing = check_markers(outputs.get("hosted", ""), markers)
        capabilities[name] = {"passed": not missing, "missing": missing}
        failures.extend(f"{name}: missing marker: {marker}" for marker in missing)
    for name, (output_name, markers) in SPECIAL_CAPABILITIES.items():
        missing = check_markers(outputs.get(output_name, ""), markers)
        capabilities[name] = {"passed": not missing, "missing": missing}
        failures.extend(f"{name}: missing marker: {marker}" for marker in missing)

    panic_markers = ["CYAN SCREEN OF DEATH", "System halted. Manual reset required"]
    for architecture in ["aarch64", "x86_64"]:
        found = [marker for marker in panic_markers if marker in outputs.get(architecture, "")]
        if found:
            failures.append(f"{architecture}: unexpected panic markers: {found}")

    report = {
        "schema": SCHEMA,
        "created_unix": int(time.time()),
        "elapsed_seconds": round(time.time() - started, 3),
        "status": "pass" if not failures else "fail",
        "qemu_correctness_only": True,
        "physical_performance_claims_allowed": False,
        "commands": results,
        "capabilities": capabilities,
        "x86_qemu_service_parity": not failures,
        "x86_physical_support": False,
        "x86_pending": [
            "physical Intel firmware, interrupt, storage, NIC, and NUMA validation",
            "physical AVX2, AVX-512, VNNI, and AMX state and kernel validation",
            "physical reliability, security, performance, power, and thermal evidence",
        ],
        "failures": failures,
    }
    output_path = BUILD / "qemu-core-os-rc-report.json"
    output_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"qemu-core-os-rc: report written to {output_path.relative_to(ROOT)}")
    if failures:
        print("qemu-core-os-rc: failed")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("qemu-core-os-rc: all QEMU-testable core capability gates passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
