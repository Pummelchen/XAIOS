#!/usr/bin/env python3
import json
import os
import subprocess
import time

from qemu_gate_lib import BUILD, ROOT, check_markers, run, timeout_scale

# A step past this fraction of its budget is reported as a note. It is not a
# failure -- the step passed -- but it is the one that times out next on a
# busier machine, and B-39 is what that looks like when nobody was warned.
BUDGET_WARN_FRACTION = 0.75


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
    # B-72: 300 was set when this gate's RISC-V legs failed in under a second
    # on a missing filesystem. Since B-68 they boot for real, and it used all
    # 900 of its tripled budget twice without finishing. It takes 105-107s
    # here, measured three times, but one of its four guests runs on hardware
    # virtualisation here and none of them do on the runner, so that figure
    # does not scale into an answer -- and the parity container cannot settle
    # it either, being arm64 and unable to build the x86-64 userland. 600
    # stops the budget being the thing that fails; the step reports its own
    # elapsed, so the runner supplies the real number on the next run.
    ("nvme", ["make", "qemu-nvme-gate"], 600),
    ("fragmentation", ["make", "qemu-outbound-fragmentation-gate"], 360),
    ("network", ["make", "qemu-network-suite"], 300),
    ("high_core", ["make", "qemu-high-core-gate"], 500),
    ("x86_64", ["make", "qemu-x86_64-smoke"], 240),
    # Both of these existed as make targets that nothing invoked, which makes
    # them documentation rather than gates. The memory matrix is the only thing
    # that boots all three architectures at more than one memory size, and the
    # address-space defects it guards were invisible at the single size every
    # other gate uses. The read-only medium gate is the only thing that
    # exercises the driver's refusal path at all.
    ("memory_matrix", ["make", "qemu-memory-matrix"], 3600),
    ("readonly_medium", ["make", "qemu-readonly-medium-gate"], 900),
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
            # arch= is named, and this is the AArch64 release candidate, so
            # naming it is the stronger claim rather than a looser one. The
            # field appeared when the gate gained a third architecture; the
            # markers here kept the two-architecture wording and reported four
            # missing crossings for a gate that crosses all four.
            "qemu-storage-crash: recovered arch=aarch64 "
            "point=system-backup-flushed volume=v5",
            "qemu-storage-crash: recovered arch=aarch64 "
            "point=system-backup-flushed volume=v6",
            "qemu-storage-crash: recovered arch=aarch64 "
            "point=system-primary-written volume=v5",
            "qemu-storage-crash: recovered arch=aarch64 "
            "point=system-primary-written volume=v6",
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
            # Named per architecture, because the gate now covers three and
            # says how each one is driven. RISC-V is polled: that board has no
            # MSI-X, which is a property of the machine and is why the count
            # differs rather than something to hide behind a looser match.
            "passed on aarch64 4 msix, x86_64 4 msix, riscv64 1 polled",
        ],
    ),
    "outbound_fragmentation": (
        "fragmentation",
        [
            # This said "AArch64/x86_64" until the gate grew a third
            # architecture and changed its own wording. The aggregate kept the
            # old string and reported a missing marker for a gate that passes,
            # which is the same shape as a stale assertion anywhere else: the
            # system improved and the check did not move with it.
            "PASS: outbound fragmentation on aarch64, x86_64, riscv64",
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
    # B-39: a step that is killed has to say what it was killed for.
    #
    # The fragmentation step timed out once here and never again -- 121s
    # standalone, 120s from the boot-test image state, 121s with all three of
    # its images invalidated, and this whole gate green on a re-run. Two
    # explanations were tried against the exit code alone and both were wrong,
    # because an exit code of 124 carries no elapsed time and no idea what else
    # the machine was doing. This machine has cut a qemu-smoke boot short at
    # load average 30 and passed it at load 9 with no change in between, so
    # "how loaded was it" is not a detail.
    #
    # Every step now records its own elapsed time, its budget and the load
    # either side of it, whether it passed or not. A recurrence describes
    # itself.
    for name, command, base_timeout in COMMANDS:
        # The budgets above were written on this Mac. A host with no hardware
        # virtualisation interprets every guest and needs several times longer
        # for the same work -- the fragmentation step runs in 96 to 98 seconds
        # here and exceeds its 360-second budget on every CI run. The scale is
        # declared by the environment rather than guessed at; see
        # qemu_gate_lib.timeout_scale.
        timeout = int(base_timeout * timeout_scale())
        timed_out = False
        load_start = os.getloadavg()[0]
        started = time.monotonic()
        try:
            proc = run(command, timeout=timeout)
            output = proc.stdout or ""
            exit_code = proc.returncode
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            output = exc.stdout or ""
            if isinstance(output, bytes):
                output = output.decode("utf-8", errors="replace")
            output += (
                f"\nqemu-core-os-rc: command timed out after {timeout}s "
                f"(load {load_start:.2f} at start, "
                f"{os.getloadavg()[0]:.2f} now)\n"
            )
            exit_code = 124
        except OSError as exc:
            output = f"qemu-core-os-rc: command failed to start: {exc}\n"
            exit_code = 127
        elapsed = time.monotonic() - started
        load_end = os.getloadavg()[0]
        outputs[name] = output
        BUILD.mkdir(parents=True, exist_ok=True)
        (BUILD / f"qemu-core-os-rc-{name}.log").write_text(
            output, encoding="utf-8"
        )
        results[name] = {
            "command": command,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "seconds": round(elapsed, 1),
            "budget_seconds": timeout,
            "budget_used": round(elapsed / timeout, 3) if timeout else None,
            "load_start": round(load_start, 2),
            "load_end": round(load_end, 2),
            "log": f"build/qemu-core-os-rc-{name}.log",
        }
        if exit_code != 0:
            failures.append(
                f"{name} exited {exit_code} after {elapsed:.0f}s of a "
                f"{timeout}s budget, load {load_start:.2f} to {load_end:.2f}")
        elif timeout and elapsed > timeout * BUDGET_WARN_FRACTION:
            # Not a failure. A step this close to its budget is the next
            # timeout nobody can explain, and saying so now costs nothing.
            print(f"qemu-core-os-rc: NOTE {name} used {elapsed:.0f}s of its "
                  f"{timeout}s budget ({elapsed / timeout:.0%}), load "
                  f"{load_start:.2f} to {load_end:.2f}", flush=True)

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
