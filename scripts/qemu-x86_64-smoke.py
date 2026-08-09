#!/usr/bin/env python3
import os
import select
import subprocess
import sys
import time


TARGETS = [
    "XAIOS loader starting",
    "XAIOS loader target: x86_64 UEFI",
    "XAIOS loader loaded kernel.elf",
    "XAIOS loader validated ELF64 kernel",
    "XAIOS loader copied kernel segments",
    "XAIOS loader exiting boot services",
    "XAIOS x86_64 kernel starting",
    "x86_64: UEFI boot info valid",
    "x86_64: COM1 serial online",
    "x86_64: Intel Desktop milestone 43 boot path passed",
    "x86_64: GDT/TSS installed rsp0=",
    "x86_64: IDT installed vectors=32",
    "x86_64: early exception path online",
    "x86_64: controlled INT3 exception round-trip passed count=1",
    "x86_64: Intel Desktop milestone 44 early exceptions passed",
    "x86_64: PMM parsed descriptors=",
    "x86_64: Intel Desktop milestone 45 memory map passed",
    "x86_64: ACPI root=XSDT enabled_cpus=",
    "MADT=1 SRAT=",
    "x86_64: ACPI topology and NUMA tables validated",
    "x86_64: early page tables loaded cr3=",
    "x86_64: VMM policy kernel/user split prepared",
    "x86_64: Intel Desktop milestone 46 page tables passed",
    "/bin/hello: hello world from C userspace",
    "/bin/hello: C toolchain and EL0 runtime integration passed",
    "x86_64: real /bin/hello ELF syscall ABI passed calls=3 exit=0",
    "x86_64: APIC discovery supported=",
    "x86_64: timer discovery tsc=",
    "x86_64: local APIC timer interrupt passed id=",
    "x86_64: Intel Desktop milestone 47 timers APIC passed",
    "x86_64: SMP AP startup passed online=",
    "madt_cpus=",
    "dynamic_records=1",
    "x86_64: SMP IPI worker dispatch passed workers=",
    "x86_64: common security policy self-test passed",
    "x86_64: scalar AI kernel self-test passed",
    "x86_64: PCI discovery devices=",
    "modern_virtio=2",
    "x86_64: Intel Desktop milestone 48 PCI discovery passed",
    "x86_64: modern VirtIO block DMA read passed sector=0 bytes=512",
    "x86_64: VirtIO block MSI-X completion interrupt passed vector=34",
    "x86_64: modern VirtIO network DMA TX passed bytes=42",
    "x86_64: placement policy logical_cpus=",
    "x86_64: SMT policy disabled_by_default=1",
    "x86_64: hot-core telemetry migration_total=0 context_switch_total=0",
    "x86_64: Intel Desktop milestone 49 placement policy passed",
    "x86_64: common kernel/runtime linked=1 probe=0x000000000000000f expected=0x000000000000000f",
    "x86_64: OS contract userspace=0 filesystem=1 networking=0 ai_cell=0 security=0 telemetry=0",
    "x86_64: full OS contract parity marker ready=0",
    "x86_64: Intel Desktop milestone 50 portable common runtime passed platform services pending",
    "x86_64: hardware gate qemu_correctness=1 physical_required=1 baseline_required=1 performance_claims_allowed=0 release_candidate_ready=0",
    "x86_64: Intel Desktop hardware gate blocked platform-parity-and-physical-evidence-required",
    "x86_64: Intel Desktop milestone 51 hardware gate blocked",
]

OR_TARGETS = [
    [
        "x86_64: AVX2 packed no-expand known-answer canary passed",
        "x86_64: AVX2 packed canary unsupported on selected CPU",
    ],
    [
        "x86_64: XSAVE/XRSTOR canary passed bytes=",
        "x86_64: FXSAVE/FXRSTOR fallback canary passed bytes=512",
    ],
]


def main() -> int:
    env = os.environ.copy()
    env.setdefault("XAIOS_QEMU_X86_ACCEL", "tcg")
    env.setdefault("XAIOS_QEMU_X86_CPU", "max")
    timeout = int(env.get("XAIOS_QEMU_X86_SMOKE_TIMEOUT", "45"))

    proc = subprocess.Popen(
        ["./scripts/run-qemu-x86_64.sh"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=False,
        bufsize=0,
        env=env,
    )

    seen = []
    deadline = time.time() + timeout
    try:
        assert proc.stdout is not None
        fd = proc.stdout.fileno()
        while time.time() < deadline:
            ready, _, _ = select.select([fd], [], [], 0.2)
            if ready:
                chunk = os.read(fd, 4096).decode("utf-8", errors="replace")
                if not chunk:
                    break
                sys.stdout.write(chunk)
                sys.stdout.flush()
                seen.append(chunk)
                text = "".join(seen)
                if (
                    all(target in text for target in TARGETS)
                    and all(
                        any(target in text for target in alternatives)
                        for alternatives in OR_TARGETS
                    )
                ):
                    print(
                        "qemu-x86_64-smoke: x86_64 boot reached all "
                        "early bring-up and portable-runtime markers"
                    )
                    return 0
            elif proc.poll() is not None:
                break
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)

    text = "".join(seen)
    missing = [target for target in TARGETS if target not in text]
    missing.extend(
        " | ".join(alternatives)
        for alternatives in OR_TARGETS
        if not any(target in text for target in alternatives)
    )
    print("\nqemu-x86_64-smoke: missing markers:")
    for marker in missing:
        print(f"  - {marker}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
