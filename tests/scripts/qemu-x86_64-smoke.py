#!/usr/bin/env python3
import os
import select
import subprocess
import sys
import time
from pathlib import Path


TARGETS = [
    "XAIOS loader starting",
    "XAIOS loader target: x86_64 UEFI",
    "XAIOS loader loaded verified A/B system slot",
    "XAIOS loader validated ELF64 kernel",
    "XAIOS x86_64 kernel starting",
    "x86_64: UEFI boot info valid",
    "x86_64: controlled INT3 exception round-trip passed count=1",
    "x86_64: PMM parsed descriptors=",
    "x86_64: ACPI root=XSDT enabled_cpus=",
    "x86_64: early page tables loaded cr3=",
    "x86_64: local APIC timer interrupt passed id=",
    "x86_64: SMP AP startup passed online=",
    "dynamic_records=1",
    "NUMA: self-test passed",
    "VMM: x86 map/unmap self-test passed",
    "PCI: x86 enumeration self-test passed",
    "virtio-blk: read/write/error/reset self-test passed",
    "virtio-blk: x86 completion canary passed mode=",
    "virtio-net: persistent mode initialized",
    "kernel: /bin/service-manager returned to kernel exit_code=0",
    "scheduler: SIMD/FP interrupt preservation passed",
    "smp: x86 secondary worker barrier passed ready=",
    "threads: concurrent group complete",
    "/bin/smptest: complete",
    "/bin/nettest: complete",
    "kernel: /bin/xaios-shell returned to kernel exit_code=0",
    "kernel: /bin/sshtest returned to kernel exit_code=0",
    "kernel: /bin/posix-shell returned to kernel exit_code=0",
    "/bin/helloworldc99: Hello, World!",
    "kernel: /bin/helloworldc99 returned to kernel exit_code=0",
    "kernel: starting persistent /bin/sshd service",
    "sshd: Phase 2 runtime ready",
    "boot-ui: progress=100 loaded=SSH-server loading=complete remaining=0",
    "IPv4: 10.0.2.15",
    "SSH server: up and running (tcp/22)",
]

FORBIDDEN = [
    "x86_64: panic:",
    "Triple fault",
    "Cyan Screen of Death",
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
    timeout = int(env.get("XAIOS_QEMU_X86_SMOKE_TIMEOUT", "180"))
    supplied_persistent_image = env.get("XAIOS_X86_PERSISTENT_IMAGE")
    persistent_image = Path(
        supplied_persistent_image or "build/xaios-x86-smoke-persistent.img"
    )
    owns_persistent_image = supplied_persistent_image is None
    if owns_persistent_image:
        persistent_image.unlink(missing_ok=True)
        env["XAIOS_X86_PERSISTENT_IMAGE"] = str(persistent_image)

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
                try:
                    sys.stdout.write(chunk)
                    sys.stdout.flush()
                except BlockingIOError:
                    pass
                seen.append(chunk)
                text = "".join(seen)
                if any(marker in text for marker in FORBIDDEN):
                    break
                if (
                    all(target in text for target in TARGETS)
                    and all(
                        any(target in text for target in alternatives)
                        for alternatives in OR_TARGETS
                    )
                ):
                    print(
                        "qemu-x86_64-smoke: x86_64 boot reached all "
                        "full common-runtime and SSH readiness markers"
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
        if owns_persistent_image:
            persistent_image.unlink(missing_ok=True)

    text = "".join(seen)
    missing = [target for target in TARGETS if target not in text]
    missing.extend(
        " | ".join(alternatives)
        for alternatives in OR_TARGETS
        if not any(target in text for target in alternatives)
    )
    forbidden = [marker for marker in FORBIDDEN if marker in text]
    print("\nqemu-x86_64-smoke: missing markers:")
    for marker in missing:
        print(f"  - {marker}")
    for marker in forbidden:
        print(f"  - forbidden marker observed: {marker}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
