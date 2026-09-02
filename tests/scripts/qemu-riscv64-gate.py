#!/usr/bin/env python3
"""Boot the RISC-V bring-up under QEMU and require it to prove each claim.

What this gate is for is narrower than "RISC-V works", and the difference
matters. The port covers console, traps, paging, the timer, and shared kernel
code. It does not cover SMP, PCI, virtio, storage, networking or userspace.
A gate that only checked the guest reached its last line would pass equally
well on a kernel that printed the lines and did nothing, so each marker below
corresponds to something the guest verified about itself before printing it:
a trap it provoked and counted, a satp it wrote and read back, a clock it
sampled twice, and known-answer vectors it asserted.

The forbidden markers are the other half. The bring-up prints a specific line
when a self-test fails rather than halting silently, and a gate that matched
only on success would treat "TRAP SELF-TEST FAILED" followed by a clean
shutdown as a pass, since the absence it was looking for is indistinguishable
from a guest that stopped early.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
KERNEL = ROOT / "build" / "kernel-riscv64" / "kernel.elf"
LOG = ROOT / "build" / "qemu-riscv64-gate.log"

REQUIRED = [
    # The console itself: nothing else can be reported without it.
    "XAIOS riscv64 bring-up starting",
    "riscv64: sbi console ready",
    # A trap that was provoked, taken, identified and returned from. cause=3
    # is a breakpoint, which is what the guest deliberately raised.
    "riscv64: trap taken and returned from cause=3",
    # Translation on, and the kernel still able to reach itself through it.
    "riscv64: sv39 paging enabled, kernel still addressable",
    # A clock, not a constant.
    "riscv64: timer advancing",
    # The claim this port exists to test: kernel/runtime/sha256.c, the same
    # file AArch64 and x86-64 compile, asserting its own vectors here.
    "sha256: self-test passed",
    "riscv64: shared kernel sha256 verified on this architecture",
    # The guest saying what it is not, so a passing gate cannot be read as
    # more than it is.
    "riscv64: NOT present on this architecture: smp, pci, virtio, storage, "
    "network, userspace",
    "riscv64: halting",
]

FORBIDDEN = [
    "TRAP SELF-TEST FAILED",
    "SV39 REFUSED",
    "TIMER DID NOT ADVANCE",
    "XAIOS panic",
]


def main() -> int:
    qemu = shutil.which("qemu-system-riscv64")
    if qemu is None:
        print("qemu-system-riscv64 is not installed; skipping", file=sys.stderr)
        return 0
    if not KERNEL.is_file():
        print(f"no kernel at {KERNEL}; run scripts/build-riscv64.sh first",
              file=sys.stderr)
        return 2

    timeout = int(os.environ.get("XAIOS_RISCV64_TIMEOUT", "120"))
    command = [
        qemu, "-machine", "virt", "-cpu", "rv64", "-smp", "1", "-m", "256",
        "-nographic", "-bios", "default", "-kernel", str(KERNEL),
    ]
    try:
        finished = subprocess.run(command, cwd=str(ROOT), text=True,
                                  capture_output=True, timeout=timeout)
        output = finished.stdout + finished.stderr
    except subprocess.TimeoutExpired as expired:
        output = (expired.stdout or "") + (expired.stderr or "")
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        LOG.parent.mkdir(parents=True, exist_ok=True)
        LOG.write_text(output, encoding="utf-8")
        print(f"the guest did not halt within {timeout}s -- it should power "
              f"itself off through SBI rather than needing to be killed.\n"
              f"whole boot saved to {LOG.relative_to(ROOT)}", file=sys.stderr)
        return 1

    LOG.parent.mkdir(parents=True, exist_ok=True)
    LOG.write_text(output, encoding="utf-8")

    missing = [marker for marker in REQUIRED if marker not in output]
    present = [marker for marker in FORBIDDEN if marker in output]
    if missing or present:
        print("riscv64 gate failed", file=sys.stderr)
        for marker in missing:
            print(f"  missing: {marker}", file=sys.stderr)
        for marker in present:
            print(f"  forbidden: {marker}", file=sys.stderr)
        print(f"whole boot saved to {LOG.relative_to(ROOT)}", file=sys.stderr)
        return 1

    version = subprocess.run([qemu, "--version"], text=True,
                             capture_output=True).stdout.splitlines()
    print("qemu-riscv64-gate: console, traps, sv39, timer and shared kernel "
          "sha256 all verified on rv64gc")
    print(f"  {version[0] if version else 'qemu-system-riscv64'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
