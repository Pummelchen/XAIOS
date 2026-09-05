#!/usr/bin/env python3
"""What this machine is, held to what it said.

The shared gates ask every architecture the same questions, which is right
for the things every architecture has to do and useless for the things only
this one has. A PLIC is not a GIC; an instruction cache that needs fence.i is
not one that snoops; firmware reached by ecall is not firmware reached by
SMC. This reads the report the kernel emits about those and requires the
answers this project depends on.

Two kinds of assertion, kept apart on purpose.

REQUIRED are answers that, if they changed, would mean the kernel is wrong:
Sv48 is live, kernel text is executable and not writable, data is neither
executable nor -- these are what the page tables are for, and RISC-V spells
them as PTE bits this port sets per section.

REPORTED are properties of the machine rather than of the kernel: which SBI
extensions the firmware offers, whether a misaligned load completes. Those
are printed for the record and not asserted, because a different board may
answer differently without anything being broken. Asserting them would make
this gate a description of QEMU.
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOG = ROOT / "build" / "qemu-riscv64-isa-gate.log"
BOOT_TIMEOUT_SECONDS = float(os.environ.get("XAIOS_RISCV64_ISA_TIMEOUT", "600"))

# Answers whose change would mean a defect.
REQUIRED = [
    # Sv48, not the Sv39 a machine may default to. Every mapping the kernel
    # makes assumes the depth it built its tables for.
    ("sv48 paging is live",
     re.compile(r"riscv-isa: satp mode=9 ")),
    # W^X, spelled in PTE bits. Kernel text must be executable and not
    # writable; writable data must not be executable. The first version of
    # the kernel's own test wrote code into a data buffer and jumped to it,
    # and faulted -- which is this property working.
    ("kernel text is executable and not writable",
     re.compile(r"riscv-isa: fence\.i accepted; text x=1 w=0 ")),
    ("writable data is not executable",
     re.compile(r"riscv-isa: fence\.i accepted; text x=1 w=0 data x=0 w=1")),
    # The supervisor can reach firmware at all, and firmware answers rather
    # than accepting everything: an extension that cannot exist must probe
    # as absent, or every other probe means nothing.
    ("firmware answers a probe for an absent extension with no",
     re.compile(r"riscv-isa: sbi absent-extension probe answered 0")),
    # Hart state management refuses a hart that does not exist. A firmware
    # that answered for any hart id would make hart bring-up unverifiable.
    ("hart state management refuses a hart that does not exist",
     re.compile(r"riscv-isa: hsm absent-hart refused=1 ")),
    # The self-test ran to the end rather than faulting part way through.
    ("the architecture self-test completed",
     re.compile(r"riscv-isa: self-test passed")),
    # Harts are leasable, which is what the AI cell lifecycle needs and what
    # this architecture answered "unsupported" to until recently.
    ("a hart can be leased out of the scheduler",
     re.compile(r"smp: hart\d+ leased owner=\d+ role=ai-hot")),
    # Secondaries come online before the self-tests that need one, and still
    # do not schedule until the rendezvous.
    ("secondaries are online and holding before the rendezvous",
     re.compile(r"smp: riscv64 \d+ harts online, scheduling held until the "
                r"rendezvous")),
]

# Printed, not required.
REPORTED = [
    re.compile(r"riscv-isa: sbi spec=[^\n]*"),
    re.compile(r"riscv-isa: sbi extensions[^\n]*"),
    re.compile(r"riscv-isa: misaligned[^\n]*"),
    re.compile(r"riscv-isa: sstatus[^\n]*"),
    re.compile(r"timer: riscv64 rdtime[^\n]*"),
    re.compile(r"exception: plic at[^\n]*"),
    re.compile(r"irq: riscv64 plic[^\n]*"),
    re.compile(r"smmu: riscv64[^\n]*"),
]

FORBIDDEN = [
    ("kernel panic", re.compile(r"CYAN SCREEN OF DEATH")),
    ("assertion failure", re.compile(r"ERROR: assertion failed")),
]


def boot() -> str:
    LOG.parent.mkdir(parents=True, exist_ok=True)
    LOG.unlink(missing_ok=True)
    environment = dict(os.environ,
                       XAIOS_RISCV64_LOG=str(LOG),
                       XAIOS_RISCV64_CPUS="4")
    process = subprocess.Popen(
        [str(ROOT / "platform" / "qemu" / "run-qemu-riscv64.sh")],
        cwd=ROOT, env=environment, stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + BOOT_TIMEOUT_SECONDS
    text = ""
    try:
        while time.monotonic() < deadline:
            time.sleep(2.0)
            if not LOG.is_file():
                continue
            text = LOG.read_text(errors="replace")
            if all(pattern.search(text) for _, pattern in REQUIRED):
                break
            if any(pattern.search(text) for _, pattern in FORBIDDEN):
                break
            if process.poll() is not None:
                break
    finally:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
    return LOG.read_text(errors="replace") if LOG.is_file() else text


def main() -> int:
    text = boot()
    print(f"+ boot log: {LOG.relative_to(ROOT)} ({len(text)} bytes)", flush=True)

    print("+ what this machine reports about itself:", flush=True)
    for pattern in REPORTED:
        match = pattern.search(text)
        print(f"    {match.group(0).strip() if match else '(not reported)'}")

    failures = []
    for name, pattern in REQUIRED:
        if pattern.search(text):
            print(f"  ok   {name}")
        else:
            print(f"  FAIL {name}")
            failures.append(name)
    for name, pattern in FORBIDDEN:
        if pattern.search(text):
            print(f"  FAIL {name}")
            failures.append(name)

    if failures:
        print(f"qemu-riscv64-isa-gate: {len(failures)} failed: "
              f"{', '.join(failures)}")
        return 1
    print(f"qemu-riscv64-isa-gate: {len(REQUIRED)} architecture properties "
          f"hold on this machine")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
