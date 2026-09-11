#!/usr/bin/env python3
"""Fault the kernel on purpose, three ways, and require the stated report.

The three faults are shared kernel code: read an address nothing is mapped
at, write to read-only data, execute writable data. What differs per machine
is what the trap is called, and that is exactly what has to be asserted --
"the kernel panicked" is equally true of a machine that faulted the way it
was asked to and of one that fell over for an unrelated reason. So the class
name is per architecture and the rest is not.

The distinction matters most on the read-only and no-execute cases: a store
to read-only memory that reported a *load* fault, or an execute of data that
reported a data fault, would mean the page tables are not carrying the
permissions the boot said they were.

Every boot here gets its own durable volume, made fresh. This gate used to
take the runner's default, which is `build/xaios-persistent.img` -- the volume
every ad-hoc run on the machine has been writing to since the tree was cloned.
Roughly twenty sibling gates pass their own and reset it; this one did not, and
on a volume 64 boots deep the guest died in an unrelated self-test before any
fault was injected. All three scenarios failed and the gate reported them as
missing fault markers, which is an accusation about the fault machinery for a
condition the host created. The same three passed on a fresh volume, on the
same commit, minutes later.

That is also why a boot that never reaches `exceptions:` is now reported as
inconclusive rather than as missing markers. "The kernel did not say it was
about to fault" is true of a kernel with broken fault injection and equally
true of one that never got that far, and the two need different sentences: the
first is a defect here, the second is a defect somewhere else or nowhere. Both
still exit non-zero -- an inconclusive gate is not a passing one -- but only
one of them names the guest.
"""
import os
import select
import signal
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from qemu_gate_lib import (arch_from_argv, qemu_boot_environment, qemu_runner,
                           smoke_timeout)

ARCH = arch_from_argv(sys.argv)

# How each machine names the trap the fault produces.
FAULT_CLASS = {
    "aarch64": {"page": "class=data-abort-current",
                "ro": "class=data-abort-current",
                "nx": "class=instruction-abort-current"},
    "x86_64": {"page": "class=data-abort-current",
               "ro": "class=data-abort-current",
               "nx": "class=instruction-abort-current"},
    # RISC-V distinguishes the three, which is a stronger assertion than the
    # other two can make: a store fault and a load fault are different causes
    # here, so "the write was refused" is checkable rather than inferred.
    "riscv64": {"page": "class=load-page-fault",
                "ro": "class=store-page-fault",
                "nx": "class=instruction-page-fault"},
}[ARCH]

FAULTS = [
    (
        "page",
        [
            "exceptions: triggering controlled page fault",
            FAULT_CLASS["page"],
            "controlled page fault reported",
        ],
    ),
    (
        "ro",
        [
            "exceptions: triggering controlled rodata write fault",
            FAULT_CLASS["ro"],
            "controlled page fault reported",
        ],
    ),
    (
        "nx",
        [
            "exceptions: triggering controlled NX execute fault",
            FAULT_CLASS["nx"],
            "controlled page fault reported",
        ],
    ),
]

BUILD_COMMANDS = {
    "aarch64": [["./scripts/build-image.sh"]],
    "x86_64": [["./scripts/build-image.sh"]],
    "riscv64": [["./scripts/build-riscv64.sh"],
                ["./scripts/build-riscv64-image.sh"]],
}[ARCH]


def run_build(fault: str) -> int:
    env = os.environ.copy()
    env["XAIOS_FAULT_TEST"] = fault
    env["XAIOS_BOOT_TEST_APPS"] = "1"
    for command in BUILD_COMMANDS:
        proc = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
            check=False,
        )
        sys.stdout.write(proc.stdout)
        if proc.returncode != 0:
            return proc.returncode
    return 0


# What the guest must have printed before a missing fault marker can be read
# as a statement about fault handling. It is the line the fault injector itself
# emits on its way in, so its absence means the injector never ran.
REACHED = "exceptions: triggering controlled"

# One per scenario, per architecture, so a scenario cannot inherit the volume
# the one before it left behind either.
def fresh_persistent(name: str) -> Path:
    volume = Path(__file__).resolve().parents[2] / "build" / (
        f"fault-matrix-{ARCH}-{name}-persistent.img")
    volume.unlink(missing_ok=True)
    return volume


def run_fault_boot(name: str, targets) -> int:
    for attempt in range(2):
        env = qemu_boot_environment(
            ARCH, os.environ.copy(), hostfwd_port="none",
            # A volume of this gate's own, deleted first, so the runner makes a
            # blank one. See the note at the top: without this the boot carries
            # whatever state the machine has accumulated, and the failure that
            # produces is reported as a fault-handling defect.
            persistent=str(fresh_persistent(name)),
            # The boot is read from the runner's stdout here, and RISC-V's
            # runner writes the console to a file unless told otherwise.
            serial_to_stdout=True)
        proc = subprocess.Popen(
            [qemu_runner(ARCH)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=env,
            start_new_session=True,
        )

        seen = []
        deadline = time.time() + smoke_timeout(
            ARCH, int(os.environ.get("XAIOS_QEMU_FAULT_TIMEOUT", "60")))
        passed = False
        try:
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
                    output = "".join(seen)
                    if all(target in output for target in targets):
                        passed = True
                        break
                elif proc.poll() is not None:
                    break
        finally:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait(timeout=3)

        if passed:
            print(f"\nqemu-fault-matrix: {name} fault path passed")
            return 0

        output = "".join(seen)
        if attempt == 0 and "XAIOS loader starting" not in output:
            print(
                f"\nqemu-fault-matrix: {name} firmware did not reach the "
                "loader; retrying once"
            )
            continue
        if REACHED not in output:
            # The injector never ran, so nothing here is evidence about fault
            # handling in either direction. Say which, and say it about the
            # boot rather than about the kernel's fault paths.
            why = "the boot ended before the fault injector ran"
            if "assertion failed" in output:
                assertion = next(
                    (line.strip() for line in output.splitlines()
                     if "assertion failed" in line), "an assertion")
                why = f"the guest panicked first: {assertion}"
            elif "XAIOS loader starting" not in output:
                why = "firmware never reached the loader"
            print(f"\nqemu-fault-matrix: {name} INCONCLUSIVE, not a guest "
                  f"fault-handling defect -- {why}")
            return 2

        missing = [target for target in targets if target not in output]
        print(f"\nqemu-fault-matrix: {name} missing targets: {missing}")
        return 1
    return 1


def rebuild_normal_image() -> int:
    """Leave the tree holding a kernel that does not fault on purpose."""
    env = os.environ.copy()
    env["XAIOS_BOOT_TEST_APPS"] = "1"
    env.pop("XAIOS_FAULT_TEST", None)
    for command in BUILD_COMMANDS:
        proc = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
            check=False,
        )
        sys.stdout.write(proc.stdout)
        if proc.returncode != 0:
            return proc.returncode
    return 0


def main() -> int:
    failures = []
    inconclusive = []
    for fault, targets in FAULTS:
        print(f"\nqemu-fault-matrix: building fault image fault={fault}")
        if run_build(fault) != 0:
            failures.append(f"{fault}:build")
            continue
        status = run_fault_boot(fault, targets)
        if status == 2:
            inconclusive.append(f"{fault}:boot")
        elif status != 0:
            failures.append(f"{fault}:boot")

    print("\nqemu-fault-matrix: rebuilding normal image")
    if rebuild_normal_image() != 0:
        failures.append("normal:rebuild")

    # Both are non-zero. A gate that cannot conclude has not passed, and one
    # that reported inconclusive as success would be the more dangerous of the
    # two errors -- but the caller and the reader should be able to tell them
    # apart, and so should the exit code.
    if failures:
        print(f"qemu-fault-matrix: failed scenarios: {failures}")
        if inconclusive:
            print(f"qemu-fault-matrix: inconclusive scenarios: {inconclusive}")
        return 1
    if inconclusive:
        print(f"qemu-fault-matrix: INCONCLUSIVE, not a guest defect: "
              f"{inconclusive}")
        print("qemu-fault-matrix: nothing above is evidence about fault "
              "handling in either direction")
        return 2

    print("qemu-fault-matrix: all controlled fault scenarios passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
