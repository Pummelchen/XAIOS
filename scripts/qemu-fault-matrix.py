#!/usr/bin/env python3
import os
import select
import signal
import subprocess
import sys
import time


FAULTS = [
    (
        "page",
        [
            "exceptions: triggering controlled page fault",
            "class=data-abort-current",
            "controlled page fault reported",
        ],
    ),
    (
        "ro",
        [
            "exceptions: triggering controlled rodata write fault",
            "class=data-abort-current",
            "controlled page fault reported",
        ],
    ),
    (
        "nx",
        [
            "exceptions: triggering controlled NX execute fault",
            "class=instruction-abort-current",
            "controlled page fault reported",
        ],
    ),
]


def run_build(fault: str) -> int:
    env = os.environ.copy()
    env["XAIOS_FAULT_TEST"] = fault
    proc = subprocess.run(
        ["./scripts/build-image.sh"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
        check=False,
    )
    sys.stdout.write(proc.stdout)
    return proc.returncode


def run_fault_boot(name: str, targets) -> int:
    for attempt in range(2):
        env = os.environ.copy()
        env["XAIOS_QEMU_HOSTFWD_PORT"] = "none"
        proc = subprocess.Popen(
            ["./scripts/run-qemu-aarch64.sh"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=env,
            start_new_session=True,
        )

        seen = []
        deadline = time.time() + int(
            os.environ.get("XAIOS_QEMU_FAULT_TIMEOUT", "60")
        )
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
        missing = [target for target in targets if target not in output]
        print(f"\nqemu-fault-matrix: {name} missing targets: {missing}")
        return 1
    return 1


def rebuild_normal_image() -> int:
    proc = subprocess.run(
        ["./scripts/build-image.sh"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
    )
    sys.stdout.write(proc.stdout)
    return proc.returncode


def main() -> int:
    failures = []
    for fault, targets in FAULTS:
        print(f"\nqemu-fault-matrix: building fault image fault={fault}")
        if run_build(fault) != 0:
            failures.append(f"{fault}:build")
            continue
        if run_fault_boot(fault, targets) != 0:
            failures.append(f"{fault}:boot")

    print("\nqemu-fault-matrix: rebuilding normal image")
    if rebuild_normal_image() != 0:
        failures.append("normal:rebuild")

    if failures:
        print(f"qemu-fault-matrix: failed scenarios: {failures}")
        return 1

    print("qemu-fault-matrix: all controlled fault scenarios passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
