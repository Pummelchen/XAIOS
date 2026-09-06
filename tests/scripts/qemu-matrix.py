#!/usr/bin/env python3
import os
import subprocess
import sys
import time


SCENARIOS = [
    ("qemu-smoke", ["make", "qemu-smoke"], 120, 0),
    ("qemu-benchmark", ["python3", "./tests/scripts/qemu-benchmark.py"], 120, 0),
    ("qemu-persistence-reboot", ["make", "qemu-persistence-reboot"], 140, 0),
    ("qemu-preview", ["make", "qemu-preview"], 120, 0),
    ("qemu-fault-matrix", ["make", "qemu-fault-matrix"], 360, 0),
    ("qemu-x86_64-smoke", ["make", "qemu-x86_64-smoke"], 120, 0),
    ("intel-desktop-gate", ["python3", "./tests/scripts/intel-desktop-gate.py"], 140, 1),
    ("qemu-cpu-matrix", ["make", "qemu-cpu-matrix"], 900, 0),
    ("qemu-dry-run-aarch64", ["./platform/qemu/run-qemu-aarch64.sh", "--dry-run"], 10, 0),
    ("qemu-dry-run-x86_64", ["./platform/qemu/run-qemu-x86_64.sh", "--dry-run"], 10, 0),
    # The third architecture, on the same terms as the other two.
    #
    # This matrix is where the family is checked as a family, and RISC-V was
    # missing from it -- so every scenario here was a statement about two
    # architectures wearing the name of all three. The budgets are larger
    # because the machine is: RISC-V runs this closure through an interpreter
    # with no host acceleration, and reusing AArch64's numbers would report a
    # slower machine as a broken one. They are deadlines, not delays.
    ("qemu-riscv64-smoke", ["make", "qemu-riscv64-smoke"], 480, 0),
    ("qemu-riscv64-benchmark", ["make", "qemu-riscv64-benchmark"], 600, 0),
    ("qemu-riscv64-persistence-reboot",
     ["make", "qemu-riscv64-persistence-reboot"], 700, 0),
    ("qemu-dry-run-riscv64", ["./platform/qemu/run-qemu-riscv64.sh", "--dry-run"], 10, 0),
]


def run_scenario(name: str, cmd, timeout: int, expected_rc: int, env) -> bool:
    print(f"\n[QEMU matrix] running {name}: {' '.join(cmd)}", flush=True)
    start = time.time()
    try:
        proc = subprocess.run(
            cmd,
            stdout=None,
            stderr=None,
            timeout=timeout,
            env=env,
            text=True,
            check=False,
        )
    except subprocess.TimeoutExpired:
        elapsed = time.time() - start
        print(f"[QEMU matrix] {name} timed out after {elapsed:.2f}s "
              f"(budget={timeout}s)")
        return False
    except OSError as exc:
        elapsed = time.time() - start
        print(f"[QEMU matrix] {name} could not start after {elapsed:.2f}s: {exc}")
        return False
    elapsed = time.time() - start
    passed = proc.returncode == expected_rc
    print(f"[QEMU matrix] {name} exit={proc.returncode} expected={expected_rc} elapsed={elapsed:.2f}s")
    return passed


def main() -> int:
    env = os.environ.copy()
    env.setdefault("XAIOS_QEMU_SMOKE_TIMEOUT", "60")
    failures = []
    for name, cmd, timeout, expected_rc in SCENARIOS:
        passed = run_scenario(name, cmd, timeout, expected_rc, env)
        if not passed:
            failures.append((name, expected_rc))
    if failures:
        print("\nqemu-matrix: failed scenarios:")
        for name, expected_rc in failures:
            print(f"  {name}: did not return expected rc={expected_rc}")
        return 1
    print("\nqemu-matrix: all scenarios passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
