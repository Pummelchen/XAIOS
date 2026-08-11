#!/usr/bin/env python3
import os
from qemu_gate_lib import BUILD, now, result, run, status_from_failures, write_report


SCHEMA = "xaios.qemu.soak_gate.v1"
REPORT = BUILD / "qemu-milestone-69-soak-gate.json"


def main() -> int:
    iterations = int(os.environ.get("XAIOS_QEMU_SOAK_BOOTS", "5"))
    failures = []
    checks = []
    for index in range(iterations):
        proc = run(["python3", "./tests/scripts/qemu-smoke.py"], timeout=180)
        ok = proc.returncode == 0
        checks.append(result("smoke_boot", ok, iteration=index + 1,
                             exit_code=proc.returncode))
        if not ok:
            failures.append(f"smoke iteration {index + 1} exited {proc.returncode}")
            break
    report = {
        "schema": SCHEMA,
        "status": status_from_failures(failures),
        "milestone": 69,
        "created_at_unix": now(),
        "iterations_requested": iterations,
        "iterations_completed": len(checks),
        "checks": checks,
        "failures": failures,
    }
    write_report(REPORT, report)
    if failures:
        print("qemu-soak-gate: failed")
        for failure in failures:
            print(f" - {failure}")
        return 1
    print(f"qemu-soak-gate: milestone 69 passed boots={iterations}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
