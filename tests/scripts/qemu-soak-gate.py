#!/usr/bin/env python3
import os
import sys

from qemu_gate_lib import (BUILD, arch_from_argv, now, result, run,
                           smoke_command, smoke_timeout, status_from_failures,
                           write_report)

ARCH = arch_from_argv(sys.argv)
SUFFIX = "" if ARCH == "aarch64" else f"-{ARCH}"

SCHEMA = "xaios.qemu.soak_gate.v1"
REPORT = BUILD / f"qemu-milestone-69-soak-gate{SUFFIX}.json"


def main() -> int:
    iterations = int(os.environ.get("XAIOS_QEMU_SOAK_BOOTS", "5"))
    per_boot = str(smoke_timeout(
        ARCH, int(os.environ.get("XAIOS_QEMU_SOAK_SMOKE_TIMEOUT", "120"))))
    failures = []
    checks = []
    for index in range(iterations):
        proc = run(
            smoke_command(ARCH),
            timeout=int(per_boot) + 30,
            env={"XAIOS_QEMU_SMOKE_TIMEOUT": per_boot},
        )
        ok = proc.returncode == 0
        detail = {}
        if not ok:
            output_tail = proc.stdout[-4096:]
            detail["output_tail"] = output_tail
            print(output_tail, end="" if output_tail.endswith("\n") else "\n")
        checks.append(result("smoke_boot", ok, iteration=index + 1,
                             exit_code=proc.returncode, **detail))
        if not ok:
            failures.append(f"smoke iteration {index + 1} exited {proc.returncode}")
            break
    report = {
        "schema": SCHEMA,
        "status": status_from_failures(failures),
        "milestone": 69,
        "created_at_unix": now(),
        "arch": ARCH,
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
    print(f"qemu-soak-gate: milestone 69 passed arch={ARCH} boots={iterations}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
