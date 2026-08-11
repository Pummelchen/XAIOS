#!/usr/bin/env python3
from qemu_gate_lib import BUILD, now, result, run, status_from_failures, write_report


SCHEMA = "xaios.qemu.100_gate.v1"
REPORT = BUILD / "qemu-100-report.json"

COMMANDS = [
    (62, "filesystem", ["python3", "./tests/scripts/qemu-milestone-gate.py", "62"]),
    (63, "app_agent", ["python3", "./tests/scripts/qemu-milestone-gate.py", "63"]),
    (64, "network_full", ["python3", "./tests/scripts/qemu-milestone-gate.py", "64"]),
    (65, "cpu_ai_runtime", ["python3", "./tests/scripts/qemu-milestone-gate.py", "65"]),
    (66, "ai_cell", ["python3", "./tests/scripts/qemu-milestone-gate.py", "66"]),
    (67, "security", ["python3", "./tests/scripts/qemu-milestone-gate.py", "67"]),
    (68, "update", ["python3", "./tests/scripts/qemu-milestone-gate.py", "68"]),
    (69, "soak", ["python3", "./tests/scripts/qemu-soak-gate.py"]),
    (70, "release", ["python3", "./tests/scripts/qemu-release.py"]),
    (71, "ssh", ["python3", "./tests/scripts/qemu-ssh-smoke.py"]),
]


def main() -> int:
    failures = []
    checks = []
    for milestone, name, command in COMMANDS:
        proc = run(command, timeout=1200)
        ok = proc.returncode == 0
        checks.append(result(name, ok, milestone=milestone,
                             exit_code=proc.returncode))
        if not ok:
            failures.append(f"milestone {milestone} {name} exited {proc.returncode}")
            break
    report = {
        "schema": SCHEMA,
        "status": status_from_failures(failures),
        "milestone": 71,
        "created_at_unix": now(),
        "qemu_full_os_complete": not failures,
        "performance_claims_allowed": False,
        "checks": checks,
        "failures": failures,
    }
    write_report(REPORT, report)
    if failures:
        print("qemu-100-gate: failed")
        for failure in failures:
            print(f" - {failure}")
        return 1
    print("qemu-100-gate: milestone 71 passed; QEMU target complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
