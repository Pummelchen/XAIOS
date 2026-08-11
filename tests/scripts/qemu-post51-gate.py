#!/usr/bin/env python3
import json
from qemu_gate_lib import BUILD, now, result, run, status_from_failures, write_report


SCHEMA = "xaios.qemu.post51_gate.v1"
REPORT = BUILD / "qemu-post51-gate-report.json"

MILESTONE_COMMANDS = [
    (52, "regression_suite", ["python3", "./tests/scripts/qemu-regression-suite.py"]),
    (53, "fault_injection", ["python3", "./tests/scripts/qemu-fault-injection.py"]),
    (54, "abi_contract", ["python3", "./tests/scripts/qemu-abi-contract.py"]),
    (55, "boot_loop", ["python3", "./tests/scripts/qemu-boot-loop.py"]),
    (56, "userspace_suite", ["python3", "./tests/scripts/qemu-userspace-suite.py"]),
    (57, "network_suite", ["python3", "./tests/scripts/qemu-network-suite.py"]),
    (58, "cpu_ai_suite", ["python3", "./tests/scripts/qemu-cpu-ai-suite.py"]),
    (59, "developer_ux", ["python3", "./tests/scripts/qemu-developer-ux.py"]),
]


def main() -> int:
    failures = []
    milestones = []
    for milestone, name, cmd in MILESTONE_COMMANDS:
        proc = run(cmd, timeout=360)
        ok = proc.returncode == 0
        milestones.append(result(name, ok, milestone=milestone,
                                  exit_code=proc.returncode))
        if not ok:
            failures.append(f"milestone {milestone} {name} exited {proc.returncode}")
            print(proc.stdout)
        else:
            print(f"qemu-post51-gate: milestone {milestone} {name} passed")

    report = {
        "schema": SCHEMA,
        "status": status_from_failures(failures),
        "created_at_unix": now(),
        "description": "Aggregate QEMU-only post-51 gate covering milestones 52 through 59 before physical hardware testing.",
        "milestones": milestones,
        "failures": failures,
        "performance_claims_allowed": False,
    }
    write_report(REPORT, report)
    print(f"qemu-post51-gate: report={json.dumps(report, sort_keys=True)}")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
