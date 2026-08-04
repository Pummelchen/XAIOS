#!/usr/bin/env python3
from qemu_gate_lib import (BUILD, check_markers, contract, now, parse_telemetry,
                           result, run, status_from_failures,
                           validate_telemetry_against_contract, write_report)


SCHEMA = "xaios.qemu.regression_suite.v1"
REPORT = BUILD / "qemu-milestone-52-regression-suite.json"

MARKER_GROUPS = {
    "process_lifecycle": [
        "user: process pid=1 name=/init state=running",
        "user: /init exited status=0",
        "kernel: /init returned to kernel exit_code=0",
        "user: process pid=2 name=/bin/service-manager state=running",
        "kernel: /bin/service-manager returned to kernel exit_code=0",
    ],
    "filesystem_rollback": [
        "mutable-fs: snapshot committed",
        "mutable-fs: snapshot rollback",
        "mutable-fs: journal replay self-test passed",
        "persistence: disk reload/rollback self-test passed",
    ],
    "ai_cell_conflicts": [
        "ai-cell: descriptor ABI self-test passed accepts=5 rejects=4",
        "ai-cell: resource contract self-test passed admissions=2 rejects=10",
        "nic-conflict-agent",
        "core-conflict-agent",
        "workspace-conflict-agent",
    ],
    "network_state": [
        "network: udp flow id=",
        "expired queue=",
        "retransmit=1",
        "network: queue-backed udp/tcp self-test passed",
    ],
    "security_denials": [
        "security: self-test passed denied=15",
        "/init: bad syscall tests passed",
        "/service-manager: missing capability tests passed",
        "admin: remote-safe command=shell rejected",
    ],
}


def main() -> int:
    proc = run(["python3", "./scripts/qemu-smoke.py"], timeout=140)
    text = proc.stdout
    failures = []
    checks = []
    rc_contract = contract()
    telemetry = {}

    if proc.returncode != 0:
        failures.append(f"qemu-smoke exited {proc.returncode}")
    else:
        try:
            telemetry = parse_telemetry(text)
            failures.extend(validate_telemetry_against_contract(telemetry, rc_contract))
        except ValueError as exc:
            failures.append(str(exc))

    for group, markers in MARKER_GROUPS.items():
        missing = check_markers(text, markers)
        checks.append(result(group, not missing, missing_markers=missing))
        failures.extend(f"{group} missing marker: {marker}" for marker in missing)

    report = {
        "schema": SCHEMA,
        "status": status_from_failures(failures),
        "milestone": 52,
        "created_at_unix": now(),
        "description": "QEMU regression suite for process, filesystem, AI Cell, networking, security, and telemetry contracts.",
        "smoke_exit_code": proc.returncode,
        "checks": checks,
        "telemetry_keys": sorted(telemetry.keys()),
        "failures": failures,
    }
    write_report(REPORT, report)
    print(proc.stdout)
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
