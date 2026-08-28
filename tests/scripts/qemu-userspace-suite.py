#!/usr/bin/env python3
import json
import re

from qemu_gate_lib import BUILD, check_markers, now, result, run, status_from_failures, write_report


SCHEMA = "xaios.qemu.userspace_expansion.v1"
REPORT = BUILD / "qemu-milestone-56-userspace-suite.json"

COMMAND_MARKERS = {
    "osctl_status": ["osctl: /svc/source-index state=running"],
    "osctl_services": [
        "service: /init state=running",
        "service-supervisor: tree parent=/init child=/svc/source-index children=1 edges=1",
    ],
    "osctl_cells": [
        "ai-cell: lifecycle self-test passed",
        "ai-cell: multi-cell shared model/private kv self-test passed",
    ],
    "osctl_telemetry": [
        "\"ai_cell_transitions\":14",
    ],
    "osctl_rollback": [
        "xaibootfs: snapshot rollback",
        "\"persistence_rollbacks\":7",
        "\"update_rollbacks\":1",
    ],
    "service_manager_commands": [
        "/service-manager: child service supervised",
        "/service-manager: admin status exported",
        "/service-manager: remote-safe checks passed",
        "/service-manager: control plane complete",
        "/worker: scheduled child process ran",
        "kernel: /bin/xaios-worker pid=5 returned to kernel exit_code=0",
        "/bin/xaios-shell: command surface passed 1..15 + ls variants + tar/cpio archive",
        "/bin/hello: C toolchain and EL0 runtime integration passed",
        "/bin/sysinfo: complete",
        "/bin/systest: syscall and filesystem suite passed",
        "/bin/smptest: complete",
        "/bin/nettest: complete",
        "/bin/sshtest: complete",
        "/bin/mltest: complete",
        "/bin/smptest: app-requested SMP worker set passed",
        "/bin/smptest: concurrent kernel-dispatched worker group passed",
        "/bin/nettest: app-callable udp/tcp path passed",
        "/bin/nettest: external host-to-guest tcp/udp session path passed",
        "/bin/lstm-xor: cpu-ai fixture decode=",
        "/bin/lstm-xor: xor solve passed predictions=0,1,1,0",
        "/bin/sshtest: interactive remote login command surface passed",
        "/bin/mltest: multi-model CPU-only ML runtime passed",
    ],
}


def main() -> int:
    proc = run(["python3", "./tests/scripts/qemu-smoke.py"], timeout=140)
    failures = []
    checks = []
    if proc.returncode != 0:
        failures.append(f"qemu-smoke exited {proc.returncode}")

    for command, markers in COMMAND_MARKERS.items():
        missing = check_markers(proc.stdout, markers)
        checks.append(result(command, not missing, missing_markers=missing))
        failures.extend(f"{command} missing marker: {marker}" for marker in missing)

    telemetry_matches = re.findall(r"^telemetry: (\{.*\})$", proc.stdout, re.MULTILINE)
    telemetry_failures = []
    if not telemetry_matches:
        telemetry_failures.append("telemetry JSON record missing")
    else:
        try:
            telemetry = json.loads(telemetry_matches[-1])
        except json.JSONDecodeError as exc:
            telemetry_failures.append(f"telemetry JSON invalid: {exc}")
        else:
            for field, minimum in (
                ("control_plane_syscalls", 160),
                ("user_process_loaded", 14),
                ("user_process_scheduled", 14),
            ):
                value = telemetry.get(field)
                if not isinstance(value, int) or value < minimum:
                    telemetry_failures.append(
                        f"{field} expected at least {minimum}, observed {value!r}"
                    )
    checks.append(result("osctl_telemetry_ranges", not telemetry_failures,
                         failures=telemetry_failures))
    failures.extend(telemetry_failures)

    report = {
        "schema": SCHEMA,
        "status": status_from_failures(failures),
        "milestone": 56,
        "created_at_unix": now(),
        "description": "Userspace control-plane expansion gate for osctl-style service, cell, telemetry, rollback, and admin operations.",
        "smoke_exit_code": proc.returncode,
        "checks": checks,
        "failures": failures,
    }
    write_report(REPORT, report)
    print(proc.stdout)
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
