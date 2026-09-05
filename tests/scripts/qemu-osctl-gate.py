#!/usr/bin/env python3
import sys
from qemu_gate_lib import (arch_from_argv, smoke_command,
                           smoke_timeout, BUILD, check_markers, now, parse_telemetry, result,
                           run, status_from_failures, write_report)


SCHEMA = "xaios.qemu.osctl_gate.v1"
REPORT = BUILD / "qemu-milestone-61-osctl-gate.json"

MARKERS = [
    "user: osctl command='osctl status'",
    "osctl: status legacy=1 processes=",
    "user: osctl command='osctl ps'",
    "osctl: ps slots=1024",
    "user: osctl command='osctl services'",
    "osctl: services transitions=",
    "user: osctl command='osctl cells'",
    "osctl: cells transitions=",
    "user: osctl command='osctl fs'",
    "osctl: fs files=",
    "user: osctl command='osctl net'",
    "osctl: net udp_tx=",
    "user: osctl command='osctl telemetry'",
    "osctl: telemetry cpu_ai_loads=",
    "user: osctl command='osctl update'",
    "osctl: update transactions=",
    "user: osctl command='osctl rollback'",
    "osctl: rollback persistence=",
    "/service-manager: osctl command surface passed",
]


def main() -> int:
    arch = arch_from_argv(sys.argv[1:])
    proc = run(smoke_command(arch), timeout=smoke_timeout(arch, 160))
    failures = []
    checks = []

    if proc.returncode != 0:
        failures.append(f"qemu-smoke exited {proc.returncode}")

    missing = check_markers(proc.stdout, MARKERS)
    checks.append(result("osctl_markers", not missing, missing_markers=missing))
    failures.extend(f"missing osctl marker: {marker}" for marker in missing)

    telemetry = {}
    try:
        telemetry = parse_telemetry(proc.stdout)
    except ValueError as exc:
        failures.append(str(exc))

    control_plane = telemetry.get("control_plane_syscalls") if telemetry else None
    if not isinstance(control_plane, int) or control_plane < 34:
        failures.append(
            f"control_plane_syscalls expected >= 34, got {control_plane!r}")

    checks.append(result("control_plane_telemetry",
                         isinstance(control_plane, int) and control_plane >= 34,
                         control_plane_syscalls=control_plane))

    report = {
        "schema": SCHEMA,
        "generated_at": now(),
        "status": status_from_failures(failures),
        "checks": checks,
        "telemetry": telemetry,
        "failures": failures,
    }
    write_report(REPORT, report)
    if failures:
        print("qemu-osctl-gate: failed")
        for failure in failures:
            print(f" - {failure}")
        return 1

    print("qemu-osctl-gate: milestone 61 userspace command surface gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
