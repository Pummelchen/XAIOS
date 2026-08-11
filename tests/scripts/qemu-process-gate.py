#!/usr/bin/env python3
from qemu_gate_lib import (BUILD, check_markers, now, parse_telemetry, result,
                           run, status_from_failures, write_report)


SCHEMA = "xaios.qemu.process_scheduler_gate.v1"
REPORT = BUILD / "qemu-milestone-60-process-gate.json"

MARKERS = [
    "user: process table initialized slots=1024",
    "scheduler: lifecycle self-test passed",
    "scheduler: process pid=3 parent=2 runnable name=/bin/xaios-worker",
    "scheduler: dispatch pid=3 parent=2 name=/bin/xaios-worker",
    "kernel: /bin/xaios-worker pid=3 returned to kernel exit_code=0",
    "scheduler: process pid=4 parent=2 runnable name=/bin/xaios-worker",
    "scheduler: dispatch pid=4 parent=2 name=/bin/xaios-worker",
    "kernel: /bin/xaios-worker pid=4 returned to kernel exit_code=0",
    "scheduler: process pid=5 parent=2 runnable name=/bin/xaios-worker",
    "scheduler: dispatch pid=5 parent=2 name=/bin/xaios-worker",
    "kernel: /bin/xaios-worker pid=5 returned to kernel exit_code=0",
    "/worker: scheduled child process ran",
]

MINIMUMS = {
    "user_process_transitions": 39,
    "user_process_loaded": 12,
    "user_process_runnable": 3,
    "user_process_running": 12,
    "user_process_exited": 12,
    "user_process_reclaims": 12,
    "user_process_scheduled": 12,
}

EQUALS = {
    "user_process_failed": 0,
    "user_process_active": 0,
}


def main() -> int:
    proc = run(["python3", "./tests/scripts/qemu-smoke.py"], timeout=160)
    failures = []
    checks = []

    if proc.returncode != 0:
        failures.append(f"qemu-smoke exited {proc.returncode}")

    missing = check_markers(proc.stdout, MARKERS)
    checks.append(result("process_markers", not missing, missing_markers=missing))
    failures.extend(f"missing process marker: {marker}" for marker in missing)

    telemetry = {}
    try:
        telemetry = parse_telemetry(proc.stdout)
    except ValueError as exc:
        failures.append(str(exc))

    if telemetry:
        metric_failures = []
        for key, minimum in MINIMUMS.items():
            value = telemetry.get(key)
            if not isinstance(value, int) or value < minimum:
                metric_failures.append(f"{key} expected >= {minimum}, got {value!r}")
        for key, expected in EQUALS.items():
            value = telemetry.get(key)
            if value != expected:
                metric_failures.append(f"{key} expected {expected}, got {value!r}")
        checks.append(result("process_telemetry", not metric_failures,
                             failures=metric_failures))
        failures.extend(metric_failures)

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
        print("qemu-process-gate: failed")
        for failure in failures:
            print(f" - {failure}")
        return 1

    print("qemu-process-gate: milestone 60 process scheduler gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
