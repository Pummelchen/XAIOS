#!/usr/bin/env python3
from qemu_gate_lib import BUILD, now, parse_telemetry, result, run, status_from_failures, write_report


SCHEMA = "xaios.qemu.deterministic_boot_loop.v1"
REPORT = BUILD / "qemu-milestone-55-boot-loop.json"
INVARIANT_KEYS = [
    "cpu_count",
    "pmm_total_pages",
    "virtio_block_sectors",
    "migration_total",
    "context_switch_total",
    "user_process_failed",
    "network_flow_core_mismatches",
    "persistence_checksum_errors",
]


def main() -> int:
    iterations = 3
    failures = []
    boots = []
    invariant_snapshots = []

    for index in range(iterations):
        proc = run(["python3", "./tests/scripts/qemu-smoke.py"], timeout=200,
                   env={"XAIOS_QEMU_SMOKE_TIMEOUT": "120"})
        if proc.returncode != 0:
            failures.append(f"boot {index + 1} qemu-smoke exited {proc.returncode}")
            boots.append(result(f"boot_{index + 1}", False,
                                exit_code=proc.returncode,
                                output_tail=proc.stdout[-4000:]))
            continue
        try:
            telemetry = parse_telemetry(proc.stdout)
        except ValueError as exc:
            failures.append(f"boot {index + 1} {exc}")
            boots.append(result(f"boot_{index + 1}", False, exit_code=proc.returncode))
            continue
        snapshot = {key: telemetry.get(key) for key in INVARIANT_KEYS}
        invariant_snapshots.append(snapshot)
        ok = (
            snapshot["migration_total"] == 0
            and snapshot["context_switch_total"] == 0
            and snapshot["user_process_failed"] == 0
            and snapshot["network_flow_core_mismatches"] == 0
            and snapshot["persistence_checksum_errors"] == 0
        )
        boots.append(result(f"boot_{index + 1}", ok, exit_code=0, invariants=snapshot))
        if not ok:
            failures.append(f"boot {index + 1} invariant failure: {snapshot}")

    if len(invariant_snapshots) == iterations:
        baseline = invariant_snapshots[0]
        for index, snapshot in enumerate(invariant_snapshots[1:], start=2):
            for key in ["cpu_count", "pmm_total_pages", "virtio_block_sectors"]:
                if snapshot.get(key) != baseline.get(key):
                    failures.append(
                        f"boot {index} non-deterministic {key}: {snapshot.get(key)} != {baseline.get(key)}"
                    )

    report = {
        "schema": SCHEMA,
        "status": status_from_failures(failures),
        "milestone": 55,
        "created_at_unix": now(),
        "description": "Repeated QEMU boot loop validating deterministic boot invariants and zero hot-path migration/context-switch counters.",
        "iterations": iterations,
        "boots": boots,
        "failures": failures,
    }
    write_report(REPORT, report)
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
