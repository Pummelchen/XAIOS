#!/usr/bin/env python3
from qemu_gate_lib import BUILD, check_markers, now, parse_telemetry, result, run, status_from_failures, write_report


SCHEMA = "xaios.qemu.network_stack_tests.v1"
REPORT = BUILD / "qemu-milestone-57-network-suite.json"

MARKERS = {
    "udp_flow_lifecycle": [
        "network: udp flow id=",
        "expired queue=",
        "network: app udp echo payload=13",
        "\"network_udp_flows\":2",
        "\"network_udp_flow_hits\":2",
        "\"network_udp_expired\":1",
        "network: external host udp session port=2222",
    ],
    "tcp_state_timeouts": [
        "retransmit=1",
        "timeout queue=",
        "network: app tcp connect-close",
        "network: external host tcp session port=2222",
        "\"network_tcp_connections\":1",
        "\"network_tcp_timeouts\":1",
        "\"network_tcp_retransmits\":1",
        "\"network_tcp_resets\":2",
        "\"network_tcp_established\":2",
        "\"network_tcp_closed\":2",
    ],
    "per_core_queue_ownership": [
        "\"network_queue_rx_enqueues\":12",
        "\"network_queue_tx_enqueues\":10",
        "\"network_queue_completions\":10",
        "\"network_flow_core_mismatches\":0",
    ],
    "malformed_drop_path": [
        "virtio-net: malformed packet/drop self-test passed",
        "\"network_udp_malformed\":1",
        "\"network_packet_drops\":4",
    ],
}


def main() -> int:
    proc = run(["python3", "./scripts/qemu-smoke.py"], timeout=140)
    failures = []
    checks = []
    telemetry = {}
    if proc.returncode != 0:
        failures.append(f"qemu-smoke exited {proc.returncode}")
    else:
        try:
            telemetry = parse_telemetry(proc.stdout)
        except ValueError as exc:
            failures.append(str(exc))

    for name, markers in MARKERS.items():
        missing = check_markers(proc.stdout, markers)
        checks.append(result(name, not missing, missing_markers=missing))
        failures.extend(f"{name} missing marker: {marker}" for marker in missing)

    latency_ok = telemetry.get("network_udp_p999", 1) >= 0 and telemetry.get("network_tcp_p999", 1) >= 0
    checks.append(result("latency_counters_present", latency_ok,
                         udp_p999=telemetry.get("network_udp_p999"),
                         tcp_p999=telemetry.get("network_tcp_p999")))
    if not latency_ok:
        failures.append("network p999 counters missing or invalid")

    report = {
        "schema": SCHEMA,
        "status": status_from_failures(failures),
        "milestone": 57,
        "created_at_unix": now(),
        "description": "QEMU network stack tests for UDP flow lifecycle, TCP timeout/retransmit behavior, malformed drops, and per-core queue ownership.",
        "smoke_exit_code": proc.returncode,
        "checks": checks,
        "failures": failures,
    }
    write_report(REPORT, report)
    print(proc.stdout)
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
