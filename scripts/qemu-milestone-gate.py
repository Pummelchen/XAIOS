#!/usr/bin/env python3
import sys
from qemu_gate_lib import (BUILD, check_markers, now, parse_telemetry, result,
                           run, status_from_failures, write_report)


GATES = {
    "62": {
        "schema": "xaios.qemu.filesystem_gate.v1",
        "report": "qemu-milestone-62-filesystem-gate.json",
        "name": "filesystem",
        "markers": [
            "mutable-fs: mounted start=3072 metadata=16 journal=2 data=3090 sectors=96 nodes=32 policy=rw",
            "mutable-fs: public API self-test passed list=1 stat=3 rename=1 open=3 close=3",
            "mutable-fs: journal replay self-test passed replays=1 journal_writes=1",
            "mutable-fs: self-test passed files=7 directories=15 writes=12 reads=6 deletes=1 commits=1 rollbacks=1 replays=1 rejects=8 checksum_errors=0",
            "/service-manager: mutable fs syscalls passed",
        ],
        "minimums": {
            "mutable_fs_files": 8,
            "mutable_fs_directories": 13,
            "mutable_fs_writes": 33,
            "mutable_fs_reads": 12,
            "mutable_fs_renames": 3,
            "mutable_fs_lists": 3,
            "mutable_fs_stats": 5,
            "mutable_fs_opens": 10,
            "mutable_fs_closes": 10,
            "mutable_fs_rejects": 8,
            "control_plane_syscalls": 81,
        },
        "equals": {"mutable_fs_checksum_errors": 0},
    },
    "63": {
        "schema": "xaios.qemu.app_agent_gate.v1",
        "report": "qemu-milestone-63-app-agent-gate.json",
        "name": "app_agent",
        "markers": [
            "source-index: fixture loaded files=2 symbols=2 updates=1",
            "git-workspace: self-test passed sync=4 apply=1 revert=1 conflicts=2",
            "sandbox: lifecycle self-test passed active=1 transitions=4",
            "mutable-fs: write path=/state/workspaces/workspace-0.state",
            "service-supervisor: restarting child /svc/source-index parent=/init attempt=2",
        ],
        "minimums": {
            "source_index_files": 2,
            "source_index_symbols": 2,
            "source_index_updates": 1,
            "git_workspace_active": 2,
            "git_workspace_syncs": 4,
            "git_workspace_applies": 1,
            "git_workspace_reverts": 1,
            "git_workspace_conflicts": 2,
            "sandbox_transitions": 4,
        },
        "equals": {},
    },
    "64": {
        "schema": "xaios.qemu.network_full_gate.v1",
        "report": "qemu-milestone-64-network-full-gate.json",
        "name": "network_full",
        "markers": [
            "network: stack initialized",
            "network: udp flow id=",
            "network: tcp flow id=",
            "network: queue-backed udp/tcp self-test passed rx=6 tx=6 drops=2 lifecycle=18",
            "network: app udp echo payload=13",
            "network: app tcp connect-close",
            "virtio-net: queue/tx/parser/reset self-test passed",
        ],
        "minimums": {
            "network_udp_tx": 5,
            "network_udp_rx": 5,
            "network_udp_flow_hits": 2,
            "network_udp_expired": 1,
            "network_tcp_handshakes": 7,
            "network_tcp_timeouts": 1,
            "network_tcp_retransmits": 1,
            "network_tcp_resets": 2,
            "network_tcp_established": 3,
            "network_tcp_closed": 3,
            "network_rx_packets": 14,
            "network_tx_packets": 12,
            "network_packet_lifecycle": 40,
            "network_queue_rx_enqueues": 14,
            "network_queue_tx_enqueues": 12,
            "network_queue_completions": 12,
        },
        "equals": {
            "network_queue_backpressure_drops": 0,
            "network_flow_core_mismatches": 0,
        },
    },
    "65": {
        "schema": "xaios.qemu.cpu_ai_runtime_gate.v1",
        "report": "qemu-milestone-65-cpu-ai-runtime-gate.json",
        "name": "cpu_ai_runtime",
        "markers": [
            "cpu-ai-runtime: model file loaded id=2 name=cpu-ai-v1-fixture",
            "cpu-ai-runtime: tokenizer/runtime boundary self-test passed tokenizer_calls=2 runtime_calls=2",
            "cpu-ai-runtime: multi-cell shared weights self-test passed loads=2 shared_binds=2 kv_writes=8",
            "cpu-ai-runtime: tokenizer binding and CPU dispatch self-test passed tokenizer_binds=2 kernel_dispatches=2",
            "ai-cell: multi-cell shared model/private kv self-test passed",
            "/bin/lstm-xor: cpu-ai fixture decode=",
        ],
        "minimums": {
            "cpu_ai_model_loads": 5,
            "cpu_ai_model_load_failures": 3,
            "cpu_ai_tokenizer_calls": 5,
            "cpu_ai_runtime_calls": 5,
            "cpu_ai_kv_writes": 19,
            "cpu_ai_shared_weight_binds": 5,
            "cpu_ai_gpu_rejects": 1,
            "cpu_ai_model_file_loads": 1,
            "cpu_ai_model_file_rejects": 3,
            "cpu_ai_manifest_validations": 10,
            "cpu_ai_tokenizer_binds": 5,
            "cpu_ai_kernel_dispatches": 5,
            "cpu_ai_admission_rejects": 5,
            "cpu_ai_checksum_failures": 1,
        },
        "equals": {},
    },
    "66": {
        "schema": "xaios.qemu.ai_cell_gate.v1",
        "report": "qemu-milestone-66-ai-cell-gate.json",
        "name": "ai_cell",
        "markers": [
            "ai-cell: descriptor ABI self-test passed accepts=5 rejects=4",
            "ai-cell: resource contract self-test passed admissions=2 rejects=10",
            "core-conflict-agent",
            "nic-conflict-agent",
            "workspace-conflict-agent",
        ],
        "minimums": {
            "ai_cell_transitions": 14,
            "ai_cell_descriptor_accepts": 5,
            "ai_cell_descriptor_rejects": 4,
            "ai_cell_resource_admissions": 2,
            "ai_cell_resource_rejects": 10,
            "ai_cell_arena_pages_peak": 160,
            "ai_cell_arena_bytes_peak": 655360,
            "ai_cell_queue_binds": 3,
            "ai_cell_queue_releases": 3,
            "ai_cell_workspace_binds": 2,
            "ai_cell_workspace_releases": 2,
            "ai_cell_conflicts": 3,
        },
        "equals": {
            "ai_cell_arena_pages_reserved": 0,
            "ai_cell_arena_bytes_reserved": 0,
        },
    },
    "67": {
        "schema": "xaios.qemu.security_gate.v1",
        "report": "qemu-milestone-67-security-gate.json",
        "name": "security",
        "markers": [
            "security: self-test passed denied=15",
            "/init: bad syscall tests passed",
            "/service-manager: missing capability tests passed",
            "admin: remote-safe command=shell rejected",
            "security: denied operation reason=fs-write-denied",
        ],
        "minimums": {
            "security_denied_ops": 22,
            "security_capability_denials": 5,
            "security_fs_denials": 1,
            "security_workspace_denials": 4,
            "security_sandbox_denials": 3,
            "security_rollback_denials": 1,
            "security_update_policy_rejects": 3,
            "security_credential_rejects": 3,
            "security_signature_rejects": 3,
            "security_update_authorizations": 3,
            "security_update_replay_rejects": 1,
            "security_key_rejects": 1,
            "security_sandbox_escape_rejects": 2,
            "control_plane_denials": 5,
        },
        "equals": {"admin_command_denials": 0},
    },
    "68": {
        "schema": "xaios.qemu.update_gate.v1",
        "report": "qemu-milestone-68-update-gate.json",
        "name": "update",
        "markers": [
            "update: transaction begin generation=2 target=/system/xaios rollback=update-rp",
            "update: boot fallback recovered generation=2 rollback=update-rp",
            "update: committed generation=3 target=/system/xaios",
            "update: rollback complete generation=3 target=/system/xaios",
            "update: self-test passed transactions=2 staged=2 committed=1 failed=1 recovered=1 rollbacks=1 boot_fallbacks=1 records=8 rollback_points=2 rejects=2",
        ],
        "minimums": {
            "update_transactions": 2,
            "update_staged": 2,
            "update_committed": 1,
            "update_failures": 1,
            "update_recoveries": 1,
            "update_rollbacks": 1,
            "update_boot_fallbacks": 1,
            "update_records_persisted": 8,
            "update_rollback_points": 2,
            "update_rejects": 2,
            "persistence_rollbacks": 7,
            "mutable_fs_rollbacks": 3,
        },
        "equals": {},
    },
}


def main() -> int:
    milestone = sys.argv[1] if len(sys.argv) == 2 else ""
    config = GATES.get(milestone)
    if config is None:
      print("usage: qemu-milestone-gate.py <62|63|64|65|66|67|68>")
      return 2

    proc = run(["python3", "./scripts/qemu-smoke.py"], timeout=180)
    failures = []
    checks = []
    if proc.returncode != 0:
        failures.append(f"qemu-smoke exited {proc.returncode}")

    missing = check_markers(proc.stdout, config["markers"])
    checks.append(result("markers", not missing, missing_markers=missing))
    failures.extend(f"missing marker: {marker}" for marker in missing)

    telemetry = {}
    try:
        telemetry = parse_telemetry(proc.stdout)
    except ValueError as exc:
        failures.append(str(exc))

    metric_failures = []
    for key, minimum in config["minimums"].items():
        value = telemetry.get(key)
        if not isinstance(value, int) or value < minimum:
            metric_failures.append(f"{key} expected >= {minimum}, got {value!r}")
    for key, expected in config["equals"].items():
        value = telemetry.get(key)
        if value != expected:
            metric_failures.append(f"{key} expected {expected}, got {value!r}")
    checks.append(result("telemetry", not metric_failures,
                         failures=metric_failures))
    failures.extend(metric_failures)

    report = {
        "schema": config["schema"],
        "status": status_from_failures(failures),
        "milestone": int(milestone),
        "created_at_unix": now(),
        "gate": config["name"],
        "smoke_exit_code": proc.returncode,
        "checks": checks,
        "telemetry": telemetry,
        "failures": failures,
    }
    write_report(BUILD / config["report"], report)
    if failures:
        print(f"qemu-{config['name']}-gate: failed")
        for failure in failures:
            print(f" - {failure}")
        return 1
    print(f"qemu-{config['name']}-gate: milestone {milestone} passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
