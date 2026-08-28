#!/usr/bin/env python3
import json
import os
import subprocess
import sys


def parse_telemetry(text: str):
    marker = "telemetry: "
    start = text.rfind(marker)
    if start < 0:
        return None
    payload = text[start + len(marker):].strip().splitlines()[0]
    if not payload.startswith("{"):
        return None
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return None


def main() -> int:
    env = os.environ.copy()
    env.setdefault("XAIOS_QEMU_SMOKE_TIMEOUT", "60")
    proc = subprocess.run(
        ["python3", "./tests/scripts/qemu-smoke.py"],
        check=False,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    if proc.returncode != 0:
        sys.stdout.write(proc.stdout)
        print("qemu-benchmark: smoke failed; benchmark not collected")
        return 1

    telemetry = parse_telemetry(proc.stdout)
    if telemetry is None:
        sys.stdout.write(proc.stdout)
        print("qemu-benchmark: missing telemetry payload")
        return 1

    expected_keys = {
        "cpu_count",
        "pmm_total_pages",
        "pmm_free_pages",
        "kheap_pages",
        "arena_committed_pages",
        "persistence_snapshots",
        "persistence_rollbacks",
        "persistence_rejects",
        "persistence_disk_writes",
        "persistence_disk_loads",
        "persistence_boot_loads",
        "persistence_checksum_errors",
        "xaiboot_fs_mounts",
        "xaiboot_fs_formats",
        "xaiboot_fs_boot_loads",
        "xaiboot_fs_files",
        "xaiboot_fs_directories",
        "xaiboot_fs_writes",
        "xaiboot_fs_reads",
        "xaiboot_fs_deletes",
        "xaiboot_fs_commits",
        "xaiboot_fs_rollbacks",
        "xaiboot_fs_replays",
        "xaiboot_fs_journal_writes",
        "xaiboot_fs_allocations",
        "xaiboot_fs_frees",
        "xaiboot_fs_multi_sector_files",
        "xaiboot_fs_state_records",
        "xaiboot_fs_renames",
        "xaiboot_fs_lists",
        "xaiboot_fs_stats",
        "xaiboot_fs_opens",
        "xaiboot_fs_closes",
        "xaiboot_fs_rejects",
        "xaiboot_fs_checksum_errors",
        "update_transactions",
        "update_staged",
        "update_committed",
        "update_failures",
        "update_recoveries",
        "update_rollbacks",
        "update_boot_fallbacks",
        "update_records_persisted",
        "update_rollback_points",
        "update_rejects",
        "security_denied_ops",
        "security_capability_denials",
        "security_fs_denials",
        "security_workspace_denials",
        "security_sandbox_denials",
        "security_rollback_denials",
        "security_update_policy_rejects",
        "security_credential_rejects",
        "security_signature_accepts",
        "security_signature_rejects",
        "security_admin_denials",
        "security_update_authorizations",
        "security_update_replay_rejects",
        "security_key_accepts",
        "security_key_rejects",
        "security_sandbox_escape_rejects",
        "virtio_block_sectors",
        "cpu_ai_model_loads",
        "cpu_ai_model_load_failures",
        "cpu_ai_tokenizer_calls",
        "cpu_ai_runtime_calls",
        "cpu_ai_kv_writes",
        "cpu_ai_shared_weight_binds",
        "cpu_ai_gpu_rejects",
        "cpu_ai_model_file_loads",
        "cpu_ai_model_file_rejects",
        "cpu_ai_model_bytes_loaded",
        "cpu_ai_manifest_validations",
        "cpu_ai_tokenizer_binds",
        "cpu_ai_kernel_dispatches",
        "cpu_ai_admission_rejects",
        "cpu_ai_checksum_failures",
        "network_udp_tx",
        "network_udp_rx",
        "network_udp_malformed",
        "network_udp_dropped",
        "network_udp_flows",
        "network_udp_flow_hits",
        "network_udp_expired",
        "network_tcp_connections",
        "network_tcp_handshakes",
        "network_tcp_timeouts",
        "network_tcp_retransmits",
        "network_tcp_established",
        "network_tcp_closed",
        "network_rx_packets",
        "network_tx_packets",
        "network_packet_drops",
        "network_packet_lifecycle",
        "network_queue_bindings",
        "network_queue_rx_enqueues",
        "network_queue_tx_enqueues",
        "network_queue_completions",
        "network_queue_backpressure_drops",
        "network_flow_core_mismatches",
        "network_udp_p999",
        "network_tcp_p999",
        "ai_cell_transitions",
        "ai_cell_descriptor_accepts",
        "ai_cell_descriptor_rejects",
        "ai_cell_resource_admissions",
        "ai_cell_resource_rejects",
        "ai_cell_arena_pages_reserved",
        "ai_cell_arena_bytes_reserved",
        "ai_cell_arena_pages_peak",
        "ai_cell_arena_bytes_peak",
        "ai_cell_queue_binds",
        "ai_cell_queue_releases",
        "ai_cell_workspace_binds",
        "ai_cell_workspace_releases",
        "ai_cell_conflicts",
        "migration_total",
        "context_switch_total",
        "service_child_descriptors",
        "service_tree_edges",
        "service_transitions",
        "service_restarts",
        "service_crashes",
        "service_cleanups",
        "service_log_records",
        "admin_policy_exports",
        "admin_status_exports",
        "admin_log_reads",
        "admin_remote_safe_accepts",
        "admin_remote_safe_rejects",
        "admin_command_denials",
        "control_plane_syscalls",
        "control_plane_denials",
        "service_descriptor_reads",
        "user_process_transitions",
        "user_process_loaded",
        "user_process_running",
        "user_process_exited",
        "user_process_failed",
        "user_process_reclaims",
    }
    missing = sorted(expected_keys - set(telemetry.keys()))
    if missing:
        print(f"qemu-benchmark: telemetry missing keys: {missing}")
        return 1

    gates = {
        "cpu_count_min": telemetry["cpu_count"] >= 1,
        "pmm_has_free_pages": telemetry["pmm_free_pages"] > 0,
        "virtio_block_visible": telemetry["virtio_block_sectors"] > 0,
        "ai_cell_contract_enforced": telemetry["ai_cell_transitions"] >= 14
        and telemetry["ai_cell_descriptor_accepts"] >= 5
        and telemetry["ai_cell_descriptor_rejects"] >= 4
        and telemetry["ai_cell_resource_admissions"] >= 2
        and telemetry["ai_cell_resource_rejects"] >= 10
        and telemetry["ai_cell_arena_pages_reserved"] == 0
        and telemetry["ai_cell_arena_bytes_reserved"] == 0
        and telemetry["ai_cell_arena_pages_peak"] >= 160
        and telemetry["ai_cell_arena_bytes_peak"] >= 655360
        and telemetry["ai_cell_queue_binds"] >= 3
        and telemetry["ai_cell_queue_releases"] >= 3
        and telemetry["ai_cell_workspace_binds"] >= 2
        and telemetry["ai_cell_workspace_releases"] >= 2
        and telemetry["ai_cell_conflicts"] >= 3,
        "cpu_ai_runtime_boundaries": telemetry["cpu_ai_model_loads"] >= 4
        and telemetry["cpu_ai_model_load_failures"] >= 3
        and telemetry["cpu_ai_tokenizer_calls"] >= 4
        and telemetry["cpu_ai_runtime_calls"] >= 4
        and telemetry["cpu_ai_kv_writes"] >= 16
        and telemetry["cpu_ai_shared_weight_binds"] >= 4
        and telemetry["cpu_ai_gpu_rejects"] >= 1
        and telemetry["cpu_ai_model_file_loads"] >= 1
        and telemetry["cpu_ai_model_file_rejects"] >= 3
        and telemetry["cpu_ai_model_bytes_loaded"] >= 1
        and telemetry["cpu_ai_manifest_validations"] >= 9
        and telemetry["cpu_ai_tokenizer_binds"] >= 4
        and telemetry["cpu_ai_kernel_dispatches"] >= 4
        and telemetry["cpu_ai_admission_rejects"] >= 5
        and telemetry["cpu_ai_checksum_failures"] >= 1,
        "security_enforcement_recorded": telemetry["security_denied_ops"] >= 22
        and telemetry["security_capability_denials"] >= 5
        and telemetry["security_fs_denials"] >= 1
        and telemetry["security_workspace_denials"] >= 4
        and telemetry["security_sandbox_denials"] >= 3
        and telemetry["security_rollback_denials"] >= 1
        and telemetry["security_update_policy_rejects"] >= 3
        and telemetry["security_credential_rejects"] >= 3
        and telemetry["security_signature_rejects"] >= 3
        and telemetry["security_admin_denials"] >= 2
        and telemetry["security_update_authorizations"] >= 1
        and telemetry["security_update_replay_rejects"] >= 1
        and telemetry["security_key_accepts"] >= 1
        and telemetry["security_key_rejects"] >= 1
        and telemetry["security_sandbox_escape_rejects"] >= 2,
        "persistence_rollbacks_present": telemetry["persistence_rollbacks"] >= 5,
        "update_rollback_system": telemetry["update_transactions"] >= 2
        and telemetry["update_staged"] >= 2
        and telemetry["update_committed"] >= 1
        and telemetry["update_failures"] >= 1
        and telemetry["update_recoveries"] >= 1
        and telemetry["update_rollbacks"] >= 1
        and telemetry["update_boot_fallbacks"] >= 1
        and telemetry["update_records_persisted"] >= 8
        and telemetry["update_rollback_points"] >= 2
        and telemetry["update_rejects"] >= 2,
        "disk_persistence_reloaded": telemetry["persistence_disk_writes"] >= 1
        and telemetry["persistence_disk_loads"] >= 1
        and telemetry["persistence_checksum_errors"] == 0,
        "mutable_filesystem_active": telemetry["xaiboot_fs_mounts"] >= 2
        and telemetry["xaiboot_fs_files"] >= 8
        and telemetry["xaiboot_fs_directories"] >= 11
        and telemetry["xaiboot_fs_writes"] >= 26
        and telemetry["xaiboot_fs_reads"] >= 8
        and telemetry["xaiboot_fs_deletes"] >= 1
        and telemetry["xaiboot_fs_commits"] >= 1
        and telemetry["xaiboot_fs_rollbacks"] >= 1
        and telemetry["xaiboot_fs_replays"] >= 1
        and telemetry["xaiboot_fs_journal_writes"] >= 1
        and telemetry["xaiboot_fs_allocations"] >= 1
        and telemetry["xaiboot_fs_frees"] >= 1
        and telemetry["xaiboot_fs_multi_sector_files"] >= 1
        and telemetry["xaiboot_fs_state_records"] >= 4
        and telemetry["xaiboot_fs_renames"] >= 1
        and telemetry["xaiboot_fs_lists"] >= 1
        and telemetry["xaiboot_fs_stats"] >= 4
        and telemetry["xaiboot_fs_opens"] >= 5
        and telemetry["xaiboot_fs_closes"] >= 5
        and telemetry["xaiboot_fs_rejects"] >= 8
        and telemetry["xaiboot_fs_checksum_errors"] == 0,
        "no_hot_path_migration": telemetry["migration_total"] == 0,
        "no_hot_path_context_switches": telemetry["context_switch_total"] == 0,
        "udp_path_exercised": telemetry["network_udp_tx"] >= 3
        and telemetry["network_udp_rx"] >= 3
        and telemetry["network_udp_flows"] >= 1
        and telemetry["network_udp_flow_hits"] >= 1
        and telemetry["network_udp_expired"] >= 1,
        "tcp_path_exercised": telemetry["network_tcp_connections"] == 0
        and telemetry["network_tcp_handshakes"] >= 7
        and telemetry["network_tcp_timeouts"] >= 1
        and telemetry["network_tcp_retransmits"] >= 1
        and telemetry["network_tcp_established"] >= 3
        and telemetry["network_tcp_closed"] >= 3,
        "queue_backed_packet_flow": telemetry["network_rx_packets"] >= 6
        and telemetry["network_tx_packets"] >= 6
        and telemetry["network_packet_drops"] >= 2
        and telemetry["network_packet_lifecycle"] >= 18
        and telemetry["network_queue_rx_enqueues"] >= 6
        and telemetry["network_queue_tx_enqueues"] >= 6
        and telemetry["network_queue_completions"] >= 6
        and telemetry["network_queue_backpressure_drops"] == 0
        and telemetry["network_flow_core_mismatches"] == 0,
        "child_service_supervised": telemetry["service_child_descriptors"] >= 1
        and telemetry["service_tree_edges"] >= 1
        and telemetry["service_transitions"] >= 12
        and telemetry["service_restarts"] >= 1
        and telemetry["service_crashes"] >= 1
        and telemetry["service_cleanups"] >= 3
        and telemetry["service_log_records"] >= 2,
        "userspace_control_plane_active": telemetry["control_plane_syscalls"] >= 34
        and telemetry["control_plane_denials"] >= 4
        and telemetry["service_descriptor_reads"] >= 1,
        "admin_control_plane_active": telemetry["admin_policy_exports"] >= 1
        and telemetry["admin_status_exports"] >= 2
        and telemetry["admin_log_reads"] >= 1
        and telemetry["admin_remote_safe_accepts"] >= 1
        and telemetry["admin_remote_safe_rejects"] >= 1
        and telemetry["admin_command_denials"] == 0,
        "user_process_lifecycle_complete": telemetry["user_process_loaded"] >= 2
        and telemetry["user_process_running"] >= 2
        and telemetry["user_process_exited"] >= 2
        and telemetry["user_process_failed"] == 0
        and telemetry["user_process_reclaims"] >= 2,
    }
    failed_gates = sorted(name for name, passed in gates.items() if not passed)
    if failed_gates:
        print(f"qemu-benchmark: failed gates: {failed_gates}")
        return 1

    report = {
        "schema": "xaios.qemu.correctness_benchmark.v1",
        "status": "pass",
        "benchmark_type": "qemu-correctness",
        "baseline_required_for_performance_claims": True,
        "performance_claims_allowed": False,
        "notes": "QEMU results validate boot correctness and contracts only; they are not tuned Linux/BSD performance claims.",
        "gates": gates,
        "telemetry": telemetry,
        "smoke_exit_code": proc.returncode,
    }
    print(f"qemu-benchmark: report={json.dumps(report, sort_keys=True)}")

    output = os.environ.get("XAIOS_QEMU_BENCHMARK_OUTPUT")
    if output:
        with open(output, "w", encoding="utf-8") as handle:
            json.dump(report, handle, sort_keys=True, indent=2)
        print(f"qemu-benchmark: report written to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
