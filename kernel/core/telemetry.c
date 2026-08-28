#include <xaios/agent_protocol.h>
#include <xaios/ai_cell.h>
#include <xaios/arena.h>
#include <xaios/core_lease.h>
#include <xaios/cpu_ai_runtime.h>
#include <xaios/git_workspace.h>
#include <xaios/kheap.h>
#include <xaios/xaiboot_fs.h>
#include <xaios/klog.h>
#include <xaios/network_stack.h>
#include <xaios/persistence.h>
#include <xaios/pmm.h>
#include <xaios/sandbox.h>
#include <xaios/security.h>
#include <xaios/service.h>
#include <xaios/smp.h>
#include <xaios/source_index.h>
#include <xaios/syscall.h>
#include <xaios/telemetry.h>
#include <xaios/timer.h>
#include <xaios/update.h>
#include <xaios/user.h>
#include <xaios/virtio_blk.h>

void telemetry_emit_boot_summary(void) {
  klog(
      "telemetry: boot_summary cpu_online=%u pmm_total=%lu pmm_free=%lu timer_hz=%lu\n",
      smp_online_count(), pmm_total_pages(), pmm_free_pages(),
      timer_frequency_hz());
  klog(
      "telemetry: {\"cpu_count\":%u,\"pmm_total_pages\":%lu,\"pmm_free_pages\":%lu,\"kheap_pages\":%lu,\"kheap_bytes\":%lu,\"arena_active\":%lu,\"arena_committed_pages\":%lu,\"sandbox_active\":%lu,\"sandbox_transitions\":%lu,\"persistence_snapshots\":%lu,\"persistence_rollbacks\":%lu,\"persistence_rejects\":%lu,\"persistence_disk_writes\":%lu,\"persistence_disk_loads\":%lu,\"persistence_boot_loads\":%lu,\"persistence_checksum_errors\":%lu,\"xaiboot_fs_mounts\":%lu,\"xaiboot_fs_formats\":%lu,\"xaiboot_fs_boot_loads\":%lu,\"xaiboot_fs_files\":%lu,\"xaiboot_fs_directories\":%lu,\"xaiboot_fs_writes\":%lu,\"xaiboot_fs_reads\":%lu,\"xaiboot_fs_deletes\":%lu,\"xaiboot_fs_commits\":%lu,\"xaiboot_fs_rollbacks\":%lu,\"xaiboot_fs_replays\":%lu,\"xaiboot_fs_journal_writes\":%lu,\"xaiboot_fs_allocations\":%lu,\"xaiboot_fs_frees\":%lu,\"xaiboot_fs_multi_sector_files\":%lu,\"xaiboot_fs_state_records\":%lu,\"xaiboot_fs_renames\":%lu,\"xaiboot_fs_lists\":%lu,\"xaiboot_fs_stats\":%lu,\"xaiboot_fs_opens\":%lu,\"xaiboot_fs_closes\":%lu,\"xaiboot_fs_rejects\":%lu,\"xaiboot_fs_checksum_errors\":%lu,\"update_transactions\":%lu,\"update_staged\":%lu,\"update_committed\":%lu,\"update_failures\":%lu,\"update_recoveries\":%lu,\"update_rollbacks\":%lu,\"update_boot_fallbacks\":%lu,\"update_records_persisted\":%lu,\"update_rollback_points\":%lu,\"update_rejects\":%lu,\"hot_core_mask\":%u,\"irq_isolated_mask\":%u,\"migration_total\":%lu,\"context_switch_total\":%lu,\"source_index_active\":%lu,\"source_index_files\":%lu,\"source_index_symbols\":%lu,\"source_index_updates\":%lu,\"security_denied_ops\":%lu,\"security_capability_denials\":%lu,\"security_fs_denials\":%lu,\"security_workspace_denials\":%lu,\"security_sandbox_denials\":%lu,\"security_rollback_denials\":%lu,\"security_update_policy_rejects\":%lu,\"security_credential_rejects\":%lu,\"security_signature_accepts\":%lu,\"security_signature_rejects\":%lu,\"security_admin_denials\":%lu,\"security_update_authorizations\":%lu,\"security_update_replay_rejects\":%lu,\"security_key_accepts\":%lu,\"security_key_rejects\":%lu,\"security_sandbox_escape_rejects\":%lu,\"virtio_block_sectors\":%lu,\"ai_cell_transitions\":%lu,\"ai_cell_descriptor_accepts\":%lu,\"ai_cell_descriptor_rejects\":%lu,\"ai_cell_resource_admissions\":%lu,\"ai_cell_resource_rejects\":%lu,\"ai_cell_arena_pages_reserved\":%lu,\"ai_cell_arena_bytes_reserved\":%lu,\"ai_cell_arena_pages_peak\":%lu,\"ai_cell_arena_bytes_peak\":%lu,\"ai_cell_queue_binds\":%lu,\"ai_cell_queue_releases\":%lu,\"ai_cell_workspace_binds\":%lu,\"ai_cell_workspace_releases\":%lu,\"ai_cell_conflicts\":%lu,\"cpu_ai_model_loads\":%lu,\"cpu_ai_model_load_failures\":%lu,\"cpu_ai_tokenizer_calls\":%lu,\"cpu_ai_runtime_calls\":%lu,\"cpu_ai_kv_writes\":%lu,\"cpu_ai_shared_weight_binds\":%lu,\"cpu_ai_gpu_rejects\":%lu,\"cpu_ai_model_file_loads\":%lu,\"cpu_ai_model_file_rejects\":%lu,\"cpu_ai_model_bytes_loaded\":%lu,\"cpu_ai_manifest_validations\":%lu,\"cpu_ai_tokenizer_binds\":%lu,\"cpu_ai_kernel_dispatches\":%lu,\"cpu_ai_admission_rejects\":%lu,\"cpu_ai_checksum_failures\":%lu,\"git_workspace_active\":%lu,\"git_workspace_syncs\":%lu,\"git_workspace_applies\":%lu,\"git_workspace_reverts\":%lu,\"git_workspace_conflicts\":%lu,\"network_udp_tx\":%lu,\"network_udp_rx\":%lu,\"network_udp_malformed\":%lu,\"network_udp_dropped\":%lu,\"network_udp_flows\":%lu,\"network_udp_flow_hits\":%lu,\"network_udp_expired\":%lu,\"network_tcp_connections\":%lu,\"network_tcp_handshakes\":%lu,\"network_tcp_resets\":%lu,\"network_tcp_timeouts\":%lu,\"network_tcp_retransmits\":%lu,\"network_tcp_established\":%lu,\"network_tcp_closed\":%lu,\"network_queue_bindings\":%lu,\"network_rx_packets\":%lu,\"network_tx_packets\":%lu,\"network_packet_drops\":%lu,\"network_packet_lifecycle\":%lu,\"network_queue_rx_enqueues\":%lu,\"network_queue_tx_enqueues\":%lu,\"network_queue_completions\":%lu,\"network_queue_backpressure_drops\":%lu,\"network_flow_core_mismatches\":%lu,\"network_udp_p50\":%lu,\"network_udp_p95\":%lu,\"network_udp_p99\":%lu,\"network_udp_p999\":%lu,\"network_tcp_p50\":%lu,\"network_tcp_p95\":%lu,\"network_tcp_p99\":%lu,\"network_tcp_p999\":%lu,\"service_child_descriptors\":%lu,\"service_tree_edges\":%lu,\"service_transitions\":%lu,\"service_restarts\":%lu,\"service_crashes\":%lu,\"service_cleanups\":%lu,\"service_log_records\":%lu,\"admin_policy_exports\":%lu,\"admin_status_exports\":%lu,\"admin_log_reads\":%lu,\"admin_remote_safe_accepts\":%lu,\"admin_remote_safe_rejects\":%lu,\"admin_command_denials\":%lu,\"control_plane_syscalls\":%lu,\"control_plane_denials\":%lu,\"service_descriptor_reads\":%lu,\"user_process_transitions\":%lu,\"user_process_loaded\":%lu,\"user_process_runnable\":%lu,\"user_process_running\":%lu,\"user_process_waiting\":%lu,\"user_process_exited\":%lu,\"user_process_failed\":%lu,\"user_process_reclaims\":%lu,\"user_process_scheduled\":%lu,\"user_process_waits\":%lu,\"user_process_wakes\":%lu,\"user_process_active\":%lu,\"cpu_ai_inferences\":%lu,\"source_index_scans\":%lu,\"git_workspace_blob_hashes\":%lu,\"git_workspace_diffs\":%lu,\"sandbox_vm_execs\":%lu,\"agent_protocol_requests\":%lu,\"agent_protocol_errors\":%lu}\n",
      smp_online_count(), pmm_total_pages(), pmm_free_pages(),
      kheap_pages_allocated(), kheap_bytes_allocated(),
      arena_active_count(), arena_committed_pages(),
      sandbox_active_count(), sandbox_transition_count(),
      persistence_snapshot_count(), persistence_rollback_count(),
      persistence_reject_count(), persistence_disk_write_count(),
      persistence_disk_load_count(), persistence_disk_boot_load_count(),
      persistence_checksum_error_count(),
      xaiboot_fs_mount_count(), xaiboot_fs_format_count(),
      xaiboot_fs_boot_load_count(), xaiboot_fs_file_count(),
      xaiboot_fs_directory_count(), xaiboot_fs_write_count(),
      xaiboot_fs_read_count(), xaiboot_fs_delete_count(),
      xaiboot_fs_commit_count(), xaiboot_fs_rollback_count(),
      xaiboot_fs_replay_count(), xaiboot_fs_journal_write_count(),
      xaiboot_fs_allocation_count(), xaiboot_fs_free_count(),
      xaiboot_fs_multi_sector_file_count(), xaiboot_fs_state_record_count(),
      xaiboot_fs_rename_count(), xaiboot_fs_list_count(),
      xaiboot_fs_stat_count(), xaiboot_fs_open_count(),
      xaiboot_fs_close_count(),
      xaiboot_fs_reject_count(), xaiboot_fs_checksum_error_count(),
      update_transaction_count(), update_stage_count(), update_commit_count(),
      update_failure_count(), update_recovery_count(), update_rollback_count(),
      update_boot_fallback_count(), update_record_persist_count(),
      update_rollback_point_count(), update_reject_count(),
      smp_hot_core_mask(), smp_irq_isolated_mask(),
      core_lease_migration_count(),
      core_lease_involuntary_context_switch_count(),
      source_index_active_count(), source_index_total_file_records(),
      source_index_total_symbol_records(), source_index_total_updates(),
      security_denied_operation_count(), security_capability_denial_count(),
      security_fs_denial_count(), security_workspace_denial_count(),
      security_sandbox_denial_count(), security_rollback_denial_count(),
      security_update_policy_reject_count(), security_credential_reject_count(),
      security_signature_accept_count(), security_signature_reject_count(),
      security_admin_denial_count(), security_update_authorization_count(),
      security_update_replay_reject_count(), security_key_accept_count(),
      security_key_reject_count(), security_sandbox_escape_reject_count(),
      virtio_block_capacity_sectors(), ai_cell_transition_count(),
      ai_cell_descriptor_accept_count(), ai_cell_descriptor_reject_count(),
      ai_cell_resource_admission_count(), ai_cell_resource_reject_count(),
      ai_cell_arena_pages_reserved(), ai_cell_arena_bytes_reserved(),
      ai_cell_arena_pages_peak(), ai_cell_arena_bytes_peak(),
      ai_cell_queue_bind_count(), ai_cell_queue_release_count(),
      ai_cell_workspace_bind_count(), ai_cell_workspace_release_count(),
      ai_cell_conflict_count(),
      cpu_ai_runtime_model_load_count(),
      cpu_ai_runtime_model_load_failure_count(),
      cpu_ai_runtime_tokenizer_call_count(),
      cpu_ai_runtime_runtime_call_count(),
      cpu_ai_runtime_kv_write_count(),
      cpu_ai_runtime_shared_weight_bind_count(),
      cpu_ai_runtime_gpu_reject_count(),
      cpu_ai_runtime_model_file_load_count(),
      cpu_ai_runtime_model_file_reject_count(),
      cpu_ai_runtime_model_bytes_loaded(),
      cpu_ai_runtime_manifest_validation_count(),
      cpu_ai_runtime_tokenizer_bind_count(),
      cpu_ai_runtime_kernel_dispatch_count(),
      cpu_ai_runtime_admission_reject_count(),
      cpu_ai_runtime_checksum_failure_count(),
      git_workspace_active_count(), git_workspace_sync_count(),
      git_workspace_apply_count(), git_workspace_revert_count(),
      git_workspace_conflict_count(),
      network_stack_udp_tx_count(), network_stack_udp_rx_count(),
      network_stack_udp_malformed_count(), network_stack_udp_dropped_count(),
      network_stack_udp_flow_count(), network_stack_udp_flow_hit_count(),
      network_stack_udp_expired_count(),
      network_stack_tcp_connections(), network_stack_tcp_handshake_count(),
      network_stack_tcp_reset_count(), network_stack_tcp_timeout_count(),
      network_stack_tcp_retransmit_count(),
      network_stack_tcp_established_count(), network_stack_tcp_closed_count(),
      network_stack_queue_bindings(), network_stack_rx_packet_count(),
      network_stack_tx_packet_count(), network_stack_packet_drop_count(),
      network_stack_packet_lifecycle_count(),
      network_stack_queue_rx_enqueue_count(),
      network_stack_queue_tx_enqueue_count(),
      network_stack_queue_completion_count(),
      network_stack_queue_backpressure_drop_count(),
      network_stack_flow_core_mismatch_count(),
      network_stack_udp_latency_p50_ns(), network_stack_udp_latency_p95_ns(),
      network_stack_udp_latency_p99_ns(), network_stack_udp_latency_p999_ns(),
      network_stack_tcp_latency_p50_ns(), network_stack_tcp_latency_p95_ns(),
      network_stack_tcp_latency_p99_ns(), network_stack_tcp_latency_p999_ns(),
      service_child_descriptor_count(), service_tree_edge_count(),
      service_transition_count(), service_restart_count(),
      service_crash_count(), service_cleanup_count(),
      service_log_record_count(),
      service_admin_policy_export_count(),
      service_admin_status_export_count(),
      service_admin_log_read_count(),
      service_admin_remote_safe_accept_count(),
      service_admin_remote_safe_reject_count(),
      service_admin_command_denial_count(),
      syscall_control_plane_count(), syscall_control_plane_denial_count(),
      syscall_service_descriptor_read_count(),
      user_process_transition_count(), user_process_loaded_count(),
      user_process_runnable_count(), user_process_running_count(),
      user_process_waiting_count(), user_process_exited_count(),
      user_process_failed_count(), user_process_reclaim_count(),
      user_process_scheduled_count(), user_process_wait_count(),
      user_process_wake_count(), user_process_active_count(),
      cpu_ai_runtime_inference_count(), source_index_scan_count(),
      git_workspace_blob_hash_count(), git_workspace_diff_count(),
      sandbox_vm_exec_count(),
      agent_protocol_request_count(), agent_protocol_error_count());
}
