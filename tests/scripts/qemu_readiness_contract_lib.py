#!/usr/bin/env python3
"""Contract, telemetry and CPU-matrix validation for the readiness gate.

The gate is `qemu-readiness-gate.py`. This module holds the half that is data
and contract checking rather than process mechanics: the schema strings and the
contract path, the frozen QEMU contract list and the Intel desktop entry
criteria, the telemetry minimums and equals tables, the two small comparison
helpers, and the validators for the release-candidate contract and the CPU
matrix. It was split out so the gate, which runs `make qemu-matrix`, loads the
artifacts and writes the report, stays under the repository's 500-line limit.
The moved code is verbatim; the gate imports these names, so the command line,
the output and the exit codes are unchanged.

The benchmark and preview validators in `qemu_readiness_report_lib.py` read the
same telemetry tables and use the same comparison helpers, so both are defined
here once and imported there rather than copied.

It is imported and is not itself a program: `python3
tests/scripts/qemu-readiness-gate.py` remains the only entry point.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent))
from qemu_gate_lib import validate_syscall_abi  # noqa: E402


REPORT_SCHEMA = "xaios.qemu.hardware_readiness_gate.v1"
BENCHMARK_SCHEMA = "xaios.qemu.correctness_benchmark.v1"
PREVIEW_SCHEMA = "xaios.qemu.preview.v1"
CPU_MATRIX_SCHEMA = "xaios.qemu.cpu_matrix.v1"
CONTRACT_SCHEMA = "xaios.qemu.release_candidate_contract.v1"
CONTRACT_PATH = "contracts/qemu-rc-v1.json"

FROZEN_QEMU_CONTRACTS = [
    {
        "id": "qemu.aarch64.uefi-loader",
        "description": "AArch64 UEFI loader boots and transfers control to kernel.elf.",
    },
    {
        "id": "qemu.memory.pmm-vmm",
        "description": "UEFI memory map is parsed into PMM/VMM state with map/unmap checks.",
    },
    {
        "id": "qemu.protection.controlled-faults",
        "description": "Controlled page, read-only write, and NX execute faults are reported through the exception path.",
    },
    {
        "id": "qemu.userspace.el0-init",
        "description": "Real EL0 /init ELF is loaded from the VirtIO-backed read-only filesystem.",
    },
    {
        "id": "qemu.syscall.capabilities",
        "description": "Syscalls enforce process capabilities and user pointer validation.",
    },
    {
        "id": "qemu.abi.freeze",
        "description": "QEMU RC contract freezes syscall ABI, telemetry schema, filesystem format, persistence format, and service descriptor format.",
    },
    {
        "id": "qemu.virtio.block-net",
        "description": "Split VirtIO transport, block, and net self-tests pass.",
    },
    {
        "id": "qemu.ai-cell.resources",
        "description": "AI Cell lifecycle, core leases, model arenas, KV/cache, source index, workspace, sandbox, and CPU-AI runtime fixtures emit telemetry.",
    },
    {
        "id": "qemu.security.policy",
        "description": "Security policy enforces capabilities, filesystem boundaries, workspace and sandbox ownership, rollback authorization, credential rejection, and signed-update format validation.",
    },
    {
        "id": "qemu.persistence.rollback-metadata",
        "description": "VirtIO-backed persistence snapshots, reloads after reboot, and rolls back boot, service, workspace, and sandbox records.",
    },
    {
        "id": "qemu.telemetry.no-hot-path-migration",
        "description": "Hot AI core telemetry reports zero migration and zero involuntary context switches.",
    },
]

INTEL_DESKTOP_ENTRY_CRITERIA = [
    "make qemu-readiness-gate exits with status 0.",
    "build/qemu-preview-manifest.json exists and uses schema xaios.qemu.preview.v1.",
    "build/qemu-benchmark-report.json exists and uses schema xaios.qemu.correctness_benchmark.v1.",
    "All benchmark gates are true.",
    "Two-boot persistence reboot validation passes on the same VirtIO state image.",
    "QEMU performance_claims_allowed is false.",
    "QEMU benchmark_type remains qemu-correctness.",
    "Controlled page, read-only write, and NX fault scenarios pass.",
    "QEMU CPU matrix report validates ARM64 boot tiers and x86_64 command tiers.",
    "QEMU RC contract remains frozen at xaios.qemu.release_candidate_contract.v1.",
    "Platform and benchmark documentation describe QEMU as correctness-only.",
]

REQUIRED_TELEMETRY_MINIMUMS = {
    "cpu_count": 1,
    "pmm_total_pages": 1,
    "pmm_free_pages": 1,
    "virtio_block_sectors": 1,
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
    "cpu_ai_model_loads": 5,
    "cpu_ai_model_load_failures": 3,
    "cpu_ai_tokenizer_calls": 5,
    "cpu_ai_runtime_calls": 8,
    "cpu_ai_kv_writes": 19,
    "cpu_ai_shared_weight_binds": 5,
    "cpu_ai_gpu_rejects": 1,
    "cpu_ai_model_file_loads": 1,
    "cpu_ai_model_file_rejects": 3,
    "cpu_ai_model_bytes_loaded": 1,
    "cpu_ai_manifest_validations": 10,
    "cpu_ai_tokenizer_binds": 5,
    "cpu_ai_kernel_dispatches": 8,
    "cpu_ai_admission_rejects": 5,
    "cpu_ai_checksum_failures": 1,
    "security_denied_ops": 22,
    "security_capability_denials": 5,
    "security_fs_denials": 1,
    "security_workspace_denials": 4,
    "security_sandbox_denials": 3,
    "security_rollback_denials": 1,
    "security_update_policy_rejects": 3,
    "security_credential_rejects": 3,
    "security_signature_rejects": 3,
    "security_admin_denials": 2,
    "security_update_authorizations": 3,
    "security_update_replay_rejects": 1,
    "security_key_accepts": 3,
    "security_key_rejects": 1,
    "security_sandbox_escape_rejects": 2,
    "persistence_snapshots": 7,
    "persistence_rollbacks": 7,
    "persistence_disk_writes": 1,
    "persistence_disk_loads": 1,
    "sandbox_transitions": 7,
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
    "network_packet_drops": 4,
    "network_packet_lifecycle": 40,
    "network_queue_rx_enqueues": 14,
    "network_queue_tx_enqueues": 12,
    "network_queue_completions": 12,
    "service_child_descriptors": 1,
    "service_tree_edges": 1,
    "service_transitions": 21,
    "service_restarts": 1,
    "service_crashes": 1,
    "service_cleanups": 6,
    "service_log_records": 2,
    "admin_policy_exports": 1,
    "admin_status_exports": 2,
    "admin_log_reads": 1,
    "admin_remote_safe_accepts": 1,
    "admin_remote_safe_rejects": 1,
    "control_plane_syscalls": 89,
    "control_plane_denials": 5,
    "service_descriptor_reads": 1,
    "user_process_transitions": 45,
    "user_process_loaded": 14,
    "user_process_runnable": 3,
    "user_process_running": 14,
    "user_process_exited": 14,
    "user_process_reclaims": 14,
    "user_process_scheduled": 14,
    "xaiboot_fs_files": 8,
    "xaiboot_fs_directories": 13,
    "xaiboot_fs_writes": 33,
    "xaiboot_fs_reads": 12,
    "xaiboot_fs_renames": 3,
    "xaiboot_fs_lists": 3,
    "xaiboot_fs_stats": 5,
    "xaiboot_fs_opens": 10,
    "xaiboot_fs_closes": 10,
    "xaiboot_fs_rejects": 8,
}

REQUIRED_TELEMETRY_EQUALS = {
    "migration_total": 0,
    "context_switch_total": 0,
    "user_process_failed": 0,
    "persistence_checksum_errors": 0,
    "network_queue_backpressure_drops": 0,
    "network_flow_core_mismatches": 0,
    "network_tcp_connections": 0,
    "ai_cell_arena_pages_reserved": 0,
    "ai_cell_arena_bytes_reserved": 0,
    "admin_command_denials": 0,
}


def check_bool(value: Any, expected: bool, name: str, failures: List[str]) -> None:
    if value is not expected:
        failures.append(f"{name} expected {expected!r}, got {value!r}")


def check_equal(value: Any, expected: Any, name: str, failures: List[str]) -> None:
    if value != expected:
        failures.append(f"{name} expected {expected!r}, got {value!r}")


def validate_contract(contract: Dict[str, Any], failures: List[str]) -> Dict[str, Any]:
    check_equal(contract.get("schema"), CONTRACT_SCHEMA, "contract.schema", failures)
    check_equal(contract.get("status"), "frozen", "contract.status", failures)
    check_bool(contract.get("scope", {}).get("performance_claims_allowed"), False, "contract.scope.performance_claims_allowed", failures)
    check_equal(contract.get("scope", {}).get("benchmark_type"), "qemu-correctness", "contract.scope.benchmark_type", failures)

    syscall_abi = contract.get("syscall_abi", {})
    syscalls = syscall_abi.get("syscalls", [])
    capabilities = syscall_abi.get("capabilities", [])
    check_equal(syscall_abi.get("version"), 1, "contract.syscall_abi.version", failures)
    failures.extend(validate_syscall_abi(contract))
    capability_names = [entry.get("name") for entry in capabilities]
    capability_bits = [entry.get("bit") for entry in capabilities]
    if not capabilities:
        failures.append("contract.syscall_abi.capabilities is empty")
    if len(set(capability_names)) != len(capability_names):
        failures.append("contract.syscall_abi.capability names are not unique")
    if len(set(capability_bits)) != len(capability_bits):
        failures.append("contract.syscall_abi.capability bits are not unique")
    for name, bit in zip(capability_names, capability_bits):
        if not isinstance(name, str) or not name.startswith("XAIOS_CAP_"):
            failures.append(f"contract syscall capability has invalid name {name!r}")
        if not isinstance(bit, int) or bit <= 0 or bit & (bit - 1) != 0:
            failures.append(f"contract syscall capability {name!r} has invalid bit {bit!r}")
    expected_syscall_numbers = list(range(1, len(syscalls) + 1))
    actual_syscall_numbers = [entry.get("number") for entry in syscalls]
    if actual_syscall_numbers != expected_syscall_numbers:
        failures.append(f"contract.syscall_abi numbers expected {expected_syscall_numbers}, got {actual_syscall_numbers}")

    telemetry_schema = contract.get("telemetry_schema", {})
    check_equal(telemetry_schema.get("schema"), "xaios.qemu.telemetry.v1", "contract.telemetry_schema.schema", failures)
    check_equal(telemetry_schema.get("minimums"), REQUIRED_TELEMETRY_MINIMUMS, "contract.telemetry_schema.minimums", failures)
    check_equal(telemetry_schema.get("equals"), REQUIRED_TELEMETRY_EQUALS, "contract.telemetry_schema.equals", failures)

    filesystem = contract.get("filesystem_format", {})
    check_equal(filesystem.get("magic"), "XAIOSROFS2", "contract.filesystem.magic", failures)
    check_equal(filesystem.get("version"), 2, "contract.filesystem.version", failures)
    check_equal(filesystem.get("header_bytes"), 8192, "contract.filesystem.header_bytes", failures)
    check_equal(filesystem.get("manifest_path"), "/etc/xaios-init.conf", "contract.filesystem.manifest_path", failures)
    required_paths = filesystem.get("required_paths", [])
    for path in ["/init", "/bin/service-manager", "/bin/xaios-worker", "/bin/xaios-shell", "/bin/xaiosctl", "/bin/hello", "/bin/helloworldc99", "/bin/sysinfo", "/bin/systest", "/bin/smptest", "/bin/nettest", "/bin/lstm-xor", "/bin/sshtest", "/bin/mltest", "/etc/xaios-init.conf", "/etc/services/source-index.svc", "/models/cpu-ai-v1-fixture.xaiosmodel"]:
        if path not in required_paths:
            failures.append(f"contract.filesystem.required_paths missing {path}")
    check_equal(filesystem.get("max_files"), 80, "contract.filesystem.max_files", failures)

    model_format = contract.get("cpu_ai_model_format", {})
    check_equal(model_format.get("magic"), "XAIOS_MODEL_MIAI", "contract.cpu_ai_model_format.magic", failures)
    check_equal(model_format.get("version"), 1, "contract.cpu_ai_model_format.version", failures)
    check_equal(model_format.get("header_bytes"), 80, "contract.cpu_ai_model_format.header_bytes", failures)
    check_equal(model_format.get("path"), "/models/cpu-ai-v1-fixture.xaiosmodel", "contract.cpu_ai_model_format.path", failures)
    check_bool(model_format.get("cpu_only_required"), True, "contract.cpu_ai_model_format.cpu_only_required", failures)
    check_bool(model_format.get("gpu_required_rejected"), True, "contract.cpu_ai_model_format.gpu_required_rejected", failures)

    ai_cell_descriptor = contract.get("ai_cell_descriptor_abi", {})
    check_equal(ai_cell_descriptor.get("magic"), "AIC1", "contract.ai_cell_descriptor_abi.magic", failures)
    check_equal(ai_cell_descriptor.get("version"), 1, "contract.ai_cell_descriptor_abi.version", failures)
    check_equal(ai_cell_descriptor.get("descriptor_bytes"), 112, "contract.ai_cell_descriptor_abi.descriptor_bytes", failures)
    required_flags = ai_cell_descriptor.get("required_flags", [])
    for flag in ["cpu_only", "fixed_cores", "shared_model", "private_kv", "nic_queue", "git_workspace"]:
        if flag not in required_flags:
            failures.append(f"contract.ai_cell_descriptor_abi.required_flags missing {flag}")

    persistence = contract.get("persistence_format", {})
    check_equal(persistence.get("magic"), "XAIOSPST1", "contract.persistence.magic", failures)
    check_equal(persistence.get("version"), 1, "contract.persistence.version", failures)
    check_equal(persistence.get("sector"), 3000, "contract.persistence.sector", failures)

    descriptor = contract.get("service_descriptor_format", {})
    check_equal(descriptor.get("path"), "/etc/services/source-index.svc", "contract.service_descriptor.path", failures)
    for key in ["name", "parent", "restart", "start", "status"]:
        if key not in descriptor.get("required_keys", []):
            failures.append(f"contract.service_descriptor.required_keys missing {key}")

    security_policy = contract.get("security_policy", {})
    check_bool(security_policy.get("admin_capability_required"), True, "contract.security_policy.admin_capability_required", failures)
    check_equal(security_policy.get("admin_capability"), "XAIOS_CAP_ADMIN", "contract.security_policy.admin_capability", failures)
    check_equal(security_policy.get("update_generation_policy"), "strictly monotonic", "contract.security_policy.update_generation_policy", failures)
    check_equal(security_policy.get("accepted_update_key"), "XAIOS-QEMU-DEV-PUBKEY", "contract.security_policy.accepted_update_key", failures)
    for cap in ["XAIOS_CAP_UPDATE", "XAIOS_CAP_ADMIN"]:
        if cap not in security_policy.get("update_requires_capabilities", []):
            failures.append(f"contract.security_policy.update_requires_capabilities missing {cap}")
    check_bool(security_policy.get("rollback_authorization_required"), True, "contract.security_policy.rollback_authorization_required", failures)
    check_bool(security_policy.get("sandbox_path_escape_rejected"), True, "contract.security_policy.sandbox_path_escape_rejected", failures)
    check_bool(security_policy.get("credential_material_rejected"), True, "contract.security_policy.credential_material_rejected", failures)

    update_system = contract.get("update_system", {})
    check_equal(update_system.get("transaction_record_path"), "/state/updates/update.state", "contract.update_system.transaction_record_path", failures)
    for field in ["policy", "transaction_generation", "state", "target", "rollback"]:
        if field not in update_system.get("record_fields", []):
            failures.append(f"contract.update_system.record_fields missing {field}")
    check_equal(update_system.get("rollback_point_kind"), "update", "contract.update_system.rollback_point_kind", failures)
    check_bool(update_system.get("boot_fallback_required"), True, "contract.update_system.boot_fallback_required", failures)
    check_bool(update_system.get("failed_update_recovery_required"), True, "contract.update_system.failed_update_recovery_required", failures)
    check_bool(update_system.get("committed_update_rollback_required"), True, "contract.update_system.committed_update_rollback_required", failures)
    check_equal(update_system.get("minimum_transactions"), 2, "contract.update_system.minimum_transactions", failures)
    check_equal(update_system.get("minimum_persisted_records"), 8, "contract.update_system.minimum_persisted_records", failures)

    admin_control = contract.get("admin_control_plane", {})
    check_equal(admin_control.get("access_policy"), "ssh-only", "contract.admin_control_plane.access_policy", failures)
    check_bool(admin_control.get("password_login"), False, "contract.admin_control_plane.password_login", failures)
    check_bool(admin_control.get("admin_capability_required"), True, "contract.admin_control_plane.admin_capability_required", failures)
    check_equal(admin_control.get("admin_capability"), "XAIOS_CAP_ADMIN", "contract.admin_control_plane.admin_capability", failures)
    check_equal(admin_control.get("status_export_path"), "/state/services/admin.state", "contract.admin_control_plane.status_export_path", failures)
    for command in ["admin policy", "admin status <service>", "admin export <service>", "admin logs <service>", "admin remote-safe <command>"]:
        if command not in admin_control.get("required_commands", []):
            failures.append(f"contract.admin_control_plane.required_commands missing {command}")
    for command in ["status", "logs", "export"]:
        if command not in admin_control.get("remote_safe_allowlist", []):
            failures.append(f"contract.admin_control_plane.remote_safe_allowlist missing {command}")
    check_bool(admin_control.get("unsafe_remote_command_rejected"), True, "contract.admin_control_plane.unsafe_remote_command_rejected", failures)
    check_equal(admin_control.get("minimum_policy_exports"), 1, "contract.admin_control_plane.minimum_policy_exports", failures)
    check_equal(admin_control.get("minimum_status_exports"), 2, "contract.admin_control_plane.minimum_status_exports", failures)
    check_equal(admin_control.get("minimum_log_reads"), 1, "contract.admin_control_plane.minimum_log_reads", failures)

    out_of_scope = contract.get("out_of_scope_before_intel", [])
    if len(out_of_scope) < 5:
        failures.append("contract.out_of_scope_before_intel is too short")
    return contract


def validate_cpu_matrix(report: Dict[str, Any], contract: Dict[str, Any], failures: List[str]) -> None:
    check_equal(report.get("schema"), CPU_MATRIX_SCHEMA, "cpu_matrix.schema", failures)
    check_equal(report.get("status"), "pass", "cpu_matrix.status", failures)
    check_equal(report.get("contract"), CONTRACT_PATH, "cpu_matrix.contract", failures)
    tiers = report.get("tiers", [])
    if not isinstance(tiers, list) or not tiers:
        failures.append("cpu_matrix.tiers missing or empty")
        return
    required_by_name = {}
    contract_matrix = contract.get("cpu_matrix", {})
    for tier in contract_matrix.get("arm64_boot_tiers", []):
        required_by_name[tier.get("name")] = tier.get("required", True)
    for tier in contract_matrix.get("x86_64_command_tiers", []):
        required_by_name[tier.get("name")] = tier.get("required", True)
    failed = [
        tier.get("name") for tier in tiers
        if tier.get("status") != "pass"
        and required_by_name.get(tier.get("name"), True)
    ]
    if failed:
        failures.append(f"cpu_matrix failed tiers: {failed}")

    required_names = set()
    for tier in contract_matrix.get("arm64_boot_tiers", []):
        required_names.add(tier.get("name"))
    for tier in contract_matrix.get("x86_64_command_tiers", []):
        required_names.add(tier.get("name"))
    actual_names = {tier.get("name") for tier in tiers}
    missing = sorted(name for name in required_names if name not in actual_names)
    if missing:
        failures.append(f"cpu_matrix missing contract tiers: {missing}")
