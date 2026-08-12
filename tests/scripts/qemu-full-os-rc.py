#!/usr/bin/env python3
import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple


REPORT_SCHEMA = "xaios.qemu.full_os_release_candidate.v1"
READINESS_SCHEMA = "xaios.qemu.hardware_readiness_gate.v1"
BENCHMARK_SCHEMA = "xaios.qemu.correctness_benchmark.v1"
PREVIEW_SCHEMA = "xaios.qemu.preview.v1"
CPU_MATRIX_SCHEMA = "xaios.qemu.cpu_matrix.v1"
CONTRACT_SCHEMA = "xaios.qemu.release_candidate_contract.v1"
CONTRACT_PATH = "contracts/qemu-rc-v1.json"

EXPECTED_BENCHMARK_GATES = [
    "admin_control_plane_active",
    "ai_cell_contract_enforced",
    "child_service_supervised",
    "cpu_ai_runtime_boundaries",
    "cpu_count_min",
    "disk_persistence_reloaded",
    "mutable_filesystem_active",
    "no_hot_path_context_switches",
    "no_hot_path_migration",
    "persistence_rollbacks_present",
    "pmm_has_free_pages",
    "queue_backed_packet_flow",
    "security_enforcement_recorded",
    "tcp_path_exercised",
    "udp_path_exercised",
    "update_rollback_system",
    "user_process_lifecycle_complete",
    "userspace_control_plane_active",
    "virtio_block_visible",
]

VALIDATED_SUBSYSTEMS = [
    "AArch64 UEFI boot path",
    "PMM/VMM and controlled fault reporting",
    "EL0 /init and /bin/service-manager process lifecycle",
    "capability-checked syscall ABI",
    "read-only initramfs format",
    "mutable filesystem with journal replay and rollback",
    "VirtIO block and network devices",
    "queue-backed UDP/TCP correctness paths",
    "CPU-only model loader/tokenizer/runtime boundary",
    "AI Cell descriptor and resource contract",
    "service supervisor and admin control plane",
    "security, update, rollback, and persistence policy",
    "QEMU CPU compatibility matrix",
]


def run(cmd: List[str], env: Dict[str, str]) -> int:
    print(f"qemu-full-os-rc: running {' '.join(cmd)}", flush=True)
    proc = subprocess.run(cmd, check=False, env=env, text=True)
    return proc.returncode


def load_json(path: Path, failures: List[str]) -> Dict[str, Any]:
    if not path.exists():
        failures.append(f"missing artifact: {path}")
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        failures.append(f"invalid JSON artifact: {path}: {exc}")
        return {}


def check_equal(value: Any, expected: Any, name: str,
                failures: List[str]) -> None:
    if value != expected:
        failures.append(f"{name} expected {expected!r}, got {value!r}")


def check_bool(value: Any, expected: bool, name: str,
               failures: List[str]) -> None:
    if value is not expected:
        failures.append(f"{name} expected {expected!r}, got {value!r}")


def syscall_define_to_name(symbol: str) -> str:
    return symbol.lower()


def parse_syscall_header(root: Path,
                         failures: List[str]) -> Tuple[Dict[str, int],
                                                       Dict[str, int]]:
    header = root / "kernel/include/xaios/syscall.h"
    if not header.exists():
        failures.append("missing syscall ABI header")
        return {}, {}
    text = header.read_text(encoding="utf-8")
    syscalls: Dict[str, int] = {}
    capabilities: Dict[str, int] = {}
    syscall_re = re.compile(r"#define\s+XAIOS_SYSCALL_([A-Z0-9_]+)\s+UINT64_C\((\d+)\)")
    cap_re = re.compile(r"#define\s+(XAIOS_CAP_[A-Z0-9_]+)\s+UINT64_C\((\d+)\)")
    for match in syscall_re.finditer(text):
        syscalls[syscall_define_to_name(match.group(1))] = int(match.group(2))
    for match in cap_re.finditer(text):
        capabilities[match.group(1)] = int(match.group(2))
    return syscalls, capabilities


def validate_source_abi(root: Path, contract: Dict[str, Any],
                        failures: List[str]) -> None:
    source_syscalls, source_caps = parse_syscall_header(root, failures)
    contract_abi = contract.get("syscall_abi", {})
    contract_syscalls = contract_abi.get("syscalls", [])
    contract_caps = contract_abi.get("capabilities", [])

    for entry in contract_syscalls:
        name = entry.get("name")
        number = entry.get("number")
        source_number = source_syscalls.get(str(name))
        if source_number != number:
            failures.append(
                f"source syscall ABI mismatch for {name}: source={source_number!r} contract={number!r}"
            )

    for entry in contract_caps:
        name = entry.get("name")
        bit = entry.get("bit")
        source_bit = source_caps.get(str(name))
        if source_bit != bit:
            failures.append(
                f"source capability ABI mismatch for {name}: source={source_bit!r} contract={bit!r}"
            )

    syscall_numbers = sorted(source_syscalls.values())
    expected_numbers = list(range(1, len(contract_syscalls) + 1))
    if syscall_numbers != expected_numbers:
        failures.append(
            f"source syscall numbers expected contiguous {expected_numbers}, got {syscall_numbers}"
        )


def validate_benchmark(report: Dict[str, Any], failures: List[str]) -> None:
    check_equal(report.get("schema"), BENCHMARK_SCHEMA, "benchmark.schema",
                failures)
    check_equal(report.get("status"), "pass", "benchmark.status", failures)
    check_equal(report.get("benchmark_type"), "qemu-correctness",
                "benchmark.benchmark_type", failures)
    check_bool(report.get("baseline_required_for_performance_claims"), True,
               "benchmark.baseline_required_for_performance_claims", failures)
    check_bool(report.get("performance_claims_allowed"), False,
               "benchmark.performance_claims_allowed", failures)

    gates = report.get("gates", {})
    if not isinstance(gates, dict):
        failures.append("benchmark.gates missing or not an object")
        return
    for gate in EXPECTED_BENCHMARK_GATES:
        if gates.get(gate) is not True:
            failures.append(f"benchmark gate not passing: {gate}")
    unexpected_failed = sorted(name for name, passed in gates.items()
                               if passed is not True)
    if unexpected_failed:
        failures.append(f"benchmark has failed gates: {unexpected_failed}")


def validate_readiness(report: Dict[str, Any], failures: List[str]) -> None:
    check_equal(report.get("schema"), READINESS_SCHEMA, "readiness.schema",
                failures)
    check_equal(report.get("status"), "pass", "readiness.status", failures)
    check_equal(report.get("matrix_exit_code"), 0, "readiness.matrix_exit_code",
                failures)
    check_bool(report.get("performance_claims_allowed"), False,
               "readiness.performance_claims_allowed", failures)
    artifacts = report.get("artifacts", {})
    for name in [
            "benchmark_report",
            "preview_manifest",
            "cpu_matrix_report",
            "release_candidate_contract",
            "readiness_report",
    ]:
        if name not in artifacts:
            failures.append(f"readiness.artifacts missing {name}")


def validate_preview(report: Dict[str, Any], failures: List[str]) -> None:
    check_equal(report.get("schema"), PREVIEW_SCHEMA, "preview.schema",
                failures)
    check_equal(report.get("status"), "pass", "preview.status", failures)
    check_equal(report.get("release_candidate_contract"), CONTRACT_PATH,
                "preview.release_candidate_contract", failures)
    contracts = report.get("contracts", {})
    check_bool(contracts.get("performance_claims_allowed"), False,
               "preview.contracts.performance_claims_allowed", failures)
    check_equal(contracts.get("userspace"),
                "EL0 /init plus /bin/service-manager from VirtIO-backed read-only filesystem",
                "preview.contracts.userspace", failures)


def validate_cpu_matrix(report: Dict[str, Any], contract: Dict[str, Any],
                        failures: List[str]) -> None:
    check_equal(report.get("schema"), CPU_MATRIX_SCHEMA, "cpu_matrix.schema",
                failures)
    check_equal(report.get("status"), "pass", "cpu_matrix.status", failures)
    check_equal(report.get("contract"), CONTRACT_PATH, "cpu_matrix.contract",
                failures)
    tiers = report.get("tiers", [])
    if not isinstance(tiers, list) or not tiers:
        failures.append("cpu_matrix.tiers missing or empty")
        return
    failed = [
        tier.get("name") for tier in tiers
        if tier.get("required") is not False and tier.get("status") != "pass"
    ]
    if failed:
        failures.append(f"cpu_matrix failed tiers: {failed}")

    required = set()
    matrix_contract = contract.get("cpu_matrix", {})
    for tier in matrix_contract.get("arm64_boot_tiers", []):
        required.add(tier.get("name"))
    for tier in matrix_contract.get("x86_64_command_tiers", []):
        required.add(tier.get("name"))
    actual = {tier.get("name") for tier in tiers}
    missing = sorted(name for name in required if name not in actual)
    if missing:
        failures.append(f"cpu_matrix missing contract tiers: {missing}")


def validate_contract(contract: Dict[str, Any], failures: List[str]) -> None:
    check_equal(contract.get("schema"), CONTRACT_SCHEMA, "contract.schema",
                failures)
    check_equal(contract.get("status"), "frozen", "contract.status", failures)
    check_equal(contract.get("release_candidate"), "qemu-rc-1",
                "contract.release_candidate", failures)
    scope = contract.get("scope", {})
    check_equal(scope.get("architecture"), "aarch64+x86_64",
                "contract.scope.architecture", failures)
    check_equal(scope.get("machine"), "qemu-virt+q35",
                "contract.scope.machine", failures)
    check_equal(scope.get("firmware"), "UEFI", "contract.scope.firmware",
                failures)
    check_equal(scope.get("benchmark_type"), "qemu-correctness",
                "contract.scope.benchmark_type", failures)
    check_bool(scope.get("performance_claims_allowed"), False,
               "contract.scope.performance_claims_allowed", failures)
    if len(contract.get("out_of_scope_before_intel", [])) < 5:
        failures.append("contract.out_of_scope_before_intel is too short")


def validate_docs(root: Path, failures: List[str]) -> Dict[str, bool]:
    required = {
        "HARDWARE-READINESS.md": [
            "make qemu-full-os-rc",
            "xaios.qemu.full_os_release_candidate.v1",
            "build/qemu-full-os-rc-report.json",
            "QEMU correctness gate",
        ],
        "README.md": [
            "## Model support status",
            "Fixture only",
            "Qwen 3.8 27B",
            "Kimi K3 text",
        ],
        "docs/BENCHMARK-CONTRACT.md": [
            "QEMU output proves correctness and ABI behavior only",
            "performance_claims_allowed=false",
        ],
    }
    result: Dict[str, bool] = {}
    for relative, snippets in required.items():
        path = root / relative
        if not path.exists():
            failures.append(f"missing documentation: {relative}")
            result[relative] = False
            continue
        text = path.read_text(encoding="utf-8")
        missing = [snippet for snippet in snippets if snippet not in text]
        if missing:
            failures.append(f"{relative} missing snippets: {missing}")
            result[relative] = False
        else:
            result[relative] = True
    return result


def main() -> int:
    root = Path.cwd()
    build_dir = root / "build"
    build_dir.mkdir(exist_ok=True)
    output_path = Path(os.environ.get("XAIOS_QEMU_FULL_OS_RC_OUTPUT",
                                      str(build_dir / "qemu-full-os-rc-report.json")))

    env = os.environ.copy()
    env.setdefault("XAIOS_QEMU_SMOKE_TIMEOUT", "60")

    gate_rc = run(["make", "qemu-readiness-gate"], env)
    failures: List[str] = []
    if gate_rc != 0:
        failures.append(f"qemu-readiness-gate failed with exit code {gate_rc}")

    contract = load_json(root / CONTRACT_PATH, failures)
    readiness = load_json(build_dir / "qemu-readiness-report.json", failures)
    benchmark = load_json(build_dir / "qemu-benchmark-report.json", failures)
    preview = load_json(build_dir / "qemu-preview-manifest.json", failures)
    cpu_matrix = load_json(build_dir / "qemu-cpu-matrix-report.json", failures)

    if contract:
        validate_contract(contract, failures)
        validate_source_abi(root, contract, failures)
    if readiness:
        validate_readiness(readiness, failures)
    if benchmark:
        validate_benchmark(benchmark, failures)
    if preview:
        validate_preview(preview, failures)
    if cpu_matrix and contract:
        validate_cpu_matrix(cpu_matrix, contract, failures)
    docs = validate_docs(root, failures)

    report = {
        "schema": REPORT_SCHEMA,
        "created_unix": int(time.time()),
        "milestone": 42,
        "release_candidate": "qemu-rc-1",
        "status": "fail" if failures else "pass",
        "qemu_full_os_complete": not failures,
        "next_allowed_phase": "Intel Desktop bring-up" if not failures else None,
        "performance_claims_allowed": False,
        "validated_subsystems": VALIDATED_SUBSYSTEMS,
        "artifacts": {
            "full_os_rc_report": "build/qemu-full-os-rc-report.json",
            "readiness_report": "build/qemu-readiness-report.json",
            "benchmark_report": "build/qemu-benchmark-report.json",
            "preview_manifest": "build/qemu-preview-manifest.json",
            "cpu_matrix_report": "build/qemu-cpu-matrix-report.json",
            "release_candidate_contract": CONTRACT_PATH,
        },
        "schemas": {
            "full_os_rc": REPORT_SCHEMA,
            "readiness": readiness.get("schema") if readiness else None,
            "benchmark": benchmark.get("schema") if benchmark else None,
            "preview": preview.get("schema") if preview else None,
            "cpu_matrix": cpu_matrix.get("schema") if cpu_matrix else None,
            "contract": contract.get("schema") if contract else None,
        },
        "documentation": docs,
        "failures": failures,
    }

    output_path.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n",
                           encoding="utf-8")
    print(f"qemu-full-os-rc: report written to {output_path}")
    if failures:
        print("qemu-full-os-rc: failed")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("qemu-full-os-rc: milestone 42 full QEMU OS release candidate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
