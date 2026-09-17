#!/usr/bin/env python3
import json
import os
import subprocess
import time
from typing import Any, Dict, List

from qemu_readiness_contract_lib import (
    CONTRACT_PATH,
    FROZEN_QEMU_CONTRACTS,
    INTEL_DESKTOP_ENTRY_CRITERIA,
    REPORT_SCHEMA,
    validate_contract,
    validate_cpu_matrix,
)
from qemu_readiness_report_lib import (
    validate_benchmark,
    validate_docs,
    validate_preview,
)


def run(cmd: List[str], env: Dict[str, str]) -> subprocess.CompletedProcess:
    print(f"qemu-readiness-gate: running {' '.join(cmd)}", flush=True)
    return subprocess.run(
        cmd,
        check=False,
        env=env,
        stdout=None,
        stderr=None,
        text=True,
    )


def load_json(path: str, failures: List[str]) -> Dict[str, Any]:
    if not os.path.exists(path):
        failures.append(f"missing artifact: {path}")
        return {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except json.JSONDecodeError as exc:
        failures.append(f"invalid JSON artifact: {path}: {exc}")
        return {}


def main() -> int:
    root = os.getcwd()
    build_dir = os.path.join(root, "build")
    os.makedirs(build_dir, exist_ok=True)

    env = os.environ.copy()
    env.setdefault("XAIOS_QEMU_SMOKE_TIMEOUT", "60")
    matrix = run(["make", "qemu-matrix"], env)

    failures: List[str] = []
    if matrix.returncode != 0:
        failures.append(f"qemu matrix failed with exit code {matrix.returncode}")

    benchmark_path = os.path.join(build_dir, "qemu-benchmark-report.json")
    preview_path = os.path.join(build_dir, "qemu-preview-manifest.json")
    cpu_matrix_path = os.path.join(build_dir, "qemu-cpu-matrix-report.json")
    readiness_path = os.path.join(build_dir, "qemu-readiness-report.json")
    contract_path = os.path.join(root, CONTRACT_PATH)

    contract = load_json(contract_path, failures)
    benchmark = load_json(benchmark_path, failures)
    preview = load_json(preview_path, failures)
    cpu_matrix = load_json(cpu_matrix_path, failures)
    if contract:
        validate_contract(contract, failures)
    telemetry = validate_benchmark(benchmark, failures) if benchmark else {}
    if preview:
        validate_preview(preview, benchmark, failures)
    if cpu_matrix and contract:
        validate_cpu_matrix(cpu_matrix, contract, failures)
    doc_checks = validate_docs(root, failures)

    report = {
        "schema": REPORT_SCHEMA,
        "created_unix": int(time.time()),
        "status": "fail" if failures else "pass",
        "qemu_full_os_complete": False,
        "qemu_full_os_note": "Milestone 33 freezes the QEMU hardware-readiness contract. It does not mark the full QEMU OS complete.",
        "matrix_exit_code": matrix.returncode,
        "artifacts": {
            "benchmark_report": "build/qemu-benchmark-report.json",
            "preview_manifest": "build/qemu-preview-manifest.json",
            "cpu_matrix_report": "build/qemu-cpu-matrix-report.json",
            "release_candidate_contract": CONTRACT_PATH,
            "readiness_report": "build/qemu-readiness-report.json",
        },
        "release_candidate_contract_schema": contract.get("schema") if contract else None,
        "frozen_qemu_contracts": FROZEN_QEMU_CONTRACTS,
        "intel_desktop_entry_criteria": INTEL_DESKTOP_ENTRY_CRITERIA,
        "benchmark_schema": benchmark.get("schema") if benchmark else None,
        "preview_schema": preview.get("schema") if preview else None,
        "cpu_matrix_schema": cpu_matrix.get("schema") if cpu_matrix else None,
        "performance_claims_allowed": benchmark.get("performance_claims_allowed") if benchmark else None,
        "out_of_scope_before_intel": contract.get("out_of_scope_before_intel", []) if contract else [],
        "telemetry": telemetry,
        "documentation": doc_checks,
        "failures": failures,
    }

    with open(readiness_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, sort_keys=True, indent=2)

    print(f"qemu-readiness-gate: report written to {readiness_path}")
    if failures:
        print(
            "qemu-readiness-gate: failed "
            f"({len(failures)} checks; details are in the report)"
        )
        return 1

    print("qemu-readiness-gate: milestone 33 hardware-readiness gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
