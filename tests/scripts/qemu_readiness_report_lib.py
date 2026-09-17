#!/usr/bin/env python3
"""Benchmark, preview and documentation validation for the readiness gate.

The gate is `qemu-readiness-gate.py`. This module holds the validators that read
the benchmark report, the preview manifest and the hardware-readiness
documentation -- everything that checks the artifacts rather than the frozen
contract. It was split out so the gate stays under the repository's 500-line
limit. The moved code is verbatim; the gate imports these names, so the command
line, the output and the exit codes are unchanged.

The telemetry tables and the two comparison helpers live in
`qemu_readiness_contract_lib.py` because the contract and CPU-matrix validators
use them too; this module imports them rather than restating them.

It is imported and is not itself a program: `python3
tests/scripts/qemu-readiness-gate.py` remains the only entry point.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List

from qemu_readiness_contract_lib import (
    BENCHMARK_SCHEMA,
    CONTRACT_PATH,
    CONTRACT_SCHEMA,
    PREVIEW_SCHEMA,
    REQUIRED_TELEMETRY_EQUALS,
    REQUIRED_TELEMETRY_MINIMUMS,
    check_bool,
    check_equal,
)


def validate_benchmark(report: Dict[str, Any], failures: List[str]) -> Dict[str, Any]:
    check_equal(report.get("schema"), BENCHMARK_SCHEMA, "benchmark.schema", failures)
    check_equal(report.get("status"), "pass", "benchmark.status", failures)
    check_equal(report.get("benchmark_type"), "qemu-correctness", "benchmark.benchmark_type", failures)
    check_bool(report.get("baseline_required_for_performance_claims"), True, "benchmark.baseline_required_for_performance_claims", failures)
    check_bool(report.get("performance_claims_allowed"), False, "benchmark.performance_claims_allowed", failures)

    gates = report.get("gates", {})
    if not isinstance(gates, dict) or not gates:
        failures.append("benchmark.gates missing or empty")
    else:
        failed_gates = sorted(name for name, passed in gates.items() if passed is not True)
        if failed_gates:
            failures.append(f"benchmark gates failed: {failed_gates}")

    telemetry = report.get("telemetry", {})
    if not isinstance(telemetry, dict):
        failures.append("benchmark.telemetry missing or not an object")
        return {}

    for key, minimum in REQUIRED_TELEMETRY_MINIMUMS.items():
        value = telemetry.get(key)
        if not isinstance(value, int) or value < minimum:
            failures.append(f"telemetry.{key} expected >= {minimum}, got {value!r}")

    for key, expected in REQUIRED_TELEMETRY_EQUALS.items():
        value = telemetry.get(key)
        if value != expected:
            failures.append(f"telemetry.{key} expected {expected}, got {value!r}")

    return telemetry


def validate_preview(manifest: Dict[str, Any], benchmark: Dict[str, Any], failures: List[str]) -> None:
    check_equal(manifest.get("schema"), PREVIEW_SCHEMA, "preview.schema", failures)
    check_equal(manifest.get("status"), "pass", "preview.status", failures)
    check_equal(manifest.get("benchmark_schema"), BENCHMARK_SCHEMA, "preview.benchmark_schema", failures)
    check_equal(manifest.get("release_candidate_contract"), CONTRACT_PATH, "preview.release_candidate_contract", failures)

    contracts = manifest.get("contracts", {})
    if not isinstance(contracts, dict):
        failures.append("preview.contracts missing or not an object")
        return

    check_equal(contracts.get("architecture"), "aarch64", "preview.contracts.architecture", failures)
    check_equal(contracts.get("firmware"), "UEFI", "preview.contracts.firmware", failures)
    check_equal(contracts.get("machine"), "qemu-virt", "preview.contracts.machine", failures)
    check_equal(contracts.get("release_candidate_contract_schema"), CONTRACT_SCHEMA, "preview.contracts.release_candidate_contract_schema", failures)
    check_bool(contracts.get("performance_claims_allowed"), False, "preview.contracts.performance_claims_allowed", failures)

    benchmark_telemetry = benchmark.get("telemetry", {}) if isinstance(benchmark, dict) else {}
    preview_telemetry = manifest.get("telemetry", {})
    if isinstance(benchmark_telemetry, dict) and isinstance(preview_telemetry, dict):
        for key in REQUIRED_TELEMETRY_EQUALS:
            if preview_telemetry.get(key) != benchmark_telemetry.get(key):
                failures.append(f"preview.telemetry.{key} does not match benchmark telemetry")

def validate_docs(root: str, failures: List[str]) -> Dict[str, bool]:
    required_snippets = {
        "HARDWARE-READINESS.md": [
            "make qemu-readiness-gate",
            "xaios.qemu.hardware_readiness_gate.v1",
            "xaios.qemu.release_candidate_contract.v1",
            "correctness benchmark only",
        ],
    }
    result: Dict[str, bool] = {}
    for relative, snippets in required_snippets.items():
        path = os.path.join(root, relative)
        if not os.path.exists(path):
            failures.append(f"missing documentation: {relative}")
            result[relative] = False
            continue
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
        missing = [snippet for snippet in snippets if snippet not in text]
        if missing:
            failures.append(f"{relative} missing snippets: {missing}")
            result[relative] = False
        else:
            result[relative] = True
    return result
