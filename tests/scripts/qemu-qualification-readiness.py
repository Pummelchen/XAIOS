#!/usr/bin/env python3
"""Assemble the strongest reproducible QEMU evidence before physical qualification."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
REPORT = BUILD / "qemu-qualification-readiness-report.json"
SCHEMA = "xaios.qemu.qualification_readiness.v1"


def source_commit() -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip() if completed.returncode == 0 else "unknown"


def run_step(name: str, command: list[str], timeout: int,
             environment: dict[str, str] | None = None) -> dict[str, Any]:
    log_path = BUILD / f"qemu-qualification-{name}.log"
    env = os.environ.copy()
    if environment:
        env.update(environment)
    started = time.monotonic()
    print(f"qualification: running {name}", flush=True)
    try:
        with log_path.open("w", encoding="utf-8") as log:
            completed = subprocess.run(
                command,
                cwd=ROOT,
                env=env,
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout,
                check=False,
            )
        status = "pass" if completed.returncode == 0 else "fail"
        error = None
    except subprocess.TimeoutExpired:
        completed = None
        status = "fail"
        error = f"timed out after {timeout}s"
    duration = round(time.monotonic() - started, 3)
    tail = ""
    if log_path.exists():
        tail = "\n".join(log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-12:])
    print(f"qualification: {name} {status} duration={duration}s", flush=True)
    return {
        "name": name,
        "status": status,
        "exit_code": completed.returncode if completed is not None else None,
        "duration_seconds": duration,
        "timeout_seconds": timeout,
        "log": str(log_path.relative_to(ROOT)),
        "tail": tail,
        "error": error,
    }


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def artifact_manifest(paths: list[str]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for relative in paths:
        path = ROOT / relative
        if path.exists() and path.is_file():
            entries.append({
                "path": relative,
                "sha256": sha256(path),
                "bytes": path.stat().st_size,
            })
    return entries


def main() -> int:
    BUILD.mkdir(parents=True, exist_ok=True)
    soak_boots_text = os.environ.get("XAIOS_QUALIFICATION_SOAK_BOOTS", "5")
    try:
        soak_boots = int(soak_boots_text)
    except ValueError:
        print("qualification: XAIOS_QUALIFICATION_SOAK_BOOTS must be an integer")
        return 2
    if soak_boots < 1:
        print("qualification: XAIOS_QUALIFICATION_SOAK_BOOTS must be positive")
        return 2
    benchmark_output = BUILD / "qemu-qualification-benchmark.json"
    steps = [
        ("prepare_test_images", ["make", "image-qemu-test", "image-x86_64-qemu-test"],
         600, {}),
        ("benchmark", [sys.executable, "tests/scripts/qemu-benchmark.py"], 900,
         {"XAIOS_QEMU_BENCHMARK_OUTPUT": str(benchmark_output)}),
        ("network", [sys.executable, "tests/scripts/qemu-network-suite.py"], 420, {}),
        ("fragmentation", [sys.executable, "tests/scripts/qemu-outbound-fragmentation-gate.py"], 600, {}),
        ("nvme", [sys.executable, "tests/scripts/qemu-nvme-gate.py"], 600, {}),
        ("sve_context", [sys.executable, "tests/scripts/qemu-aarch64-sve2-gate.py"], 600, {}),
        ("x86_numa_hmat", [sys.executable, "tests/scripts/qemu-x86_64-numa-gate.py"], 600, {}),
        ("high_core", [sys.executable, "tests/scripts/qemu-high-core-gate.py"], 900, {}),
        ("x86_64", [sys.executable, "tests/scripts/qemu-x86_64-smoke.py"], 360, {}),
        ("sustained_soak", [sys.executable, "tests/scripts/qemu-soak-gate.py"], 1200,
         {"XAIOS_QEMU_SOAK_BOOTS": str(soak_boots)}),
        # xapt and operations rebuild production images. Keep every gate that
        # consumes diagnostic boot markers ahead of these image-mutating steps.
        ("xapt_tls", [sys.executable, "tests/scripts/qemu-xapt-gate.py"], 1800, {}),
        ("ssh_network", [sys.executable, "tests/scripts/qemu-operations-closure.py", "--skip-docker"], 900, {}),
        ("storage_crash", [sys.executable, "tests/scripts/qemu-storage-crash-test.py"], 900, {}),
    ]
    results = [run_step(name, command, timeout, environment)
               for name, command, timeout, environment in steps]
    failures = [item["name"] for item in results if item["status"] != "pass"]
    physical_metrics = {
        "numa_local_remote_bytes": {
            "status": "unavailable-in-qemu",
            "required_for": "physical NUMA qualification",
        },
        "memory_bandwidth": {
            "status": "unavailable-in-qemu",
            "required_for": "physical performance qualification",
        },
        "pmu_cycles_cache_tlb_stalls": {
            "status": "unavailable-in-qemu",
            "required_for": "physical diagnostic evidence",
        },
        "frequency_power_thermal_throttling": {
            "status": "unavailable-in-qemu",
            "required_for": "physical sustained-load qualification",
        },
        "physical_nic_loss_reorder_latency": {
            "status": "unavailable-in-qemu",
            "required_for": "N-F3P physical SSH/network qualification",
        },
        "physical_nvme_durability_queue_scaling": {
            "status": "unavailable-in-qemu",
            "required_for": "S-11P physical NVMe qualification",
        },
    }
    artifact_paths = [
        "build/qemu-qualification-benchmark.json",
        "build/qemu-milestone-57-network-suite.json",
        "build/qemu-outbound-fragmentation-report.json",
        "build/qemu-nvme-gate-report.json",
        "build/qemu-high-core-gate-report.json",
        "build/qemu-milestone-69-soak-gate.json",
    ]
    artifact_paths.extend(item["log"] for item in results)
    report = {
        "schema": SCHEMA,
        "status": "pass" if not failures else "fail",
        "qualification_status": "qemu_evidence_pass_physical_open" if not failures else "qemu_evidence_incomplete",
        "created_at_unix": int(time.time()),
        "source_commit": source_commit(),
        "execution_commit": source_commit(),
        "qemu_correctness_only": True,
        "physical_qualification": False,
        "performance_claims_allowed": False,
        "soak_boots_requested": soak_boots,
        "steps": results,
        "failures": failures,
        "physical_metrics": physical_metrics,
        "physical_evidence_contract": {
            "required_identity": [
                "hardware_model_and_revision",
                "firmware_and_microcode",
                "kernel_and_executable_commit",
                "topology_and_numa_map",
                "driver_and_device_firmware_versions",
            ],
            "required_measurements": [
                "NUMA-local-and-remote-bytes",
                "sustained-memory-bandwidth",
                "PMU-cycles-instructions-cache-misses-TLB-walks-stalls",
                "frequency-power-thermal-throttling",
                "NIC-throughput-latency-loss-reorder-and-SSH-soak",
                "NVMe-queue-scaling-latency-flush-FUA-discard-reset-and-power-loss",
            ],
            "qemu_artifacts_cannot_satisfy": True,
        },
        "artifacts": artifact_manifest(artifact_paths),
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                      encoding="utf-8")
    print(f"qualification: report written to {REPORT.relative_to(ROOT)}")
    if failures:
        print(f"qualification: failed steps={','.join(failures)}")
        return 1
    print("qualification: QEMU evidence passed; physical qualification remains open")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
