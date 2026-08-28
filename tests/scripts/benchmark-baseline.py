#!/usr/bin/env python3
"""Benchmark baseline: compare XAIOS QEMU telemetry against optional Linux baseline.

Produces a structured JSON report comparing XAIOS correctness metrics with an
optional Linux QEMU baseline.  The Linux baseline is best-effort -- if Linux
QEMU is unavailable the comparison section is empty and the script still
succeeds with XAIOS-only results.

No performance claims are derived from QEMU results.  This script validates
correctness gates and collects telemetry for trending.
"""
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"


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


def run_xaios_smoke():
    """Run XAIOS smoke test and extract telemetry."""
    env = os.environ.copy()
    env.setdefault("XAIOS_QEMU_SMOKE_TIMEOUT", "60")
    env.setdefault("XAIOS_QEMU_HOSTFWD_PORT", "none")
    proc = subprocess.run(
        ["make", "qemu-aarch64"],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=180,
        check=False,
    )
    if proc.returncode != 0:
        sys.stdout.write(proc.stdout)
        return None, proc.returncode
    telemetry = parse_telemetry(proc.stdout)
    return telemetry, proc.returncode


def run_linux_baseline():
    """Attempt a minimal Linux QEMU boot for baseline comparison.

    Returns a dict of comparable metrics, or None if Linux QEMU is unavailable.
    This is intentionally minimal -- it boots a tiny Linux kernel in QEMU and
    measures boot time and memory footprint for rough comparison.
    """
    qemu_bin = "qemu-system-aarch64"
    try:
        subprocess.run([qemu_bin, "--version"],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       check=True, timeout=10)
    except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError):
        return None

    # Check for Linux kernel and initrd (not shipped with XAIOS)
    linux_kernel = os.environ.get("XAIOS_LINUX_KERNEL", "")
    linux_initrd = os.environ.get("XAIOS_LINUX_INITRD", "")
    if not linux_kernel or not os.path.isfile(linux_kernel):
        return None
    if not linux_initrd or not os.path.isfile(linux_initrd):
        return None

    start_ns = time.monotonic_ns()
    try:
        proc = subprocess.run(
            [
                qemu_bin,
                "-machine", "virt",
                "-cpu", "cortex-a72",
                "-m", "256",
                "-nographic",
                "-kernel", linux_kernel,
                "-initrd", linux_initrd,
                "-append", "console=ttyAMA0 quiet",
                "-no-reboot",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=60,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None

    elapsed_ms = (time.monotonic_ns() - start_ns) // 1_000_000
    output = proc.stdout

    # Extract basic metrics from dmesg/boot output
    memory_kb = 0
    for line in output.splitlines():
        if "Memory:" in line and "available" in line:
            try:
                parts = line.split()
                for i, part in enumerate(parts):
                    if part.endswith("k") and i > 0:
                        memory_kb = int(part.rstrip("k"))
                        break
            except (ValueError, IndexError):
                pass

    return {
        "boot_time_ms": elapsed_ms,
        "memory_available_kb": memory_kb,
        "exit_code": proc.returncode,
        "qemu_accel": "tcg",
        "note": "Minimal Linux boot for comparison. Not a tuned bare-metal baseline.",
    }


def extract_xaios_metrics(telemetry):
    """Extract key metrics from XAIOS telemetry for comparison."""
    if telemetry is None:
        return {}
    return {
        "cpu_count": telemetry.get("cpu_count", 0),
        "pmm_total_pages": telemetry.get("pmm_total_pages", 0),
        "pmm_free_pages": telemetry.get("pmm_free_pages", 0),
        "kheap_pages": telemetry.get("kheap_pages", 0),
        "user_process_transitions": telemetry.get("user_process_transitions", 0),
        "user_process_loaded": telemetry.get("user_process_loaded", 0),
        "user_process_exited": telemetry.get("user_process_exited", 0),
        "user_process_failed": telemetry.get("user_process_failed", -1),
        "context_switch_total": telemetry.get("context_switch_total", 0),
        "migration_total": telemetry.get("migration_total", 0),
        "network_rx_packets": telemetry.get("network_rx_packets", 0),
        "network_tx_packets": telemetry.get("network_tx_packets", 0),
        "xaiboot_fs_files": telemetry.get("xaiboot_fs_files", 0),
        "xaiboot_fs_writes": telemetry.get("xaiboot_fs_writes", 0),
        "xaiboot_fs_reads": telemetry.get("xaiboot_fs_reads", 0),
    }


def main() -> int:
    print("benchmark-baseline: running XAIOS smoke test...", flush=True)
    telemetry, smoke_rc = run_xaios_smoke()

    if telemetry is None:
        print("benchmark-baseline: XAIOS smoke test failed or no telemetry")
        return 1

    xaios_metrics = extract_xaios_metrics(telemetry)

    print("benchmark-baseline: attempting Linux baseline...", flush=True)
    linux = run_linux_baseline()
    linux_metrics = linux if linux else {}

    report = {
        "schema": "xaios.benchmark.baseline_comparison.v1",
        "collected_at_unix": int(time.time()),
        "host_os": platform.system().lower(),
        "host_arch": platform.machine(),
        "qemu_accel": "tcg",
        "xaios": {
            "status": "pass" if smoke_rc == 0 else "fail",
            "smoke_exit_code": smoke_rc,
            "metrics": xaios_metrics,
            "telemetry_keys": len(telemetry),
        },
        "linux_baseline": linux_metrics,
        "comparison": {},
        "performance_claims_allowed": False,
        "baseline_required_for_performance_claims": True,
        "notes": (
            "QEMU TCG/HVF results validate correctness, not performance. "
            "Bare-metal benchmarks with isolcpus/CPU-pinning are required "
            "for production performance claims."
        ),
    }

    if linux:
        report["comparison"] = {
            "xaios_cpu_count": xaios_metrics.get("cpu_count", 0),
            "linux_boot_available": True,
            "linux_boot_time_ms": linux.get("boot_time_ms", 0),
            "linux_memory_kb": linux.get("memory_available_kb", 0),
            "note": "XAIOS and Linux boot different workloads; direct comparison requires bare-metal tuning.",
        }
    else:
        report["comparison"] = {
            "linux_boot_available": False,
            "note": "Linux baseline skipped (set XAIOS_LINUX_KERNEL and XAIOS_LINUX_INITRD to enable).",
        }

    report_json = json.dumps(report, sort_keys=True, indent=2)
    print(f"benchmark-baseline: report={json.dumps(report, sort_keys=True)}")

    output_path = os.environ.get("XAIOS_BENCHMARK_OUTPUT")
    if not output_path:
        output_path = str(BUILD / "benchmark-baseline.json")
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_json + "\n")
    print(f"benchmark-baseline: report written to {output_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
