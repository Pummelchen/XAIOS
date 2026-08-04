#!/usr/bin/env python3
import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List


ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build"
REPORT_PATH = BUILD / "qemu-x86_64-platform-matrix-report.json"
SCHEMA = "xaios.qemu.x86_64_platform_matrix.v1"
SCENARIOS = [
    {
        "name": "q35-baseline",
        "machine": "q35",
        "cpu": "max",
        "smp": 4,
        "memory": "2G",
        "accelerator": "tcg",
    },
    {
        "name": "q35-uniprocessor-fallback",
        "machine": "q35",
        "cpu": "qemu64",
        "smp": 1,
        "memory": "512M",
        "accelerator": "tcg",
    },
    {
        "name": "q35-server-eight-way",
        "machine": "q35",
        "cpu": "max",
        "smp": 8,
        "memory": "4G",
        "accelerator": "tcg,thread=multi",
    },
    {
        "name": "q35-high-core-128",
        "machine": "q35",
        "cpu": "max",
        "smp": 128,
        "memory": "4G",
        "accelerator": "tcg,thread=multi",
    },
    {
        "name": "q35-high-core-256-x2apic",
        "machine": "q35",
        "cpu": "max",
        "smp": 256,
        "memory": "4G",
        "accelerator": "tcg,thread=multi",
        "apic_mode": "x2apic",
    },
    {
        "name": "pc-compatibility",
        "machine": "pc",
        "cpu": "max",
        "smp": 4,
        "memory": "2G",
        "accelerator": "tcg",
    },
    {
        "name": "q35-nvme-inventory",
        "machine": "q35",
        "cpu": "max",
        "smp": 4,
        "memory": "2G",
        "accelerator": "tcg",
        "nvme": True,
    },
    {
        "name": "q35-tcg-single-thread",
        "machine": "q35",
        "cpu": "max",
        "smp": 2,
        "memory": "1G",
        "accelerator": "tcg,thread=single",
    },
]


def qemu_version() -> str:
    qemu = shutil.which("qemu-system-x86_64")
    if qemu is None:
        return "unavailable"
    proc = subprocess.run(
        [qemu, "--version"],
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    return proc.stdout.splitlines()[0] if proc.stdout else "unknown"


def run_scenario(scenario: Dict[str, Any]) -> Dict[str, Any]:
    name = str(scenario["name"])
    log_path = BUILD / f"qemu-x86_64-platform-{name}.log"
    env = os.environ.copy()
    env.update({
        "XAIOS_QEMU_X86_ACCEL": str(scenario["accelerator"]),
        "XAIOS_QEMU_X86_MACHINE": str(scenario["machine"]),
        "XAIOS_QEMU_X86_CPU": str(scenario["cpu"]),
        "XAIOS_QEMU_X86_MEMORY": str(scenario["memory"]),
        "XAIOS_QEMU_X86_SMP": str(scenario["smp"]),
        "XAIOS_QEMU_X86_SMOKE_TIMEOUT": "180",
    })
    if scenario.get("nvme"):
        env["XAIOS_QEMU_X86_NVME_IMAGE"] = str(
            BUILD / "qemu-x86_64-platform-nvme.img"
        )
    started = time.monotonic()
    timed_out = False
    try:
        proc = subprocess.run(
            ["python3", "./scripts/qemu-x86_64-smoke.py"],
            cwd=ROOT,
            env=env,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=210,
        )
        output = proc.stdout
        exit_code = proc.returncode
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        exit_code = None
        timed_out = True

    log_path.write_text(output, encoding="utf-8")
    required_markers = [
        f"x86_64: placement policy logical_cpus={scenario['smp']}"
    ]
    if scenario.get("nvme"):
        required_markers.append("nvme=1")
    if scenario.get("apic_mode"):
        required_markers.append(f"mode={scenario['apic_mode']}")
    missing_markers = [marker for marker in required_markers
                       if marker not in output]
    passed = exit_code == 0 and not missing_markers and not timed_out
    if not passed:
        print(f"qemu-x86_64-platform-matrix: {name} failed")
        print(output[-4000:])
    else:
        print(f"qemu-x86_64-platform-matrix: {name} passed", flush=True)
    return {
        **scenario,
        "status": "pass" if passed else "fail",
        "exit_code": exit_code,
        "timed_out": timed_out,
        "required_markers": required_markers,
        "missing_markers": missing_markers,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "log": str(log_path.relative_to(ROOT)),
    }


def main() -> int:
    BUILD.mkdir(parents=True, exist_ok=True)
    nvme_image = BUILD / "qemu-x86_64-platform-nvme.img"
    with nvme_image.open("wb") as stream:
        stream.truncate(64 * 1024 * 1024)
    results: List[Dict[str, Any]] = [
        run_scenario(scenario) for scenario in SCENARIOS
    ]
    failures = [result["name"] for result in results
                if result["status"] != "pass"]
    report = {
        "schema": SCHEMA,
        "created_unix": int(time.time()),
        "status": "fail" if failures else "pass",
        "benchmark_type": "qemu-correctness",
        "performance_claims_allowed": False,
        "qemu_version": qemu_version(),
        "scenarios": results,
        "failures": failures,
    }
    REPORT_PATH.write_text(
        json.dumps(report, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"qemu-x86_64-platform-matrix: report written to "
          f"{REPORT_PATH.relative_to(ROOT)}")
    if failures:
        return 1
    print("qemu-x86_64-platform-matrix: all scenarios passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
