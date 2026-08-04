#!/usr/bin/env python3
import json
import os
import select
import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional, Set


CONTRACT_PATH = "contracts/qemu-rc-v1.json"
REPORT_PATH = os.environ.get(
    "XAIOS_QEMU_CPU_MATRIX_REPORT", "build/qemu-cpu-matrix-report.json"
)
SCHEMA = "xaios.qemu.cpu_matrix.v1"
BOOT_PROBE_MARKERS = [
    "XAIOS kernel starting",
    "smp: per-core registry self-test passed",
    "VMM map/unmap self-test passed",
    "VMM translation test passed",
    "virtio-blk: read/write/error/reset self-test passed",
    "persistence: disk reload/rollback self-test passed",
]


def find_qemu(binary: str) -> Optional[str]:
    candidates = [
        shutil.which(binary),
        f"/opt/homebrew/opt/qemu/bin/{binary}",
        f"/opt/homebrew/bin/{binary}",
        f"/usr/local/bin/{binary}",
    ]
    for candidate in candidates:
        if candidate and os.path.exists(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def cpu_help_set(qemu: str) -> Set[str]:
    proc = subprocess.run(
        [qemu, "-cpu", "help"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    supported: Set[str] = set()
    for line in proc.stdout.splitlines():
        parts = line.strip().split()
        if not parts:
            continue
        supported.add(parts[0])
    return supported


def run(cmd: List[str], env: Dict[str, str], timeout: int) -> subprocess.CompletedProcess:
    print(f"qemu-cpu-matrix: running {' '.join(cmd)}", flush=True)
    return subprocess.run(
        cmd,
        check=False,
        env=env,
        timeout=timeout,
        stdout=None,
        stderr=None,
        text=True,
    )


def run_until_markers(cmd: List[str], env: Dict[str, str], timeout: int,
                      markers: List[str]) -> Dict[str, Any]:
    print(f"qemu-cpu-matrix: probing {' '.join(cmd)}", flush=True)
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=False,
        bufsize=0,
        env=env,
    )
    seen: List[str] = []
    deadline = time.time() + timeout
    matched = False
    try:
        assert proc.stdout is not None
        fd = proc.stdout.fileno()
        while time.time() < deadline:
            ready, _, _ = select.select([fd], [], [], 0.2)
            if ready:
                chunk = os.read(fd, 4096).decode("utf-8", errors="replace")
                if not chunk:
                    break
                seen.append(chunk)
                text = "".join(seen)
                if all(marker in text for marker in markers):
                    matched = True
                    break
            elif proc.poll() is not None:
                break
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)

    text = "".join(seen)
    missing = [marker for marker in markers if marker not in text]
    if not matched:
        tail = text[-4000:]
        if tail:
            print("qemu-cpu-matrix: boot probe tail follows")
            print(tail)
    return {
        "exit_code": 0 if matched else (proc.returncode if proc.returncode is not None else 1),
        "matched": matched,
        "missing_markers": missing,
    }


def run_arm_boot_tier(tier: Dict[str, Any], supported: Set[str],
                      base_env: Dict[str, str]) -> Dict[str, Any]:
    cpu = tier["cpu"]
    accelerator = tier["accelerator"]
    name = tier["name"]
    required = tier.get("required", True)
    if (not required and accelerator == "hvf" and
            base_env.get("XAIOS_QEMU_RUN_OPTIONAL_HVF") != "1"):
        return {
            "name": name,
            "architecture": "aarch64",
            "cpu": cpu,
            "accelerator": accelerator,
            "validation": tier["validation"],
            "required": False,
            "supported": None,
            "exit_code": None,
            "status": "skipped",
            "reason": "set XAIOS_QEMU_RUN_OPTIONAL_HVF=1 to run experimental HVF",
        }
    if cpu != "host" and cpu not in supported:
        return {
            "name": name,
            "architecture": "aarch64",
            "cpu": cpu,
            "accelerator": accelerator,
            "validation": tier["validation"],
            "required": required,
            "supported": False,
            "exit_code": 1,
            "status": "fail",
            "error": "cpu model not listed by qemu-system-aarch64 -cpu help",
        }

    if tier["validation"] == "qemu-smoke-default":
        env = base_env.copy()
        env["XAIOS_QEMU_ACCEL"] = accelerator
        env["XAIOS_QEMU_CPU"] = cpu
        proc = run(["python3", "./scripts/qemu-smoke.py"], env, 140)
        return {
            "name": name,
            "architecture": "aarch64",
            "cpu": cpu,
            "accelerator": accelerator,
            "validation": tier["validation"],
            "required": required,
            "supported": True,
            "exit_code": proc.returncode,
            "status": "pass" if proc.returncode == 0 else "fail",
        }

    env = base_env.copy()
    env["XAIOS_QEMU_ACCEL"] = accelerator
    env["XAIOS_QEMU_CPU"] = cpu
    env["XAIOS_QEMU_HOSTFWD_PORT"] = "none"
    env.setdefault("XAIOS_QEMU_SMOKE_TIMEOUT", "90")
    probe = run_until_markers(["make", "qemu-aarch64"], env, 100,
                              BOOT_PROBE_MARKERS)
    return {
        "name": name,
        "architecture": "aarch64",
        "cpu": cpu,
        "accelerator": accelerator,
        "validation": tier["validation"],
        "required": required,
        "supported": True,
        "exit_code": probe["exit_code"],
        "missing_markers": probe["missing_markers"],
        "status": "pass" if probe["matched"] else "fail",
    }


def run_x86_tier(tier: Dict[str, Any], supported: Set[str],
                 base_env: Dict[str, str]) -> Dict[str, Any]:
    cpu = tier["cpu"]
    env = base_env.copy()
    env["XAIOS_QEMU_X86_CPU"] = cpu
    validation = tier["validation"]
    required = tier.get("required", True)
    supported_by_qemu = cpu == "max" or cpu in supported
    if not supported_by_qemu:
        return {
            "name": tier["name"],
            "architecture": "x86_64",
            "cpu": cpu,
            "validation": validation,
            "required": required,
            "supported": False,
            "exit_code": 1,
            "status": "fail",
            "error": "cpu model not listed by qemu-system-x86_64 -cpu help",
        }

    if validation == "qemu-smoke":
        env.setdefault("XAIOS_QEMU_SMOKE_TIMEOUT", "90")
        proc = run(["python3", "./scripts/qemu-x86_64-smoke.py"], env, 140)
    else:
        proc = run(["./scripts/run-qemu-x86_64.sh", "--dry-run"], env, 20)
    return {
        "name": tier["name"],
        "architecture": "x86_64",
        "cpu": cpu,
        "validation": validation,
        "required": required,
        "supported": supported_by_qemu,
        "exit_code": proc.returncode,
        "status": "pass" if supported_by_qemu and proc.returncode == 0 else "fail",
    }


def main() -> int:
    os.makedirs("build", exist_ok=True)
    architecture_filter = os.environ.get("XAIOS_QEMU_CPU_MATRIX_ARCH", "all")
    if architecture_filter not in {"all", "aarch64", "x86_64"}:
        print("qemu-cpu-matrix: XAIOS_QEMU_CPU_MATRIX_ARCH must be "
              "all, aarch64, or x86_64")
        return 2
    run_aarch64 = architecture_filter in {"all", "aarch64"}
    run_x86_64 = architecture_filter in {"all", "x86_64"}

    with open(CONTRACT_PATH, "r", encoding="utf-8") as handle:
        contract = json.load(handle)

    qemu_aarch64 = find_qemu("qemu-system-aarch64") if run_aarch64 else None
    qemu_x86_64 = find_qemu("qemu-system-x86_64") if run_x86_64 else None
    failures: List[str] = []
    if run_aarch64 and qemu_aarch64 is None:
        failures.append("qemu-system-aarch64 not found")
    if run_x86_64 and qemu_x86_64 is None:
        failures.append("qemu-system-x86_64 not found")

    arm_supported = cpu_help_set(qemu_aarch64) if qemu_aarch64 else set()
    x86_supported = cpu_help_set(qemu_x86_64) if qemu_x86_64 else set()
    base_env = os.environ.copy()
    base_env.setdefault("XAIOS_QEMU_SMOKE_TIMEOUT", "90")

    tiers: List[Dict[str, Any]] = []
    if qemu_aarch64:
        arm_tiers = sorted(
            contract["cpu_matrix"]["arm64_boot_tiers"],
            key=lambda tier: not tier.get("required", True),
        )
        for tier in arm_tiers:
            result = run_arm_boot_tier(tier, arm_supported, base_env)
            tiers.append(result)
            if result["status"] != "pass" and result["required"]:
                failures.append(f"arm64 tier failed: {tier['name']}")
    if qemu_x86_64:
        if any(tier.get("validation") == "qemu-smoke"
               for tier in contract["cpu_matrix"]["x86_64_command_tiers"]):
            image_proc = run(["make", "image-x86_64"], base_env, 120)
            if image_proc.returncode != 0:
                failures.append("x86_64 image build failed for CPU matrix")
        for tier in contract["cpu_matrix"]["x86_64_command_tiers"]:
            result = run_x86_tier(tier, x86_supported, base_env)
            tiers.append(result)
            if result["status"] != "pass" and result["required"]:
                failures.append(f"x86_64 tier failed: {tier['name']}")

    report = {
        "schema": SCHEMA,
        "created_unix": int(time.time()),
        "status": "fail" if failures else "pass",
        "contract": CONTRACT_PATH,
        "architecture_filter": architecture_filter,
        "qemu": {
            "aarch64": qemu_aarch64,
            "x86_64": qemu_x86_64,
        },
        "tiers": tiers,
        "optional_failures": [
            tier["name"] for tier in tiers
            if not tier["required"] and tier["status"] == "fail"
        ],
        "optional_skipped": [
            tier["name"] for tier in tiers
            if not tier["required"] and tier["status"] == "skipped"
        ],
        "failures": failures,
    }

    with open(REPORT_PATH, "w", encoding="utf-8") as handle:
        json.dump(report, handle, sort_keys=True, indent=2)
    print(f"qemu-cpu-matrix: report written to {REPORT_PATH}")

    if failures:
        print("qemu-cpu-matrix: failed")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("qemu-cpu-matrix: all CPU tiers passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
