#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import time
from pathlib import Path


SCHEMA = "xaios.intel_desktop.hardware_gate.v1"
REPORT_PATH = Path("build/intel-desktop-gate-report.json")
REQUIRED_MARKERS = [
    "x86_64: SMP AP startup passed online=",
    "topology: initialized ",
    "virtio-blk: x86 completion canary passed mode=",
    "scheduler: SIMD/FP interrupt preservation passed",
    "kernel: /bin/service-manager returned to kernel exit_code=0",
    "sshd: Phase 2 runtime ready",
]


def run_smoke() -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.setdefault("XAIOS_QEMU_X86_ACCEL", "tcg")
    env.setdefault("XAIOS_QEMU_X86_CPU", "Skylake-Client")
    return subprocess.run(
        ["make", "qemu-x86_64-smoke"],
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
        timeout=int(env.get("XAIOS_INTEL_DESKTOP_GATE_TIMEOUT", "120")),
    )


def main() -> int:
    start = time.time()
    proc = run_smoke()
    output = proc.stdout or ""
    sys.stdout.write(output)
    missing = [marker for marker in REQUIRED_MARKERS if marker not in output]
    assessment_complete = proc.returncode == 0 and not missing
    status = "blocked" if assessment_complete else "fail"
    report = {
        "schema": SCHEMA,
        "status": status,
        "elapsed_seconds": round(time.time() - start, 3),
        "qemu_smoke_exit_code": proc.returncode,
        "milestones": {
            "49_topology_and_interrupts": "pass" if all(
                marker in output for marker in REQUIRED_MARKERS[:4]
            ) else "fail",
            "50_os_contract_port": "pass" if all(
                marker in output for marker in REQUIRED_MARKERS[4:]
            ) else "fail",
            "51_physical_hardware_gate": "blocked",
        },
        "gates": {
            "assessment_complete": assessment_complete,
            "qemu_service_parity": assessment_complete,
            "common_kernel_runtime_linked": REQUIRED_MARKERS[4] in output,
            "interrupt_delivery": REQUIRED_MARKERS[2] in output,
            "physical_hardware_required": True,
            "tuned_linux_bsd_baseline_required": True,
            "performance_claims_allowed": False,
            "release_candidate_ready": False,
        },
        "missing_markers": missing,
        "notes": (
            "Intel Desktop assessment validates QEMU common-service parity. "
            "Physical firmware, device, reliability, security and performance "
            "evidence remains missing."
        ),
    }

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"intel-desktop-gate: report written to {REPORT_PATH}")
    print(f"intel-desktop-gate: status={status}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
