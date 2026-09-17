#!/usr/bin/env python3
"""Run every CPU model the QEMU contract names, one boot per tier.

The half of the matrix that talks to an emulator -- discovery, the boot probes
and the per-architecture tier runners -- lives in `qemu_cpu_matrix_lib.py`
beside this file; this gate sequences those tiers and writes the report. The
command line, the output and the exit codes are unchanged by the split.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent))

# The moved names are imported, not redefined, so the gate's module surface is
# what it was before the split.
from qemu_cpu_matrix_lib import (  # noqa: E402
    BOOT_PROBE_MARKERS,
    RISCV_BOOT_MARKERS,
    RISCV_REFUSAL,
    cpu_help_set,
    find_qemu,
    run,
    run_arm_boot_tier,
    run_riscv_tier,
    run_until_markers,
    run_until_markers_in_file,
    run_x86_tier,
)


CONTRACT_PATH = "contracts/qemu-rc-v1.json"
REPORT_PATH = os.environ.get(
    "XAIOS_QEMU_CPU_MATRIX_REPORT", "build/qemu-cpu-matrix-report.json"
)
SCHEMA = "xaios.qemu.cpu_matrix.v1"


def main() -> int:
    os.makedirs("build", exist_ok=True)
    # --arch was accepted and ignored.
    #
    # The RISC-V CI job invokes this as `--arch riscv64` and installs only a
    # RISC-V emulator. The filter was read from the environment alone, so the
    # argument did nothing, all three architectures ran, and the job failed on
    # "qemu-system-aarch64 not found" -- a complaint about an emulator it was
    # never asked to use. An argument that is silently discarded is worse than
    # one that is rejected.
    architecture_filter = os.environ.get("XAIOS_QEMU_CPU_MATRIX_ARCH", "all")
    argv = sys.argv[1:]
    while argv:
        option = argv.pop(0)
        if option == "--arch":
            if not argv:
                print("qemu-cpu-matrix: --arch needs a value")
                return 2
            architecture_filter = argv.pop(0)
        elif option.startswith("--arch="):
            architecture_filter = option.split("=", 1)[1]
        else:
            print(f"qemu-cpu-matrix: unknown argument {option}")
            return 2
    if architecture_filter not in {"all", "aarch64", "x86_64", "riscv64"}:
        print("qemu-cpu-matrix: XAIOS_QEMU_CPU_MATRIX_ARCH must be "
              "all, aarch64, x86_64, or riscv64")
        return 2
    run_aarch64 = architecture_filter in {"all", "aarch64"}
    run_x86_64 = architecture_filter in {"all", "x86_64"}
    run_riscv64 = architecture_filter in {"all", "riscv64"}

    with open(CONTRACT_PATH, "r", encoding="utf-8") as handle:
        contract = json.load(handle)

    qemu_aarch64 = find_qemu("qemu-system-aarch64") if run_aarch64 else None
    qemu_x86_64 = find_qemu("qemu-system-x86_64") if run_x86_64 else None
    qemu_riscv64 = find_qemu("qemu-system-riscv64") if run_riscv64 else None
    failures: List[str] = []
    if run_aarch64 and qemu_aarch64 is None:
        failures.append("qemu-system-aarch64 not found")
    if run_x86_64 and qemu_x86_64 is None:
        failures.append("qemu-system-x86_64 not found")
    if run_riscv64 and qemu_riscv64 is None:
        failures.append("qemu-system-riscv64 not found")

    arm_supported = cpu_help_set(qemu_aarch64) if qemu_aarch64 else set()
    x86_supported = cpu_help_set(qemu_x86_64) if qemu_x86_64 else set()
    riscv_supported = cpu_help_set(qemu_riscv64) if qemu_riscv64 else set()
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
            image_proc = run(["make", "image-x86_64-qemu-test"], base_env,
                             120)
            if image_proc.returncode != 0:
                failures.append("x86_64 image build failed for CPU matrix")
        for tier in contract["cpu_matrix"]["x86_64_command_tiers"]:
            result = run_x86_tier(tier, x86_supported, base_env)
            tiers.append(result)
            if result["status"] != "pass" and result["required"]:
                failures.append(f"x86_64 tier failed: {tier['name']}")

    if qemu_riscv64:
        # Built once for the whole architecture. Every tier boots the same
        # kernel on a different hart, so rebuilding per tier would be
        # measuring the compiler twelve times.
        #
        # The image is built here too, and with the same switch. This used to
        # build only the kernel and boot whatever initial filesystem happened
        # to be in build/ -- so running after anything that leaves a *release*
        # image there, which `make qemu-riscv64-release-gate` does, paired a
        # boot-test kernel with a release filesystem. The markers below are
        # kernel self-tests that the release configuration's boot UI
        # suppresses, so the matrix would have reported every tier as a
        # machine that produced no output. Self-contained beats
        # order-dependent.
        riscv_env = {**base_env, "XAIOS_BOOT_TEST_APPS": "1"}
        build = run(["./scripts/build-riscv64.sh"], riscv_env, 600)
        if build.returncode == 0:
            build = run(["./scripts/build-riscv64-image.sh"], riscv_env, 600)
        if build.returncode != 0:
            failures.append("riscv64 kernel build failed for CPU matrix")
        else:
            for tier in contract["cpu_matrix"]["riscv64_boot_tiers"]:
                result = run_riscv_tier(tier, riscv_supported, base_env)
                tiers.append(result)
                if result["status"] != "pass" and result["required"]:
                    failures.append(f"riscv64 tier failed: {tier['name']}")

    report = {
        "schema": SCHEMA,
        "created_unix": int(time.time()),
        "status": "fail" if failures else "pass",
        "contract": CONTRACT_PATH,
        "architecture_filter": architecture_filter,
        "qemu": {
            "aarch64": qemu_aarch64,
            "x86_64": qemu_x86_64,
            "riscv64": qemu_riscv64,
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
