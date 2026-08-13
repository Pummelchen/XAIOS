#!/usr/bin/env python3
"""Fail-closed N-F3Q fuzz, fault, exhaustion, and dual-arch soak gate."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import time


ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"


def execute(name: str, command: list[str], timeout: int,
            env: dict[str, str] | None = None) -> dict[str, object]:
    started = time.monotonic()
    merged = os.environ.copy()
    if env:
        merged.update(env)
    print("+", " ".join(command), flush=True)
    result = subprocess.run(command, cwd=ROOT, env=merged, text=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=timeout,
                            check=False)
    print(result.stdout, end="")
    return {
        "name": name,
        "status": "pass" if result.returncode == 0 else "fail",
        "exit_code": result.returncode,
        "duration_seconds": round(time.monotonic() - started, 3),
    }


def main() -> int:
    BUILD.mkdir(parents=True, exist_ok=True)
    checks = [
        execute("coverage_guided_parser_fuzz",
                ["make", "parser-fuzz"], 600),
        execute("loss_reorder_corruption",
                ["make", "qemu-outbound-fragmentation-gate"], 600),
        execute("resource_exhaustion_and_recovery",
                ["make", "qemu-parallel-network-load"], 1800),
        execute("arm64_soak", ["make", "image-qemu-test"], 300),
    ]
    if checks[-1]["status"] == "pass":
        checks.append(execute(
            "arm64_repeated_soak", ["python3", "tests/scripts/qemu-soak-gate.py"],
            1200, {"XAIOS_QEMU_SOAK_BOOTS": os.environ.get("XAIOS_NF3Q_BOOTS", "3")},
        ))
    checks.append(execute("x86_64_build", ["make", "image-x86_64-qemu-test"], 300))
    if checks[-1]["status"] == "pass":
        checks.append(execute(
            "x86_64_repeated_soak",
            ["python3", "tests/scripts/qemu-x86_64-repeat-boot.py"], 1200,
            {"XAIOS_QEMU_REPEAT_BOOTS": os.environ.get("XAIOS_NF3Q_BOOTS", "3")},
        ))
    status = "pass" if all(c["status"] == "pass" for c in checks) else "fail"
    report = {
        "schema": "xaios.qemu.network_adversarial.v1",
        "status": status,
        "scope": "QEMU correctness only; no physical-network performance claim",
        "checks": checks,
    }
    path = BUILD / "qemu-network-adversarial.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"N-F3Q: {status.upper()} report={path}")
    return 0 if status == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
