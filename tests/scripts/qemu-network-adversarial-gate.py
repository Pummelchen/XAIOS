#!/usr/bin/env python3
"""Fail-closed N-F3Q fuzz, fault, exhaustion, and three-architecture soak."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import time


ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"


def soak_boots() -> int:
    raw = os.environ.get("XAIOS_NF3Q_BOOTS", "20")
    try:
        count = int(raw)
    except ValueError as exc:
        raise ValueError("XAIOS_NF3Q_BOOTS must be an integer") from exc
    if count < 1 or count > 1000:
        raise ValueError("XAIOS_NF3Q_BOOTS must be between 1 and 1000")
    return count


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
    try:
        boots = soak_boots()
    except ValueError as exc:
        print(f"N-F3Q: {exc}")
        return 2
    soak_timeout = boots * 180 + 60
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
            soak_timeout, {
                "XAIOS_QEMU_SOAK_BOOTS": str(boots),
                "XAIOS_QEMU_SOAK_SMOKE_TIMEOUT": "120",
            },
        ))
    checks.append(execute("x86_64_build", ["make", "image-x86_64-qemu-test"], 300))
    if checks[-1]["status"] == "pass":
        checks.append(execute(
            "x86_64_repeated_soak",
            ["python3", "tests/scripts/qemu-x86_64-repeat-boot.py"],
            soak_timeout,
            {"XAIOS_QEMU_X86_REPEAT_COUNT": str(boots)},
        ))
    # The third machine, on the same terms. It was absent from this list for
    # as long as it had no soak gate of its own, which made "dual-arch" the
    # accurate name for a gate that is supposed to cover what this project
    # ships -- and this project ships three.
    checks.append(execute("riscv64_build", ["make", "riscv64"], 300))
    if checks[-1]["status"] == "pass":
        checks.append(execute(
            "riscv64_repeated_soak",
            ["python3", "tests/scripts/qemu-soak-gate.py", "--arch", "riscv64"],
            soak_timeout, {
                "XAIOS_QEMU_SOAK_BOOTS": str(boots),
                "XAIOS_QEMU_SOAK_SMOKE_TIMEOUT": "120",
            },
        ))
    status = "pass" if all(c["status"] == "pass" for c in checks) else "fail"
    report = {
        "schema": "xaios.qemu.network_adversarial.v1",
        "status": status,
        "scope": "QEMU correctness only; no physical-network performance claim",
        "architectures": ["aarch64", "x86_64", "riscv64"],
        "soak_boots_per_architecture": boots,
        "checks": checks,
    }
    path = BUILD / "qemu-network-adversarial.json"
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"N-F3Q: {status.upper()} report={path}")
    return 0 if status == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
