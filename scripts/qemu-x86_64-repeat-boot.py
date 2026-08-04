#!/usr/bin/env python3
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List


ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build"
LOG_DIR = BUILD / "qemu-x86_64-repeat"
REPORT_PATH = BUILD / "qemu-x86_64-repeat-boot-report.json"
SCHEMA = "xaios.qemu.x86_64_repeat_boot.v1"


def repeat_count() -> int:
    raw = os.environ.get("XAIOS_QEMU_X86_REPEAT_COUNT", "20")
    try:
        count = int(raw)
    except ValueError as exc:
        raise ValueError("repeat count must be an integer") from exc
    if count < 1 or count > 1000:
        raise ValueError("repeat count must be between 1 and 1000")
    return count


def run_boot(index: int) -> Dict[str, Any]:
    env = os.environ.copy()
    env.setdefault("XAIOS_QEMU_X86_ACCEL", "tcg")
    env.setdefault("XAIOS_QEMU_X86_CPU", "max")
    env.setdefault("XAIOS_QEMU_X86_SMP", "4")
    env.setdefault("XAIOS_QEMU_X86_SMOKE_TIMEOUT", "120")
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
            timeout=150,
        )
        output = proc.stdout
        exit_code = proc.returncode
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        exit_code = None
        timed_out = True
    log_path = LOG_DIR / f"boot-{index:03d}.log"
    log_path.write_text(output, encoding="utf-8")
    passed = exit_code == 0 and not timed_out
    print(f"qemu-x86_64-repeat-boot: boot {index:03d} "
          f"{'passed' if passed else 'failed'}", flush=True)
    return {
        "boot": index,
        "status": "pass" if passed else "fail",
        "exit_code": exit_code,
        "timed_out": timed_out,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "log": str(log_path.relative_to(ROOT)),
    }


def main() -> int:
    try:
        count = repeat_count()
    except ValueError as exc:
        print(f"qemu-x86_64-repeat-boot: {exc}")
        return 2
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    results: List[Dict[str, Any]] = [run_boot(index)
                                    for index in range(1, count + 1)]
    failures = [result["boot"] for result in results
                if result["status"] != "pass"]
    report = {
        "schema": SCHEMA,
        "created_unix": int(time.time()),
        "status": "fail" if failures else "pass",
        "benchmark_type": "qemu-correctness",
        "performance_claims_allowed": False,
        "attempted": count,
        "passed": count - len(failures),
        "failed": len(failures),
        "failed_boots": failures,
        "boots": results,
    }
    REPORT_PATH.write_text(
        json.dumps(report, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"qemu-x86_64-repeat-boot: report written to "
          f"{REPORT_PATH.relative_to(ROOT)}")
    if failures:
        return 1
    print(f"qemu-x86_64-repeat-boot: all {count} boots passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
