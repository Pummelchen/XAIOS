#!/usr/bin/env python3
"""Prove QEMU SMMUv3 translation, revocation, and stream teardown."""

import json
import os
import select
import signal
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
SCHEMA = "xaios.qemu.smmuv3.v1"
MARKERS = [
    "SMMU: enabled idr0=",
    "SMMU: translated DMA result=0x0",
    "SMMU: event type=0x10",
    "SMMU: translated DMA self-test passed",
    "authorized=1 forbidden=1 stale_mapping=blocked faults=1",
]
PANIC_MARKERS = ["CYAN SCREEN OF DEATH", "System halted. Manual reset required"]


def stop_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            process.kill()
        process.wait(timeout=3)


def qemu_version() -> str:
    qemu = os.environ.get(
        "XAIOS_QEMU_SMMU",
        os.environ.get("XAIOS_QEMU", "qemu-system-aarch64"),
    )
    try:
        result = subprocess.run(
            [qemu, "--version"], capture_output=True, text=True, timeout=5,
            check=False,
        )
        return result.stdout.splitlines()[0] if result.stdout else "unknown"
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"


def main() -> int:
    BUILD.mkdir(parents=True, exist_ok=True)
    log_path = BUILD / "qemu-smmu-gate.log"
    report_path = BUILD / "qemu-smmu-gate-report.json"
    persistent_image = BUILD / "xaios-smmu-persistent.img"
    persistent_image.unlink(missing_ok=True)

    env = os.environ.copy()
    smmu_qemu = env.get("XAIOS_QEMU_SMMU")
    if smmu_qemu:
        env["XAIOS_QEMU"] = smmu_qemu
    env.update(
        {
            "XAIOS_QEMU_ACCEL": "tcg",
            "XAIOS_QEMU_IOMMU": "smmuv3",
            "XAIOS_QEMU_HOSTFWD_PORT": "none",
            "XAIOS_PERSISTENT_IMAGE": str(persistent_image),
        }
    )
    timeout = int(env.get("XAIOS_QEMU_SMMU_TIMEOUT", "90"))
    started = time.monotonic()
    process = subprocess.Popen(
        ["./scripts/run-qemu-aarch64.sh"],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    output = bytearray()
    passed = False
    deadline = started + timeout
    try:
        if process.stdout is None:
            raise RuntimeError("QEMU stdout was not captured")
        descriptor = process.stdout.fileno()
        while time.monotonic() < deadline:
            ready, _, _ = select.select([descriptor], [], [], 0.2)
            if ready:
                chunk = os.read(descriptor, 8192)
                if not chunk:
                    break
                output.extend(chunk)
                try:
                    os.write(sys.stdout.fileno(), chunk)
                except (BrokenPipeError, OSError):
                    pass
                text = output.decode("utf-8", errors="replace")
                if all(marker in text for marker in MARKERS):
                    passed = not any(marker in text for marker in PANIC_MARKERS)
                    break
            elif process.poll() is not None:
                break
    finally:
        stop_process_group(process)
        text = output.decode("utf-8", errors="replace")
        log_path.write_text(text, encoding="utf-8")
        persistent_image.unlink(missing_ok=True)

    missing = [marker for marker in MARKERS if marker not in text]
    panics = [marker for marker in PANIC_MARKERS if marker in text]
    failures = [f"missing marker: {marker}" for marker in missing]
    failures.extend(f"panic marker present: {marker}" for marker in panics)
    if not passed and not failures:
        failures.append(f"QEMU exited before SMMU evidence, code={process.returncode}")
    report = {
        "schema": SCHEMA,
        "status": "pass" if passed and not failures else "fail",
        "created_unix": int(time.time()),
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "accelerator": "tcg",
        "iommu": "smmuv3",
        "qemu_version": qemu_version(),
        "qemu_correctness_only": True,
        "claims": [
            "authorized DMA reached the mapped page",
            "unmapped DMA raised a translation fault",
            "aborted stream teardown rejected stale DMA",
        ],
        "not_claimed": ["physical IOMMU performance", "platform hardware validation"],
        "markers": MARKERS,
        "log": "build/qemu-smmu-gate.log",
        "failures": failures,
    }
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"qemu-smmu-gate: report written to {report_path.relative_to(ROOT)}")
    if failures:
        for failure in failures:
            print(f"qemu-smmu-gate: {failure}")
        return 1
    print("qemu-smmu-gate: translated DMA isolation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
