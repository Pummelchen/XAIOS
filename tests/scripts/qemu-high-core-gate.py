#!/usr/bin/env python3
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
SCHEMA = "xaios.qemu.high_core_capacity.v1"
DEFAULT_CPU_COUNT = 130


def stop_process_group(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        proc.wait(timeout=3)


def main() -> int:
    cpu_count = int(os.environ.get("XAIOS_HIGH_CORE_COUNT", DEFAULT_CPU_COUNT))
    if cpu_count <= 128:
        print("qemu-high-core-gate: XAIOS_HIGH_CORE_COUNT must exceed 128")
        return 2

    timeout = int(os.environ.get("XAIOS_HIGH_CORE_TIMEOUT", "300"))
    markers = [
        f"smp: online cpus={cpu_count}/{cpu_count} dynamic_capacity={cpu_count}",
        f"smp: per-core registry self-test passed online={cpu_count}",
        f"cpu_words={(cpu_count + 63) // 64}",
        "NUMA: dynamic metadata bytes=",
        "no fixed RAM or CPU bitmap ceiling",
        "NUMA: self-test passed",
    ]
    panic_markers = ["CYAN SCREEN OF DEATH", "System halted. Manual reset required"]
    log_path = BUILD / "qemu-high-core-gate.log"
    report_path = BUILD / "qemu-high-core-gate-report.json"
    persistent_image = BUILD / "xaios-high-core-persistent.img"
    persistent_image.unlink(missing_ok=True)
    BUILD.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["XAIOS_QEMU_ACCEL"] = "tcg"
    env["XAIOS_QEMU_SMP"] = str(cpu_count)
    env["XAIOS_QEMU_HOSTFWD_PORT"] = "none"
    env["XAIOS_PERSISTENT_IMAGE"] = str(persistent_image)
    started = time.time()
    proc = subprocess.Popen(
        ["make", "qemu-aarch64"],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env=env,
        start_new_session=True,
    )
    chunks = []
    passed = False
    deadline = started + timeout
    try:
        assert proc.stdout is not None
        fd = proc.stdout.fileno()
        while time.time() < deadline:
            ready, _, _ = select.select([fd], [], [], 0.2)
            if ready:
                chunk = os.read(fd, 4096).decode("utf-8", errors="replace")
                if not chunk:
                    break
                sys.stdout.write(chunk)
                sys.stdout.flush()
                chunks.append(chunk)
                output = "".join(chunks)
                if (all(marker in output for marker in markers) and
                        not any(marker in output for marker in panic_markers)):
                    passed = True
                    break
            elif proc.poll() is not None:
                break
    finally:
        stop_process_group(proc)
        output = "".join(chunks)
        log_path.write_text(output, encoding="utf-8")
        persistent_image.unlink(missing_ok=True)

    missing = [marker for marker in markers if marker not in output]
    panics = [marker for marker in panic_markers if marker in output]
    failures = [f"missing marker: {marker}" for marker in missing]
    failures.extend(f"panic marker present: {marker}" for marker in panics)
    if not passed and not failures:
        failures.append(f"QEMU exited before capacity evidence, code={proc.returncode}")
    report = {
        "schema": SCHEMA,
        "status": "pass" if passed and not failures else "fail",
        "created_unix": int(time.time()),
        "elapsed_seconds": round(time.time() - started, 3),
        "cpu_count": cpu_count,
        "accelerator": "tcg",
        "qemu_correctness_only": True,
        "scope": [
            "dynamic SMP registry above 128 CPUs",
            "runtime-sized NUMA CPU bitmap above 128 CPUs",
        ],
        "not_claimed": [
            "physical scalability or performance",
            "complete late-boot workload execution at 130 emulated CPUs",
        ],
        "markers": markers,
        "log": "build/qemu-high-core-gate.log",
        "failures": failures,
    }
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    print(f"qemu-high-core-gate: report written to {report_path.relative_to(ROOT)}")
    if failures:
        for failure in failures:
            print(f"qemu-high-core-gate: {failure}")
        return 1
    print(f"qemu-high-core-gate: dynamic capacity passed cpus={cpu_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
