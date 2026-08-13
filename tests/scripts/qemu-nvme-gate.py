#!/usr/bin/env python3
"""Validate asynchronous NVMe behavior on both QEMU architectures."""

from __future__ import annotations

import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time
import re


BUILD = Path("build")
REPORT = BUILD / "qemu-nvme-gate-report.json"
MARKERS = [
    "nvme: controller ready version=",
    "nvme: identify controller serial='XAIOSNVME",
    "nvme: async self-test passed namespaces=1",
    "queue_depth=16 io_queues=4 prp_pages=4 transfer_bytes=16384 rounds=8",
    "affinity=cpu msix=4 write_read_flush=1",
]

RESULT_PATTERN = re.compile(
    r"rounds=(?P<rounds>\d+) async=(?P<async_ops>\d+) "
    r"cancelled=(?P<cancelled>\d+) sgl=(?P<sgl>\d+) "
    r"direct=(?P<direct>\d+) malformed=(?P<malformed>\d+) "
    r"affinity=cpu msix=(?P<msix>\d+)"
)


def stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def run_architecture(architecture: str) -> dict[str, object]:
    image = BUILD / f"xaios-nvme-gate-{architecture}.img"
    persistent = BUILD / f"xaios-nvme-gate-{architecture}-persistent.img"
    log_path = BUILD / f"qemu-nvme-gate-{architecture}.log"
    subprocess.run(["truncate", "-s", "64M", str(image)], check=True)
    persistent.unlink(missing_ok=True)

    environment = os.environ.copy()
    environment.update(
        {
            "XAIOS_PERSISTENT_IMAGE": str(persistent),
            "XAIOS_QEMU_HOSTFWD_PORT": "none",
            "XAIOS_QEMU_ACCEL": "tcg",
            "XAIOS_QEMU_SMP": "4",
        }
    )
    if architecture == "aarch64":
        environment["XAIOS_QEMU_MSI_CONTROLLER"] = "gicv2m"
        environment["XAIOS_NVME_IMAGE"] = str(image)
        runner = "./scripts/run-qemu-aarch64.sh"
    else:
        environment["XAIOS_QEMU_X86_NVME_IMAGE"] = str(image)
        runner = "./scripts/run-qemu-x86_64.sh"
    required_markers = list(MARKERS)
    if architecture == "x86_64":
        required_markers.append("nvme: MSI-X interrupt self-test passed queues=4")

    with log_path.open("wb") as log:
        process = subprocess.Popen(
            [runner],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=environment,
        )
        chunks: list[str] = []
        deadline = time.time() + int(
            environment.get("XAIOS_QEMU_NVME_TIMEOUT", "120")
        )
        try:
            assert process.stdout is not None
            descriptor = process.stdout.fileno()
            while time.time() < deadline:
                ready, _, _ = select.select([descriptor], [], [], 0.2)
                if ready:
                    data = os.read(descriptor, 4096)
                    if not data:
                        break
                    text = data.decode("utf-8", errors="replace")
                    log.write(data)
                    log.flush()
                    sys.stdout.write(text)
                    sys.stdout.flush()
                    chunks.append(text)
                    output = "".join(chunks)
                    if all(marker in output for marker in required_markers):
                        break
                elif process.poll() is not None:
                    break
        finally:
            stop_process(process)

    output = "".join(chunks)
    missing = [marker for marker in required_markers if marker not in output]
    forbidden = [
        marker
        for marker in ("CYAN SCREEN OF DEATH", "nvme: self-test failed")
        if marker in output
    ]
    match = RESULT_PATTERN.search(output)
    metrics = (
        {key: int(value) for key, value in match.groupdict().items()}
        if match is not None
        else {}
    )
    with image.open("rb") as stream:
        first_transfer = stream.read(16384)
    expected = bytes((index ^ 0xA5) & 0xFF for index in range(16384))
    host_verified = first_transfer == expected
    behavior_verified = bool(
        metrics
        and metrics["rounds"] >= 8
        and metrics["async_ops"] >= 38
        and metrics["cancelled"] >= 1
        and metrics["sgl"] >= 1
        and metrics["direct"] == metrics["async_ops"]
        and metrics["malformed"] >= 4
        and metrics["msix"] == 4
    )
    passed = not missing and not forbidden and host_verified and behavior_verified
    return {
        "status": "pass" if passed else "fail",
        "controller": "QEMU NVMe",
        "queue_depth": 16,
        "io_queues": 4,
        "prp_pages": 4,
        "transfer_bytes": 16384,
        "guest_write_read_flush": not missing and not forbidden,
        "host_backing_image_verified": host_verified,
        "async_behavior_verified": behavior_verified,
        "msix_delivery_verified": architecture == "x86_64" and not any(
            "MSI-X interrupt self-test" in marker for marker in missing
        ),
        "metrics": metrics,
        "missing_markers": missing,
        "forbidden_markers": forbidden,
        "guest_log": str(log_path),
    }


def main() -> int:
    BUILD.mkdir(parents=True, exist_ok=True)
    results: dict[str, dict[str, object]] = {}
    for architecture in ("aarch64", "x86_64"):
        print(f"qemu-nvme-gate: testing {architecture}", flush=True)
        results[architecture] = run_architecture(architecture)
    passed = all(result["status"] == "pass" for result in results.values())
    REPORT.write_text(
        json.dumps(
            {
                "schema": "xaios.qemu.nvme.v3",
                "status": "pass" if passed else "fail",
                "qemu_correctness_only": True,
                "architectures": results,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    if not passed:
        print(f"qemu-nvme-gate: failed report={REPORT}", file=sys.stderr)
        return 1
    print(
        "qemu-nvme-gate: AArch64/x86_64 async four-queue PRP/SGL "
        f"direct I/O, cancellation, malformed completion, and stress passed report={REPORT}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
