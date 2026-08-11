#!/usr/bin/env python3
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time


IMAGE = Path("build/xaios-nvme-gate.img")
PERSISTENT = Path("build/xaios-nvme-gate-persistent.img")
REPORT = Path("build/qemu-nvme-gate-report.json")
MARKERS = [
    "PCI: [0:",
    "class=0x1.8",
    "nvme: controller ready version=",
    "nvme: identify controller serial='XAIOSNVME",
    "nvme: admin/io self-test passed namespaces=1",
    "queue_depth=16 write_read_flush=1",
]


def stop_process(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=3)


def main() -> int:
    IMAGE.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["truncate", "-s", "64M", str(IMAGE)], check=True)
    PERSISTENT.unlink(missing_ok=True)

    env = os.environ.copy()
    env.update(
        {
            "XAIOS_NVME_IMAGE": str(IMAGE),
            "XAIOS_PERSISTENT_IMAGE": str(PERSISTENT),
            "XAIOS_QEMU_HOSTFWD_PORT": "none",
            "XAIOS_QEMU_ACCEL": "tcg",
        }
    )
    proc = subprocess.Popen(
        ["./scripts/run-qemu-aarch64.sh"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=env,
    )
    chunks: list[str] = []
    deadline = time.time() + int(env.get("XAIOS_QEMU_NVME_TIMEOUT", "60"))
    try:
        assert proc.stdout is not None
        fd = proc.stdout.fileno()
        while time.time() < deadline:
            ready, _, _ = select.select([fd], [], [], 0.2)
            if ready:
                data = os.read(fd, 4096)
                if not data:
                    break
                text = data.decode("utf-8", errors="replace")
                sys.stdout.write(text)
                sys.stdout.flush()
                chunks.append(text)
                output = "".join(chunks)
                if all(marker in output for marker in MARKERS):
                    break
            elif proc.poll() is not None:
                break
    finally:
        stop_process(proc)

    output = "".join(chunks)
    missing = [marker for marker in MARKERS if marker not in output]
    forbidden = [
        marker
        for marker in ("CYAN SCREEN OF DEATH", "nvme: self-test failed")
        if marker in output
    ]
    with IMAGE.open("rb") as stream:
        block = stream.read(512)
    expected = bytes((index ^ 0xA5) & 0xFF for index in range(512))
    host_verified = block == expected
    passed = not missing and not forbidden and host_verified
    report = {
        "schema_version": 1,
        "qemu_correctness_only": True,
        "controller": "QEMU NVMe",
        "queue_depth": 16,
        "guest_write_read_flush": not missing and not forbidden,
        "host_backing_image_verified": host_verified,
        "missing_markers": missing,
        "forbidden_markers": forbidden,
        "passed": passed,
    }
    REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if not passed:
        print(f"qemu-nvme-gate: failed report={REPORT}")
        return 1
    print(
        "qemu-nvme-gate: admin identify and queued write/read/flush passed; "
        f"host image verified report={REPORT}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
