#!/usr/bin/env python3
"""Execute the ARM SVE2 arithmetic canary under QEMU TCG."""

from __future__ import annotations

import os
import select
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MARKER = b"SVE2: QEMU arithmetic canary passed"


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="xaios-sve2-") as temporary:
        temp = Path(temporary)
        image_names = (
            "xaios-aarch64.img",
            "xaios-virtio-test.img",
            "xaios-persistent.img",
            "xaios-model-volume.img",
            "xaios-system.img",
        )
        for name in image_names:
            source = ROOT / "build" / name
            if not source.exists():
                raise SystemExit(f"missing image: {source}")
            shutil.copyfile(source, temp / name)
        environment = os.environ.copy()
        environment.update(
            {
                "XAIOS_QEMU_ACCEL": "tcg",
                "XAIOS_QEMU_CPU": "max,sve=on",
                "XAIOS_AARCH64_IMAGE": str(temp / "xaios-aarch64.img"),
                "XAIOS_TEST_BLOCK_IMAGE": str(temp / "xaios-virtio-test.img"),
                "XAIOS_PERSISTENT_IMAGE": str(temp / "xaios-persistent.img"),
                "XAIOS_MODEL_VOLUME_IMAGE": str(temp / "xaios-model-volume.img"),
                "XAIOS_SYSTEM_VOLUME_IMAGE": str(temp / "xaios-system.img"),
                "XAIOS_QEMU_HOSTFWD_PORT": "none",
                "XAIOS_QEMU_RNG": "none",
            }
        )
        process = subprocess.Popen(
            [str(ROOT / "scripts" / "run-qemu-aarch64.sh")],
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        assert process.stdout is not None
        output = bytearray()
        deadline = time.monotonic() + 180.0
        try:
            while time.monotonic() < deadline and len(output) < 4 * 1024 * 1024:
                ready, _, _ = select.select([process.stdout], [], [], 0.5)
                chunk = os.read(process.stdout.fileno(), 4096) if ready else b""
                if not chunk and process.poll() is not None:
                    break
                output.extend(chunk)
                if MARKER in output:
                    print(
                        "qemu-aarch64-sve2-gate: SVE2 arithmetic and runtime capability gate passed"
                    )
                    return 0
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
        diagnostic = bytes(output)[-8192:]
        raise SystemExit("SVE2 marker missing\n" + diagnostic.decode(errors="replace"))


if __name__ == "__main__":
    raise SystemExit(main())
