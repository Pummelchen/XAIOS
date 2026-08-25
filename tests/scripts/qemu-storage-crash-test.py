#!/usr/bin/env python3
"""Kill QEMU at system-metadata write points and prove reboot recovery."""

from __future__ import annotations

import os
import select
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
POINTS = ("system-backup-flushed", "system-primary-written")
sys.path.insert(0, str(ROOT))

from tools.xaios_system_volume import NO_SLOT, read_best_metadata


def run(command: list[str], env: dict[str, str]) -> None:
    subprocess.run(command, cwd=ROOT, env=env, check=True)


def stop_process(process: subprocess.Popen[bytes], hard: bool) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGKILL if hard else signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def boot_until(
    env: dict[str, str], targets: tuple[str, ...], timeout: int, hard: bool
) -> str:
    process = subprocess.Popen(
        ["./platform/qemu/run-qemu-aarch64.sh"],
        cwd=ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    output = bytearray()
    deadline = time.monotonic() + timeout
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
                text = output.decode("utf-8", errors="replace")
                if all(target in text for target in targets):
                    return text
            elif process.poll() is not None:
                break
    finally:
        stop_process(process, hard)
    text = output.decode("utf-8", errors="replace")
    missing = [target for target in targets if target not in text]
    raise RuntimeError(
        f"QEMU did not reach {missing}; serial tail:\n{text[-4000:]}"
    )


def build_crash_image(point: str, system_image: Path) -> None:
    shutil.copyfile(BUILD / "xaios-system.img", system_image)
    env = os.environ.copy()
    env["XAIOS_BOOT_TEST_APPS"] = "1"
    env["XAIOS_STORAGE_CRASH_POINT"] = point
    env["XAIOS_SYSTEM_VOLUME_IMAGE"] = str(system_image)
    run(["./scripts/build-image.sh"], env)
    create_env = os.environ.copy()
    create_env["PYTHONPATH"] = str(ROOT)
    run(
        [
            sys.executable,
            "tools/xaios_system_volume.py",
            "create",
            str(system_image),
            "build/kernel/kernel.elf",
            "--active",
            "0",
            "--pending",
            "1",
        ],
        create_env,
    )


def validate_committed_metadata(system_image: Path) -> None:
    with system_image.open("rb") as source:
        info, selected = read_best_metadata(source)
    if (
        info["active"] != 1
        or info["pending"] != NO_SLOT
        or info["pending_attempted"] != 0
        or int(info["sequence"]) < 3
    ):
        raise RuntimeError(
            f"metadata did not converge after crash: {info} selected={selected}"
        )


def main() -> int:
    # The injected commit point follows the deterministic diagnostic boot
    # workload. On TCG this may take materially longer than a normal service
    # boot, so retain a bounded but realistic per-boot deadline.
    timeout = int(os.environ.get("XAIOS_QEMU_STORAGE_CRASH_TIMEOUT", "240"))
    work = BUILD / "storage-crash"
    work.mkdir(parents=True, exist_ok=True)
    try:
        for point in POINTS:
            print(f"qemu-storage-crash: preparing point={point}", flush=True)
            system_image = work / f"{point}.img"
            persistent_image = work / f"{point}-persistent.img"
            persistent_image.unlink(missing_ok=True)
            build_crash_image(point, system_image)
            env = os.environ.copy()
            env.update(
                {
                    "XAIOS_QEMU_ACCEL": "tcg",
                    "XAIOS_QEMU_HOSTFWD_PORT": "none",
                    "XAIOS_SYSTEM_VOLUME_IMAGE": str(system_image),
                    "XAIOS_PERSISTENT_IMAGE": str(persistent_image),
                }
            )
            marker = f"storage-crash: reached point={point}"
            boot_until(env, (marker,), timeout, hard=True)
            validate_committed_metadata(system_image)
            print(f"qemu-storage-crash: power loss observed point={point}", flush=True)
            boot_until(
                env,
                (
                    "system-slot: attached active=1 pending=4294967295",
                    "system-slot: self-test passed",
                ),
                timeout,
                hard=False,
            )
            print(f"qemu-storage-crash: recovered point={point}", flush=True)
    finally:
        restore_env = os.environ.copy()
        restore_env["XAIOS_BOOT_TEST_APPS"] = "1"
        restore_env.pop("XAIOS_STORAGE_CRASH_POINT", None)
        restore_env.pop("XAIOS_SYSTEM_VOLUME_IMAGE", None)
        run(["./scripts/build-image.sh"], restore_env)
    print("qemu-storage-crash: all metadata kill points recovered")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
