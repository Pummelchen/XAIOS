#!/usr/bin/env python3
import os
import select
import subprocess
import sys
import time
from pathlib import Path
from typing import List
import shutil
import sys
from qemu_gate_lib import (arch_from_argv, qemu_boot_environment,
                           qemu_runner)


PERSISTENT_IMAGE = Path("build/qemu-persistence-reboot.img")

FIRST_BOOT_TARGETS = [
    "persistence: no existing disk state sector=3000",
    "persistence: disk write sector=3000 version=1 records=5",
    "persistence: disk loaded sector=3000 version=1 records=5",
    "persistence: disk reload/rollback self-test passed snapshots=5 rollbacks=5 rejects=2 disk_writes=1 disk_loads=1 checksum_errors=0",
    "\"persistence_boot_loads\":0",
    "\"persistence_checksum_errors\":0",
]

SECOND_BOOT_TARGETS = [
    "persistence: existing disk state loaded records=5",
    "persistence: disk write sector=3000 version=1 records=5",
    "persistence: disk loaded sector=3000 version=1 records=5",
    "persistence: disk reload/rollback self-test passed snapshots=5 rollbacks=5 rejects=2 disk_writes=1 disk_loads=1 checksum_errors=0",
    "\"persistence_boot_loads\":1",
    "\"persistence_checksum_errors\":0",
]


def run_boot(arch: str, label: str, targets: List[str],
             timeout_seconds: int) -> int:
    env = qemu_boot_environment(
        arch, os.environ.copy(),
        persistent=persistent_image(arch), state_dir=state_dir(arch),
        hostfwd_port="none", serial_to_stdout=True)
    proc = subprocess.Popen(
        [qemu_runner(arch)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env=env,
    )
    seen: List[str] = []
    deadline = time.time() + timeout_seconds
    try:
        if proc.stdout is None:
            print(f"qemu-persistence-reboot: {label}: missing stdout")
            return 1
        fd = proc.stdout.fileno()
        while time.time() < deadline:
            ready, _, _ = select.select([fd], [], [], 0.2)
            if ready:
                chunk = os.read(fd, 4096).decode("utf-8", errors="replace")
                if not chunk:
                    break
                sys.stdout.write(chunk)
                sys.stdout.flush()
                seen.append(chunk)
                text = "".join(seen)
                if all(target in text for target in targets):
                    print(f"\nqemu-persistence-reboot: {label} reached persistence markers")
                    return 0
            elif proc.poll() is not None:
                break
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)

    text = "".join(seen)
    missing = [target for target in targets if target not in text]
    print(f"\nqemu-persistence-reboot: {label} missing targets: {missing}")
    return 1


def persistent_image(arch: str) -> Path:
    return (PERSISTENT_IMAGE if arch == "aarch64"
            else Path(f"build/qemu-persistence-reboot-{arch}.img"))


def state_dir(arch: str) -> Path:
    """RISC-V keeps its disks in a directory rather than naming one image.

    Fresh each run, because the whole question here is whether what the first
    boot wrote is what the second boot finds, and a directory carrying the
    last run's answer would let a broken write pass.
    """
    path = Path(f"build/qemu-persistence-reboot-{arch}-state")
    return path


def main() -> int:
    arch = arch_from_argv(sys.argv[1:])
    base = int(os.environ.get("XAIOS_QEMU_PERSISTENCE_TIMEOUT", "60"))
    timeout = base * 6 if arch == "riscv64" else base
    image = persistent_image(arch)
    image.parent.mkdir(parents=True, exist_ok=True)
    image.unlink(missing_ok=True)
    shutil.rmtree(state_dir(arch), ignore_errors=True)
    state_dir(arch).mkdir(parents=True, exist_ok=True)
    try:
        first = run_boot(arch, "first boot", FIRST_BOOT_TARGETS, timeout)
        if first != 0:
            return first

        second = run_boot(arch, "second boot", SECOND_BOOT_TARGETS, timeout)
        if second != 0:
            return second

        print("qemu-persistence-reboot: mutable VirtIO state survived QEMU reboot")
        return 0
    finally:
        PERSISTENT_IMAGE.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
