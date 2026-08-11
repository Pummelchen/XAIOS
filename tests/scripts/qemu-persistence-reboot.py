#!/usr/bin/env python3
import os
import select
import subprocess
import sys
import time
from typing import List


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


def run_boot(label: str, targets: List[str], timeout_seconds: int) -> int:
    env = os.environ.copy()
    env["XAIOS_QEMU_HOSTFWD_PORT"] = "none"
    proc = subprocess.Popen(
        ["./scripts/run-qemu-aarch64.sh"],
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


def main() -> int:
    timeout = int(os.environ.get("XAIOS_QEMU_PERSISTENCE_TIMEOUT", "60"))
    first = run_boot("first boot", FIRST_BOOT_TARGETS, timeout)
    if first != 0:
        return first

    second = run_boot("second boot", SECOND_BOOT_TARGETS, timeout)
    if second != 0:
        return second

    print("qemu-persistence-reboot: mutable VirtIO state survived QEMU reboot")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
