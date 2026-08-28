#!/usr/bin/env python3
"""Boot a machine XAIOS has been installed onto, twice, from one disk.

Every other QEMU gate boots the test bench: the boot medium is one device and
each volume the kernel wants is another, pinned to a known window, because that
makes a gate deterministic. An installed machine has none of that. It has one
disk. Its firmware partition and its durable state are partitions of that disk,
and nothing tells the kernel where either one is -- it has to look.

That difference is not cosmetic. Making it work meant an ordinal-addressed
transport lookup, accepting transitional virtio PCI device IDs, and teaching
the MMU to map above 512 GiB, because QEMU's virt machine puts its 64-bit PCI
window there and firmware placed the disk's registers in it. None of those
paths are exercised by any other gate, so without this one they can break and
every gate still passes.

Two boots, not one. The first formats the state partition; the second has to
find what the first wrote. A single boot would pass just as well against a
system that silently reformatted its disk every time.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
REPORT = BUILD / "qemu-installed-disk-gate.json"
DISK = BUILD / "installed-disk.img"
BOOT_TIMEOUT_S = int(os.environ.get("XAIOS_INSTALLED_DISK_TIMEOUT", "180"))

FIRMWARE_CANDIDATES = (
    "/opt/homebrew/share/qemu/edk2-aarch64-code.fd",
    "/usr/share/AAVMF/AAVMF_CODE.fd",
    "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd",
    "/usr/share/edk2/aarch64/QEMU_EFI.fd",
    "/opt/homebrew/share/edk2/aarch64/QEMU_EFI.fd",
)

# What booting from a single installed disk has to produce. The partition is
# found by type rather than by position, which is the whole point.
FIRST_BOOT = (
    ("kernel started", re.compile(r"XAIOS Build \d+ kernel starting")),
    ("disk found by ordinal, not by slot",
     re.compile(r"virtio-blk-h: slot=16 capacity_sectors=\d+")),
    ("state partition found by type",
     re.compile(r"xaibootfs: mounted from /dev/vblk16p\d+, a partition of the "
                r"disk this machine booted from")),
    ("filesystem checked", re.compile(r"persistent fsck valid=1")),
    ("all four vCPUs online", re.compile(r"smp: online cpus=4/4")),
    ("shell command surface",
     re.compile(r"/bin/xaios-shell: command surface passed")),
    ("syscall and filesystem suite",
     re.compile(r"/bin/systest: syscall and filesystem suite passed")),
)

# The second boot must load what the first one wrote. "persistent loaded" is
# the marker that separates a working installation from one that reformats
# itself every time and passes every check on the way.
SECOND_BOOT = FIRST_BOOT + (
    ("state written by the previous boot survived",
     re.compile(r"xaibootfs: persistent loaded files=[1-9]\d* ")),
)

FORBIDDEN = (
    ("kernel panic", re.compile(r"CYAN SCREEN OF DEATH")),
    ("assertion failure", re.compile(r"ERROR: assertion failed")),
    ("booted into rescue mode",
     re.compile(r"lifecycle initialized[^\n]*rescue=1")),
    # Formatting on the second boot means the first boot's writes did not
    # reach the disk, which every other marker would happily pass through.
    ("state partition reformatted",
     re.compile(r"xaibootfs: persistent disk no valid fs; formatting")),
)


def fail(message: str) -> int:
    print(f"installed-disk-gate: {message}")
    return 1


def find_firmware() -> str | None:
    for candidate in FIRMWARE_CANDIDATES:
        if Path(candidate).is_file():
            return candidate
    return None


def boot(firmware: str, log: Path) -> str:
    log.unlink(missing_ok=True)
    command = [
        "qemu-system-aarch64",
        # gic-version=3 is not optional: without it the machine faults in the
        # GIC redistributor and the failure looks like a kernel bug.
        "-machine", "virt,gic-version=3",
        "-cpu", "cortex-a72", "-smp", "4", "-m", "2048",
        "-global", "virtio-mmio.force-legacy=false",
        "-drive", f"if=pflash,format=raw,readonly=on,file={firmware}",
        # One drive and nothing else. Attaching anything beside it would make
        # this the test bench again and prove nothing.
        "-drive", f"if=none,format=raw,id=xaios_disk,file={DISK}",
        "-device", "virtio-blk-pci,drive=xaios_disk,bootindex=0",
        "-display", "none",
        "-serial", f"file:{log}",
    ]
    try:
        subprocess.run(command, cwd=ROOT, timeout=BOOT_TIMEOUT_S,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       check=False)
    except subprocess.TimeoutExpired:
        # A machine that reached a login prompt keeps running; the markers in
        # the log decide the outcome, not how the process ended.
        pass
    return log.read_text(encoding="utf-8", errors="replace") \
        if log.exists() else ""


def evaluate(text: str, expected) -> tuple[list, list]:
    checks = [{"name": name, "passed": bool(pattern.search(text))}
              for name, pattern in expected]
    faults = [{"name": name, "seen": bool(pattern.search(text))}
              for name, pattern in FORBIDDEN]
    return checks, faults


def main() -> int:
    if shutil.which("qemu-system-aarch64") is None:
        return fail("qemu-system-aarch64 is not installed")
    firmware = find_firmware()
    if firmware is None:
        return fail("no AAVMF firmware found; install the edk2 aarch64 image")

    # Build the kernel the way every other QEMU gate does. Without the test
    # apps the boot splash owns the console and suppresses the kernel log, so
    # the machine comes up perfectly and the gate sees none of it -- which is
    # exactly what happened the first time this gate ran.
    image = subprocess.run(["make", "image-qemu-test"], cwd=ROOT,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True, check=False)
    if image.returncode != 0:
        print(image.stdout[-4000:])
        return fail("could not build the kernel image")

    # Built fresh: the disk carries the kernel under test in its own ESP, and a
    # stale one would boot a stale kernel and prove nothing about this build.
    build = subprocess.run([str(ROOT / "scripts/make-installed-disk.sh")],
                           cwd=ROOT, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True, check=False)
    if build.returncode != 0:
        print(build.stdout)
        return fail("could not build the installed disk")

    boots = []
    passed = True
    for index, expected in ((1, FIRST_BOOT), (2, SECOND_BOOT)):
        text = boot(firmware, BUILD / f"installed-disk-boot{index}.log")
        checks, faults = evaluate(text, expected)
        ok = all(check["passed"] for check in checks) and \
            not any(fault["seen"] for fault in faults)
        # The first boot formats the partition, so that is not a fault there.
        if index == 1:
            faults = [fault for fault in faults
                      if fault["name"] != "state partition reformatted"]
            ok = all(check["passed"] for check in checks) and \
                not any(fault["seen"] for fault in faults)
        boots.append({"boot": index, "checks": checks, "faults": faults,
                      "passed": ok})
        passed = passed and ok
        print(f"  boot {index}:")
        for check in checks:
            print(f"    {'ok  ' if check['passed'] else 'MISS'} {check['name']}")
        for fault in faults:
            if fault["seen"]:
                print(f"    FAULT {fault['name']}")

    REPORT.write_text(json.dumps({
        "target": "qemu-aarch64-installed-disk",
        "description": "one disk, GPT, ESP and a state partition found by type",
        "boots": boots,
        "passed": passed,
    }, indent=2) + "\n", encoding="utf-8")
    print(f"installed-disk-gate: report written to {REPORT}")
    if not passed:
        return fail("an installed machine did not come up cleanly")
    print("installed-disk-gate: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
