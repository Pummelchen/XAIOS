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

The profiles, the install target read out of the kernel, the hart accounting
and the marker tables live in `qemu_installed_disk_gate_lib.py` beside this
file; this gate finds QEMU, drives the boots and writes the report. The command
line, the output and the exit codes are unchanged by the split.
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
sys.path.insert(0, str(ROOT / "tests" / "scripts"))
from qemu_gate_lib import arch_from_argv, smoke_timeout

ARCH = arch_from_argv(sys.argv)
SUFFIX = "" if ARCH == "aarch64" else f"-{ARCH}"
REPORT = BUILD / f"qemu-installed-disk-gate{SUFFIX}.json"
DISK = BUILD / f"installed-disk{SUFFIX}.img"
TARGET = BUILD / f"install-target{SUFFIX}.img"
TARGET_BYTES = 256 * 1024 * 1024
BOOT_TIMEOUT_S = smoke_timeout(
    ARCH, int(os.environ.get("XAIOS_INSTALLED_DISK_TIMEOUT", "180")))

# The moved names are imported, not redefined, so the gate's module surface is
# what it was before the split.
from qemu_installed_disk_gate_lib import (  # noqa: E402
    ARCHITECTURES,
    CAPACITY,
    HELD,
    ONLINE,
    REQUIRED_PROFILE_KEYS,
    HartAccounting,
    kernel_install_target,
)

PROFILE = ARCHITECTURES[ARCH]
FIRMWARE_CANDIDATES = PROFILE["firmware_code"]
SLOT = PROFILE["slot"]
TARGET_VOLUME = kernel_install_target()
ESP_BYTES_DIGITS = PROFILE["esp_bytes_digits"]

# What booting from a single installed disk has to produce. The partition is
# found by type rather than by position, which is the whole point.
FIRST_BOOT = (
    ("kernel started", re.compile(r"XAIOS Build \d+ kernel starting")),
    ("disk found by ordinal, not by slot",
     re.compile(rf"virtio-blk-h: slot={SLOT} capacity_sectors=\d+")),
    ("state partition found by type",
     re.compile(rf"xaibootfs: mounted from /dev/vblk{SLOT}p\d+, a partition of "
                rf"the disk this machine booted from")),
    ("filesystem checked", re.compile(r"persistent fsck valid=1")),
    *PROFILE["cpus"](),
    ("shell command surface",
     re.compile(r"/bin/xaios-shell: command surface passed")),
    ("syscall and filesystem suite",
     re.compile(r"/bin/systest: syscall and filesystem suite passed")),
    # The system reads its own EFI System Partition. That volume was written
    # by mtools on the build host and is read here by the kernel's own FAT
    # code, so this checks the reader against an implementation that is not
    # itself -- the reciprocal of the hosted test, where mtools reads what
    # XAIOS wrote. Four files, and the kernel is the large one, so a reader
    # that returned plausible nonsense would not reach this size.
    # The byte total is the substantive claim, not the file count: a reader
    # returning plausible nonsense does not reach ten megabytes. Pinning the
    # count instead broke this gate the moment a file was added to the list --
    # the same brittleness that made an unrelated gate assert on a running
    # tally of every interrupt in the kernel.
    ("boot files readable from the ESP",
     re.compile(rf"boot-esp: readable volume=/dev/vblk{SLOT}p\d+ "
                rf"files=[1-9]\d* bytes=\d{{{ESP_BYTES_DIGITS},}}")),
    ("kernel image found on the ESP",
     re.compile(r"boot-esp: /EFI/XAIOS/KERNEL\.ELF size=\d{6,}")),
)

# The second boot must load what the first one wrote. "persistent loaded" is
# the marker that separates a working installation from one that reformats
# itself every time and passes every check on the way.
SECOND_BOOT = FIRST_BOOT + (
    ("state written by the previous boot survived",
     re.compile(r"xaibootfs: persistent loaded files=[1-9]\d* ")),
)

# The install itself: a running XAIOS writes a bootable disk, and then that
# disk is booted on its own. Nothing short of booting the result proves it,
# because every earlier check is the installer marking its own work.
INSTALL = (
    ("installed onto the blank disk",
     # The byte floor is per-architecture, like the one the boot checks use and
     # for the same reason: an x86-64 ESP is about 9.6 MB because it carries no
     # GRUB chainloader, which is seven digits, while AArch64's is eight. This
     # was written as `\d{8,}` when only AArch64 could reach the phase, so the
     # first time an x86-64 machine actually installed onto a blank disk the
     # check missed a successful install and reported a failure that had not
     # happened.
     re.compile(rf"install: self-test passed target={TARGET_VOLUME} "
                rf"files=5 bytes=\d{{{ESP_BYTES_DIGITS},}}")),
    ("every boot file copied",
     re.compile(rf"install: {TARGET_VOLUME} is bootable "
                rf"esp={TARGET_VOLUME}p\d+ state={TARGET_VOLUME}p\d+ files=5")),
)

# What the disk XAIOS wrote must do when booted on its own. The state
# partition is left empty by the installer on purpose, so this boot formats it
# exactly as the first boot of any installation does.
INSTALLED_RESULT = (
    ("kernel started", re.compile(r"XAIOS Build \d+ kernel starting")),
    ("state partition found by type",
     re.compile(rf"xaibootfs: mounted from /dev/vblk{SLOT}p\d+, a partition of "
                rf"the disk this machine booted from")),
    *PROFILE["cpus"](),
    ("shell command surface",
     re.compile(r"/bin/xaios-shell: command surface passed")),
    ("syscall and filesystem suite",
     re.compile(r"/bin/systest: syscall and filesystem suite passed")),
    # The seed the installer copied. Without it there is no secure entropy and
    # sshd refuses to start -- which is how a filename that cannot be written
    # as 8.3 was found in the first place.
    ("SSH server running on the installed system",
     re.compile(r"SSH server: up and running")),
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


def firmware_vars() -> str | None:
    """A writable copy of the firmware's variable store, where one is needed.

    AArch64's AAVMF build here runs from code alone; EDK2 on RISC-V keeps its
    boot variables in a second pflash unit and writes to it. Copied per run
    rather than used in place: the file belongs to whatever installed QEMU,
    and a gate that edits it changes every later run on the host.
    """
    for candidate in PROFILE["firmware_vars"]:
        if Path(candidate).is_file():
            target = BUILD / f"installed-disk-vars{SUFFIX}.fd"
            shutil.copyfile(candidate, target)
            return str(target)
    return None


def boot(firmware: str, log: Path, disk: Path = DISK,
         spare: Path | None = None) -> str:
    log.unlink(missing_ok=True)
    command = [
        PROFILE["qemu"],
        # AArch64: gic-version=3 is not optional -- without it the machine
        # faults in the GIC redistributor and the failure looks like a kernel
        # bug. RISC-V: acpi=off, because EDK2 hands the kernel an ACPI set it
        # cannot use and the device tree is what this port reads.
        *PROFILE["machine"], "-smp", "4", "-m", "2048",
        *PROFILE["virtio_mmio"],
        "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={firmware}",
    ]
    variables = firmware_vars()
    if variables is not None:
        command += ["-drive", f"if=pflash,format=raw,unit=1,file={variables}"]
    command += [
        # One drive and nothing else. Attaching anything beside it would make
        # this the test bench again and prove nothing.
        "-drive", f"if=none,format=raw,id=xaios_disk,file={disk}",
        "-device", "virtio-blk-pci,drive=xaios_disk,bootindex=0",
    ]
    if spare is not None:
        # A blank disk for the running system to install onto, on the window
        # the boot path attaches for storage administration.
        command += [
            "-drive", f"if=none,format=raw,id=xaios_target,file={spare}",
            "-device", *PROFILE["target_device"],
        ]
    command += [
        # One network card, because an installed machine has one -- and
        # without it sshd is correctly withheld for want of a network, which
        # would make the last stage of this gate unreachable. The "one drive
        # and nothing else" rule above is about disks: attaching a second
        # volume would turn this back into the test bench, and a NIC does not.
        *PROFILE["net"],
        "-display", "none",
        "-serial", f"file:{log}",
    ]
    # The emulator's own complaints go beside the console, not to /dev/null.
    # A machine that never started leaves an empty console and a list of
    # missing markers, which reads as a broken kernel and is a broken bench.
    errors = log.with_suffix(".qemu-stderr.log")
    try:
        with errors.open("wb") as sink:
            subprocess.run(command, cwd=ROOT, timeout=BOOT_TIMEOUT_S,
                           stdout=sink, stderr=subprocess.STDOUT, check=False)
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
    if shutil.which(PROFILE["qemu"]) is None:
        return fail(f"{PROFILE['qemu']} is not installed")
    firmware = find_firmware()
    if firmware is None:
        return fail(f"no UEFI firmware found for {ARCH}; looked in "
                    f"{list(FIRMWARE_CANDIDATES)}")

    # Build the kernel the way every other QEMU gate does. Without the test
    # apps the boot splash owns the console and suppresses the kernel log, so
    # the machine comes up perfectly and the gate sees none of it -- which is
    # exactly what happened the first time this gate ran.
    # The install at boot is what produces the disk this gate then boots, and
    # it is behind a flag because an image that installs onto slot 5 unasked
    # has no business on anyone's machine. Ask for it here.
    for command in PROFILE["build"]:
        image = subprocess.run(
            command, cwd=ROOT,
            env={**os.environ, "XAIOS_INSTALL_SELF_TEST": "1",
                 "XAIOS_BOOT_TEST_APPS": "1"},
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, check=False)
        if image.returncode != 0:
            print(image.stdout[-4000:])
            return fail(f"could not build the kernel image: {command}")

    # Built fresh: the disk carries the kernel under test in its own ESP, and a
    # stale one would boot a stale kernel and prove nothing about this build.
    build = subprocess.run([str(ROOT / "scripts/make-installed-disk.sh")],
                           cwd=ROOT,
                           env={**os.environ, "XAIOS_TARGET_ARCH": ARCH,
                                "XAIOS_INSTALLED_DISK": str(DISK)},
                           stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True, check=False)
    if build.returncode != 0:
        print(build.stdout)
        return fail("could not build the installed disk")

    boots = []
    passed = True
    skip_install = PROFILE.get("install_phase_skip")

    for index, expected in ((1, FIRST_BOOT), (2, SECOND_BOOT)):
        text = boot(firmware,
                    BUILD / f"installed-disk-boot{index}{SUFFIX}.log")
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

    # Now the part that is not about this disk at all: a running XAIOS writes a
    # bootable disk of its own, and that disk is booted alone. Only the second
    # boot is evidence -- everything before it is the installer describing its
    # own work.
    if passed and skip_install is not None:
        # Reported, never counted as a pass for the thing skipped.
        print(f"  install: SKIPPED -- {skip_install}")
        boots.append({"boot": "install", "skipped": skip_install})

    if passed and skip_install is None:
        with TARGET.open("wb") as handle:
            handle.truncate(TARGET_BYTES)
        text = boot(firmware, BUILD / f"install-run{SUFFIX}.log",
                        spare=TARGET)
        checks, faults = evaluate(text, INSTALL)
        # Formatting is expected here: this boot formats the spare disk's new
        # state partition as part of installing onto it.
        faults = [f for f in faults if f["name"] != "state partition reformatted"]
        install_ok = all(c["passed"] for c in checks) and \
            not any(f["seen"] for f in faults)
        boots.append({"boot": "install", "checks": checks, "faults": faults,
                      "passed": install_ok})
        passed = passed and install_ok
        print("  install:")
        for check in checks:
            print(f"    {'ok  ' if check['passed'] else 'MISS'} {check['name']}")
        for fault in faults:
            if fault["seen"]:
                print(f"    FAULT {fault['name']}")

        if install_ok:
            text = boot(firmware,
                        BUILD / f"installed-by-xaios{SUFFIX}.log", disk=TARGET)
            checks, faults = evaluate(text, INSTALLED_RESULT)
            faults = [f for f in faults
                      if f["name"] != "state partition reformatted"]
            result_ok = all(c["passed"] for c in checks) and \
                not any(f["seen"] for f in faults)
            boots.append({"boot": "installed-result", "checks": checks,
                          "faults": faults, "passed": result_ok})
            passed = passed and result_ok
            print("  the disk XAIOS installed, booted on its own:")
            for check in checks:
                print(f"    {'ok  ' if check['passed'] else 'MISS'} "
                      f"{check['name']}")
            for fault in faults:
                if fault["seen"]:
                    print(f"    FAULT {fault['name']}")

    REPORT.write_text(json.dumps({
        "target": f"qemu-{ARCH}-installed-disk",
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
