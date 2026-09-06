#!/usr/bin/env python3
"""Bring up a machine with no kernel on its medium, and let it install itself.

This is what network boot has to be able to do. Firmware fetches one file and
runs it; there is no filesystem behind it and nowhere to go back to for a
kernel, so the file has to be the whole system. Then the machine it brought up
has to be able to put XAIOS on the blank disk in front of it, because a system
that can only ever run from the network has not set anything up.

Three steps, and only the third is evidence:

  1. Boot a medium holding the loader and nothing else -- no kernel.elf, no
     initfs.img. If the loader finds its kernel, the embedded payload works.
  2. Have that machine install onto a blank disk.
  3. Boot that disk on its own. Everything before this is the installer
     describing its own work.

What this does not test is the fetch itself. The EDK2 build shipped with QEMU
here has no network boot drivers compiled in, so the file is delivered on a
medium rather than over TFTP. That substitutes the transport and keeps
everything that depends on the file being self-contained, which is the half
that belongs to XAIOS -- the other half is the firmware's, and a firmware with
those drivers serves this file unchanged.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
sys.path.insert(0, str(ROOT / "tests" / "scripts"))
from qemu_gate_lib import arch_from_argv, smoke_timeout

ARCH = arch_from_argv(sys.argv)
SUFFIX = "" if ARCH == "aarch64" else f"-{ARCH}"

# One file that boots a machine with no disk, per architecture.
#
# UEFI names the removable-media path by machine type -- BOOTAA64.EFI on
# AArch64, BOOTRISCV64.EFI on RISC-V -- and every other difference here is the
# emulator and its firmware. The claim being tested is that the one file the
# firmware fetches is the whole system, which is not an architectural claim at
# all, so it is asked of each machine in the same words.
ARCHITECTURES = {
    "aarch64": {
        "qemu": "qemu-system-aarch64",
        "machine": ["-machine", "virt,gic-version=3", "-cpu", "cortex-a72"],
        "removable": "BOOTAA64.EFI",
        "firmware_code": (
            "/opt/homebrew/share/qemu/edk2-aarch64-code.fd",
            "/usr/share/AAVMF/AAVMF_CODE.fd",
            "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd",
            "/usr/share/edk2/aarch64/QEMU_EFI.fd",
        ),
        "firmware_vars": (),
        "build": [["make", "image-qemu-test"]],
        "slot": r"16",
    },
    "riscv64": {
        "qemu": "qemu-system-riscv64",
        "machine": ["-machine", "virt,acpi=off", "-cpu", "rv64"],
        "removable": "BOOTRISCV64.EFI",
        "firmware_code": ("/opt/homebrew/share/qemu/edk2-riscv-code.fd",
                          "/usr/share/qemu/edk2-riscv-code.fd"),
        "firmware_vars": ("/opt/homebrew/share/qemu/edk2-riscv-vars.fd",
                          "/usr/share/qemu/edk2-riscv-vars.fd"),
        "build": [["./scripts/build-riscv64.sh"],
                  ["./scripts/build-riscv64-image.sh"]],
        "slot": r"\d+",
    },
}
PROFILE = ARCHITECTURES[ARCH]
SLOT = PROFILE["slot"]

REPORT = BUILD / f"qemu-netboot-gate{SUFFIX}.json"
NETBOOT = BUILD / "netboot" / PROFILE["removable"]
MEDIUM = BUILD / f"netboot-gate-medium{SUFFIX}.img"
TARGET = BUILD / f"netboot-gate-target{SUFFIX}.img"
TIMEOUT_S = smoke_timeout(
    ARCH, int(os.environ.get("XAIOS_NETBOOT_TIMEOUT", "300")))
TARGET_BYTES = 256 * 1024 * 1024

FIRMWARE_CANDIDATES = PROFILE["firmware_code"]

DISKLESS = (
    ("loader found its embedded kernel",
     re.compile(r"XAIOS loader using embedded kernel image")),
    ("loader found its embedded initial filesystem",
     re.compile(r"XAIOS loader using embedded initfs image")),
    ("kernel started", re.compile(r"XAIOS Build \d+ kernel starting")),
    ("initial filesystem mounted",
     re.compile(r"initramfs: mounted rofs version=\d+ files=[1-9]\d*")),
)

INSTALLED_FROM_NETWORK = (
    ("installed onto the blank disk",
     re.compile(r"install: netboot self-test passed target=/dev/vblk5 "
                r"files=[1-9]\d* bytes=\d{7,}")),
)

# The disk that machine wrote, booted alone. An ordinary EFI System Partition
# is the point: a machine installed over the network is not a special kind of
# machine afterwards, so this asserts what any installed machine asserts.
RESULT = (
    ("kernel started", re.compile(r"XAIOS Build \d+ kernel starting")),
    ("state partition found by type",
     re.compile(rf"xaibootfs: mounted from /dev/vblk{SLOT}p\d+, a partition "
                rf"of the disk this machine booted from")),
    ("shell command surface",
     re.compile(r"/bin/xaios-shell: command surface passed")),
    ("syscall and filesystem suite",
     re.compile(r"/bin/systest: syscall and filesystem suite passed")),
    ("SSH server listening", re.compile(r"SSH server: up and running")),
)

FORBIDDEN = (
    ("kernel panic", re.compile(r"CYAN SCREEN OF DEATH")),
    ("firmware refused the image", re.compile(r"Synchronous Exception at")),
    ("assertion failure", re.compile(r"ERROR: assertion failed")),
)

# The fetch itself, on the architecture where a UEFI network stack is available
# as an option ROM. The firmware asks DHCP for a filename, pulls it over TFTP
# and runs it -- exactly what a blank machine on a network does.
PXE = (
    ("firmware chose network boot",
     re.compile(r'BdsDxe: starting Boot\d+ "UEFI PXEv4')),
    ("loader found its embedded kernel",
     re.compile(r"XAIOS loader using embedded kernel image")),
    ("loader found its embedded initial filesystem",
     re.compile(r"XAIOS loader using embedded initfs image")),
    ("kernel started", re.compile(r"XAIOS Build \d+ kernel starting")),
    ("initial filesystem mounted",
     re.compile(r"initramfs: mounted rofs version=\d+ files=[1-9]\d*")),
)

IPXE_ROM = Path("/opt/homebrew/share/qemu/efi-e1000.rom")
X86_FIRMWARE_CANDIDATES = (
    "/opt/homebrew/share/qemu/edk2-x86_64-code.fd",
    "/usr/share/OVMF/OVMF_CODE.fd",
    "/usr/share/ovmf/OVMF.fd",
)


def pxe_stage(stages: list) -> None:
    """Fetch the image over TFTP and boot it, rather than handing it over."""
    if shutil.which("qemu-system-x86_64") is None:
        print("  a real TFTP fetch: not run -- qemu-system-x86_64 not installed")
        return
    rom = IPXE_ROM
    if not rom.is_file():
        for candidate in Path("/usr/share/qemu").glob("efi-e1000.rom"):
            rom = candidate
            break
    if not rom.is_file():
        print("  a real TFTP fetch: not run -- no UEFI network option ROM")
        return
    fw = None
    for candidate in X86_FIRMWARE_CANDIDATES:
        if Path(candidate).is_file():
            fw = candidate
            break
    if fw is None:
        print("  a real TFTP fetch: not run -- no x86-64 UEFI firmware")
        return

    built = subprocess.run([str(ROOT / "scripts/build-netboot-image.sh")],
                           cwd=str(ROOT), stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, check=False,
                           env={**os.environ, "XAIOS_TARGET_ARCH": "x86_64"})
    image = BUILD / "netboot" / "BOOTX64.EFI"
    if built.returncode != 0 or not image.is_file():
        print("  a real TFTP fetch: not run -- no x86-64 netboot image; "
              "run XAIOS_TARGET_ARCH=x86_64 make image-qemu-test first")
        return

    root = BUILD / "tftproot"
    root.mkdir(parents=True, exist_ok=True)
    shutil.copy(image, root / "BOOTX64.EFI")
    log = BUILD / "netboot-gate-pxe.log"
    log.unlink(missing_ok=True)
    command = [
        "qemu-system-x86_64",
        "-machine", "q35", "-cpu", "max", "-smp", "4", "-m", "2048",
        "-drive", f"if=pflash,format=raw,readonly=on,file={fw}",
        "-netdev", f"user,id=net0,tftp={root},bootfile=BOOTX64.EFI",
        "-device",
        f"e1000,netdev=net0,romfile={rom},bootindex=0",
        "-display", "none", "-serial", f"file:{log}",
    ]
    process = subprocess.Popen(command, cwd=str(ROOT),
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL,
                               start_new_session=True)
    deadline = time.monotonic() + TIMEOUT_S
    try:
        while time.monotonic() < deadline:
            time.sleep(5)
            if not log.exists():
                continue
            text = log.read_bytes().decode("utf-8", "replace")
            if all(p.search(text) for _, p in PXE):
                break
            if any(p.search(text) for _, p in FORBIDDEN):
                break
            if process.poll() is not None:
                break
    finally:
        process.terminate()
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
    text = log.read_bytes().decode("utf-8", "replace") if log.exists() else ""
    stages.append(evaluate("a real TFTP fetch, over DHCP and PXE", text, PXE))


def fail(message: str) -> int:
    print(f"netboot-gate: {message}")
    return 1


def firmware() -> str | None:
    for candidate in FIRMWARE_CANDIDATES:
        if Path(candidate).is_file():
            return candidate
    return None


def firmware_vars() -> str | None:
    """A writable copy of the firmware's variable store, where one is needed.

    EDK2 on RISC-V keeps its boot variables in a second pflash unit and writes
    to it; the AArch64 build here runs from code alone. Copied per run rather
    than used in place: the file belongs to whatever installed QEMU.
    """
    for candidate in PROFILE["firmware_vars"]:
        if Path(candidate).is_file():
            target = BUILD / f"netboot-gate-vars{SUFFIX}.fd"
            shutil.copyfile(candidate, target)
            return str(target)
    return None


def build_medium() -> str | None:
    """An EFI System Partition holding the loader and nothing else."""
    for tool in ("mformat", "mmd", "mcopy"):
        if shutil.which(tool) is None:
            return f"{tool} is required"
    MEDIUM.unlink(missing_ok=True)
    with MEDIUM.open("wb") as handle:
        handle.truncate(48 * 1024 * 1024)
    for command in (["mformat", "-i", str(MEDIUM), "-v", "XAIOSNET", "::"],
                    ["mmd", "-i", str(MEDIUM), "::/EFI", "::/EFI/BOOT"],
                    ["mcopy", "-i", str(MEDIUM), str(NETBOOT),
                     f"::/EFI/BOOT/{PROFILE['removable']}"]):
        if subprocess.run(command, check=False,
                          stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode != 0:
            return f"could not build the medium: {' '.join(command[:1])}"
    return None


def boot(fw: str, log: Path, boot_disk: Path, spare: Path | None,
         expected, writable: bool = False) -> str:
    log.unlink(missing_ok=True)
    command = [
        PROFILE["qemu"],
        *PROFILE["machine"], "-smp", "4", "-m", "2048",
        "-global", "virtio-mmio.force-legacy=false",
        "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={fw}",
    ]
    variables = firmware_vars()
    if variables is not None:
        command += ["-drive", f"if=pflash,format=raw,unit=1,file={variables}"]
    command += [
        # The medium is read-only because a netboot medium is; the disk this
        # machine installed is not, and booting it read-only leaves it unable
        # to format the state partition it was given. That failure looks like
        # a broken install and is a wrong flag in the test.
        "-drive", ("if=none,format=raw,id=boot,file=" + str(boot_disk)) if
        writable else
        ("if=none,format=raw,readonly=on,id=boot,file=" + str(boot_disk)),
        "-device", "virtio-blk-pci,drive=boot,bootindex=0",
    ]
    if spare is not None:
        command += [
            "-drive", f"if=none,format=raw,id=target,file={spare}",
            "-device", "virtio-blk-device,drive=target,bus=virtio-mmio-bus.5",
        ]
    command += ["-display", "none", "-serial", f"file:{log}"]
    process = subprocess.Popen(command, cwd=str(ROOT),
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL,
                               start_new_session=True)
    deadline = time.monotonic() + TIMEOUT_S
    try:
        while time.monotonic() < deadline:
            time.sleep(5)
            if not log.exists():
                continue
            text = log.read_bytes().decode("utf-8", "replace")
            if all(p.search(text) for _, p in expected):
                break
            if any(p.search(text) for _, p in FORBIDDEN):
                break
            if process.poll() is not None:
                break
    finally:
        process.terminate()
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill()
    return log.read_bytes().decode("utf-8", "replace") if log.exists() else ""


def evaluate(stage: str, text: str, expected) -> dict:
    checks = [{"name": n, "passed": bool(p.search(text))} for n, p in expected]
    faults = [{"name": n, "seen": bool(p.search(text))} for n, p in FORBIDDEN]
    passed = all(c["passed"] for c in checks) and \
        not any(f["seen"] for f in faults)
    print(f"  {stage}:")
    for check in checks:
        print(f"    {'ok  ' if check['passed'] else 'MISS'} {check['name']}")
    for fault in faults:
        if fault["seen"]:
            print(f"    FAULT {fault['name']}")
    return {"stage": stage, "checks": checks, "faults": faults,
            "passed": passed}


def build_image() -> None:
    """Build the kernel this gate needs, asking for the boot-time install.

    That install is what the later stages watch, and it is behind a flag
    because an image that partitions slot 5 unasked has no business on
    anybody's machine. Asked for here rather than by the make target, because
    CI runs this script directly and a flag only the Makefile sets is a flag
    that is not set when it matters."""
    for command in PROFILE["build"]:
        subprocess.run(command, cwd=ROOT, check=True,
                       env={**os.environ, "XAIOS_INSTALL_SELF_TEST": "1",
                            "XAIOS_BOOT_TEST_APPS": "1"},
                       stdout=subprocess.DEVNULL)


def main() -> int:
    build_image()
    if shutil.which(PROFILE["qemu"]) is None:
        return fail(f"{PROFILE['qemu']} is not installed")
    fw = firmware()
    if fw is None:
        return fail(f"no UEFI firmware found for {ARCH}")

    built = subprocess.run([str(ROOT / "scripts/build-netboot-image.sh")],
                           cwd=str(ROOT), stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True, check=False,
                           env={**os.environ, "XAIOS_TARGET_ARCH": ARCH})
    if built.returncode != 0:
        print(built.stdout)
        return fail("could not build the netboot image")
    problem = build_medium()
    if problem is not None:
        return fail(problem)

    stages = []
    with TARGET.open("wb") as handle:
        handle.truncate(TARGET_BYTES)
    text = boot(fw, BUILD / f"netboot-gate-diskless{SUFFIX}.log", MEDIUM,
                TARGET,
                DISKLESS + INSTALLED_FROM_NETWORK)
    stages.append(evaluate("a medium holding only the loader", text, DISKLESS))
    stages.append(evaluate("that machine installing onto a blank disk", text,
                           INSTALLED_FROM_NETWORK))

    if all(s["passed"] for s in stages):
        text = boot(fw, BUILD / f"netboot-gate-installed{SUFFIX}.log",
                    TARGET, None,
                    RESULT, writable=True)
        stages.append(evaluate("the disk it installed, booted alone", text,
                               RESULT))

    # The real fetch is an x86-64 stage, because that is the only machine here
    # whose firmware has a network stack. It belongs to the AArch64 run rather
    # than to every run: repeating it under --arch riscv64 would put an x86
    # result in a report about RISC-V and say nothing new.
    if ARCH == "aarch64":
        pxe_stage(stages)

    passed = all(s["passed"] for s in stages)
    REPORT.write_text(json.dumps({
        "target": f"qemu-{ARCH}-netboot",
        "transport": f"medium on {ARCH}; DHCP and TFTP on x86_64",
        "stages": stages,
        "passed": passed,
    }, indent=2) + "\n", encoding="utf-8")
    print(f"netboot-gate: report written to {REPORT}")
    if not passed:
        return fail("the network boot path did not complete")
    print("netboot-gate: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
