#!/usr/bin/env python3
"""Platform profiles and boot markers for the installed-disk gate.

The gate is `qemu-installed-disk-gate.py`. This module holds the half that is
data rather than mechanics: what a machine of each architecture is and where its
firmware lives, the keys every profile must carry, the hart accounting the
RISC-V profile asserts, the install target read out of the kernel rather than
restated per architecture, and the marker table each boot is held to. It was
split out so the gate, which finds QEMU, drives the boots and writes the report,
stays under the repository's 500-line limit. The moved code is verbatim; the
gate imports these names, so the command line, the output and the exit codes are
unchanged.

It is imported and is not itself a program: `python3
tests/scripts/qemu-installed-disk-gate.py` remains the only entry point.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# The gates here import qemu_gate_lib by name, which works when one is run as a
# script because its directory is sys.path[0]; stating it keeps the import
# working when this module is reached some other way.
sys.path.insert(0, str(ROOT / "tests" / "scripts"))

import qemu_gate_lib  # noqa: E402


# What a machine of each kind is, and where its firmware lives.
#
# The property under test -- one disk, a GPT on it, an ESP and a state
# partition found by type rather than by position -- is not architectural at
# all. What is architectural is the emulator binary, the firmware image, the
# machine type, and the ordinal the transport layer ends up giving the disk,
# which is a fact about where QEMU puts the controller rather than about
# XAIOS. So those are named here and everything else is shared.
ARCHITECTURES = {
    "aarch64": {
        "qemu": "qemu-system-aarch64",
        "machine": ["-machine", "virt,gic-version=3", "-cpu", "cortex-a72"],
        "firmware_code": (
            "/opt/homebrew/share/qemu/edk2-aarch64-code.fd",
            "/usr/share/AAVMF/AAVMF_CODE.fd",
            "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd",
            "/usr/share/edk2/aarch64/QEMU_EFI.fd",
            "/opt/homebrew/share/edk2/aarch64/QEMU_EFI.fd",
        ),
        "firmware_vars": (),
        "build": [["make", "image-qemu-test"]],
        "slot": r"16",
        "cpus": lambda: (
            ("all four vCPUs online",
             re.compile(r"smp: online cpus=4/4")),
        ),
        "net": ["-netdev", "user,id=net0",
                "-device",
                "virtio-net-device,netdev=net0,bus=virtio-mmio-bus.2"],
        "virtio_mmio": ["-global", "virtio-mmio.force-legacy=false"],
        "esp_bytes_digits": 8,
        # The blank disk the running system installs onto, on the storage
        # administration window the boot path opens rather than on a device it
        # looks up itself: MMIO bus 5 here, which is the window the kernel names
        # /dev/vblk5. Which physical disk that window is differs by transport;
        # what the window is called does not.
        "target_device": ["virtio-blk-device,drive=xaios_target,"
                          "bus=virtio-mmio-bus.5"],
    },
    "x86_64": {
        "qemu": "qemu-system-x86_64",
        # q35 with TCG, which is what the runner uses and what CI has: an
        # x86-64 guest on an Apple-silicon host is emulation either way.
        "machine": ["-machine", "q35,accel=tcg", "-cpu", "max",
                    "-no-reboot"],
        "firmware_code": (
            "/opt/homebrew/share/qemu/edk2-x86_64-code.fd",
            "/usr/share/OVMF/OVMF_CODE.fd",
            "/usr/share/edk2/ovmf/OVMF_CODE.fd",
            "/usr/share/qemu/OVMF.fd",
        ),
        "firmware_vars": (
            "/opt/homebrew/share/qemu/edk2-i386-vars.fd",
            "/usr/share/OVMF/OVMF_VARS.fd",
            "/usr/share/edk2/ovmf/OVMF_VARS.fd",
        ),
        "build": [["make", "image-x86_64-qemu-test"]],
        # 16, measured from the guest rather than assumed: the ordinal is a
        # fact about where QEMU puts the controller, and it happens to match
        # AArch64's here. It was written as 0 first and three markers missed.
        "slot": r"16",
        "cpus": lambda: (
            ("all four vCPUs online",
             re.compile(r"smp: x86 MADT/APIC online cpus=4 dynamic_capacity=4")),
        ),
        "net": ["-netdev", "user,id=net0",
                "-device", "virtio-net-pci,netdev=net0,disable-legacy=on"],
        "virtio_mmio": [],
        "target_device": ["virtio-blk-pci,drive=xaios_target,"
                          "disable-legacy=on"],
        # Seven digits, not eight. The AArch64 image carries the GRUB
        # chainloader Fusion's firmware needs and this one does not, so its ESP
        # is about 9.6 MB against AArch64's ten-plus -- a smaller number for a
        # real reason rather than a weaker check. The claim is unchanged: a
        # reader returning plausible nonsense does not reach this.
        "esp_bytes_digits": 7,
    },
    "riscv64": {
        "qemu": "qemu-system-riscv64",
        # acpi=off, because EDK2 on this board hands the kernel an ACPI set
        # it cannot use and the device tree is what this port reads.
        "machine": ["-machine", "virt,acpi=off", "-cpu", "rv64"],
        # B-67: this pair named Homebrew and /usr/share/qemu, and Debian
        # puts it in neither, so on the Linux CI runs on the RISC-V row
        # found no firmware. The shared list knows every platform's spelling.
        "firmware_code": qemu_gate_lib.RISCV_FIRMWARE_CODE,
        # A writable variable store, copied per run: the firmware writes it,
        # and editing the one the package manager installed would change every
        # later run on this host.
        "firmware_vars": qemu_gate_lib.RISCV_FIRMWARE_VARS,
        "build": [["./scripts/build-riscv64.sh"],
                  ["./scripts/build-riscv64-image.sh"],
                  # The loader, which is a third script here and not part of
                  # either of the other two: build-riscv64-image.sh builds no
                  # UEFI loader on purpose -- this board's smoke path hands QEMU
                  # a kernel directly -- and an installed disk is booted through
                  # firmware, so it needs BOOTRISCV64.EFI on its ESP. Without
                  # this step the disk builder refuses to run for want of a
                  # loader, which is what used to happen: the gate never reached
                  # a single boot.
                  ["./scripts/build-riscv64-boot-media.sh"]],
        "slot": r"\d+",
        # Every hart the firmware let go of, and no more.
        #
        # EDK2 parks a hart on its own multiprocessor services and does not
        # give it back, so a machine started through this firmware may come up
        # with three of its four -- and *which* hart, or whether it happens at
        # all, is not deterministic: three consecutive boots of the same disk
        # here kept hart 3, kept hart 2, and kept none. So there is no fixed
        # number to assert and no fixed hart to name.
        #
        # What does hold is a relationship: the harts that come online are
        # exactly the capacity minus the ones firmware refused to release, and
        # every refusal says ALREADY_AVAILABLE, which is firmware claiming the
        # hart rather than the hart failing. A hart that simply never arrived
        # -- the case this check exists for -- breaks that sum and fails.
        "cpus": lambda: (("every hart not held by firmware came online",
                          HartAccounting()),),
        "net": ["-netdev", "user,id=net0",
                "-device", "virtio-net-pci,netdev=net0,disable-legacy=on"],
        "virtio_mmio": [],
        "target_device": ["virtio-blk-pci,drive=xaios_target,"
                          "disable-legacy=on"],
        # Eight digits, and measured rather than matched to another
        # architecture. The first draft of this profile copied x86-64's seven,
        # which is a *weaker* floor than AArch64's eight and would have let a
        # smaller ESP through while looking like a considered choice. The guest
        # reports the real figure on this boot: `files=5 bytes=16894192` -- 16.9
        # MB, which is eight digits, because this architecture's ESP carries the
        # loader and its payload the same way AArch64's does.
        "esp_bytes_digits": 8,
    },
}
# Every key this file reads without a default, checked against all three
# profiles rather than only the one being run. A profile that omits one used to
# die with a bare KeyError at import, and only the AArch64 gate ran anywhere, so
# the RISC-V profile missing `esp_bytes_digits` stayed invisible until someone
# ran the RISC-V gate -- which then did not run at all.
REQUIRED_PROFILE_KEYS = ("qemu", "machine", "firmware_code", "firmware_vars",
                         "build", "slot", "cpus", "net", "virtio_mmio",
                         "esp_bytes_digits", "target_device")
for _arch, _profile in ARCHITECTURES.items():
    _missing = [key for key in REQUIRED_PROFILE_KEYS if key not in _profile]
    if _missing:
        raise SystemExit(f"installed-disk-gate: the {_arch} profile is missing "
                         f"{', '.join(_missing)}")


def kernel_install_target() -> str:
    """The volume the running system installs onto, read from the kernel.

    Not a per-architecture fact, and it must never be guessed per architecture.
    The boot path names its install target with one unconditional constant --
    `XAIOS_INSTALL_TARGET` in kernel/core/kmain.c -- and prints that same string
    in the markers this gate asserts, so a per-architecture copy here can only
    be a second guess at it. It was one, and a wrong one: the RISC-V and x86-64
    profiles named /dev/vblk1 while the kernel prints /dev/vblk5, which made
    both of those expectations impossible to satisfy. Reading it instead of
    restating it means the two cannot drift apart again.
    """
    source = (ROOT / "kernel" / "core" / "kmain.c").read_text()
    match = re.search(r'#define\s+XAIOS_INSTALL_TARGET\s+"([^"]+)"', source)
    if match is None:
        raise SystemExit("installed-disk-gate: kernel/core/kmain.c no longer "
                         "defines XAIOS_INSTALL_TARGET")
    return match.group(1)


CAPACITY = re.compile(r"smp: riscv64 boot hart=\d+ harts=\d+ capacity=(\d+)")
ONLINE = re.compile(r"smp: riscv64 (\d+) harts online")
# ALREADY_AVAILABLE, spelled as SBI returns it. Any other error is a hart that
# failed to start, which is not the same thing and must not pass.
HELD = re.compile(r"smp: hart=(\d+) refused to start "
                  r"sbi_error=fffffffffffffffa")


class HartAccounting:
    """Online harts plus firmware-held harts must equal the capacity.

    Shaped like a compiled pattern so it can sit in the same list as one --
    the gate asks every expectation the same question, and this one's answer
    happens to need arithmetic rather than a match.
    """

    def search(self, text: str):
        capacity = CAPACITY.search(text)
        online = ONLINE.search(text)
        if capacity is None or online is None:
            return None
        held = len(HELD.findall(text))
        return self if int(online.group(1)) + held == int(
            capacity.group(1)) else None
