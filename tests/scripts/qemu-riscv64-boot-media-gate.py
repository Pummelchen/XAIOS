#!/usr/bin/env python3
"""Boot XAIOS on RISC-V from its own disk, through UEFI firmware.

The other gate hands the kernel to QEMU with -kernel, which proves the kernel
and proves nothing about the medium. This one boots EDK2 against the image
build-riscv64-boot-media.sh produces and requires the whole chain: firmware
finds the loader at the removable-media path, the loader reads the kernel off
that same disk, and the kernel comes up to a login prompt with sshd listening.

`acpi=off` is required rather than incidental. With ACPI on, this EDK2 build
publishes no device tree, and the RISC-V port reads its interrupt controller,
its timebase and its virtio window from one.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import riscv64_gate_lib as rvgate

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
MEDIUM = BUILD / "xaios-riscv64.img"
INITFS = BUILD / "xaios-riscv64-initfs.img"
LOG = BUILD / "qemu-riscv64-boot-media-gate.log"
FIRMWARE_CODE = Path("/opt/homebrew/share/qemu/edk2-riscv-code.fd")
FIRMWARE_VARS = Path("/opt/homebrew/share/qemu/edk2-riscv-vars.fd")

REQUIRED = [
    # Firmware found the loader on the medium, rather than a kernel handed to
    # QEMU on the command line.
    "XAIOS loader starting",
    "XAIOS loader target: RISC-V UEFI",
    # And the loader read the kernel off that same disk and started it.
    # The kernel came from the signed A/B slot, not from the fallback path a
    # medium without a system volume uses. That is what a real machine does,
    # and asserting it is what keeps the update path from rotting untested.
    "XAIOS loader loaded verified A/B system slot",
    "XAIOS loader exiting boot services",
    "riscv64: booted through UEFI",
    "XAIOS Build 4 kernel starting",
    # Then the ordinary boot, end to end.
    "vmm: sv48 enabled",
    "initramfs: mounted rofs version=2",
    "xaifs: mounted /models",
    "kernel: /init returned to kernel exit_code=0",
    "[########################################] 100%",
    "xaios login:",
    "SSH server: up and running",
]

FORBIDDEN = [
    "ERROR: assertion failed",
    "CYAN SCREEN OF DEATH",
    "XAIOS loader error",
]

MINIMUM_SELF_TESTS = 70
FINAL_MARKER = "SSH server: up and running"


def main() -> int:
    qemu = shutil.which("qemu-system-riscv64")
    if qemu is None:
        print("qemu-system-riscv64 is not installed; skipping", file=sys.stderr)
        return 0
    if not FIRMWARE_CODE.is_file() or not FIRMWARE_VARS.is_file():
        print(f"no EDK2 RISC-V firmware at {FIRMWARE_CODE}; skipping",
              file=sys.stderr)
        return 0
    for artefact in (MEDIUM, INITFS):
        if not artefact.is_file():
            print(f"missing {artefact}; run scripts/build-riscv64-boot-media.sh",
                  file=sys.stderr)
            return 2

    timeout = int(os.environ.get("XAIOS_RISCV64_TIMEOUT", "900"))
    LOG.parent.mkdir(parents=True, exist_ok=True)
    if LOG.exists():
        LOG.unlink()

    with tempfile.TemporaryDirectory() as scratch:
        state = Path(scratch)
        variables = state / "vars.fd"
        variables.write_bytes(FIRMWARE_VARS.read_bytes())
        persistent = state / "persistent.img"
        persistent.write_bytes(b"\0" * (16 * 1024 * 1024))
        models = state / "models.img"
        models.write_bytes((BUILD / "xaios-xaifs.img").read_bytes())
        admin = state / "storage-admin.img"
        admin.write_bytes((BUILD / "xaios-smoke-storage-admin.img").read_bytes())
        system = state / "system.img"
        system.write_bytes((BUILD / "xaios-riscv64-system.img").read_bytes())

        command = [
            qemu, "-machine", "virt,acpi=off", "-cpu", "rv64",
            "-smp", "4", "-m", "1024", "-display", "none",
            # QEMU's virtio-mmio transports default to the legacy interface,
            # which the driver refuses; without this the model volume is
            # simply absent.
            "-global", "virtio-mmio.force-legacy=false",
            "-serial", f"file:{LOG}",
            "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={FIRMWARE_CODE}",
            "-drive", f"if=pflash,format=raw,unit=1,file={variables}",
            # No -kernel: everything the machine runs comes off this disk.
            "-drive", f"if=none,format=raw,readonly=on,id=xboot,file={MEDIUM}",
            "-device", "virtio-blk-pci,drive=xboot,bootindex=0,disable-legacy=on",
            "-drive", f"if=none,format=raw,snapshot=on,id=xtest,file={INITFS}",
            "-device", "virtio-blk-device,drive=xtest,bus=virtio-mmio-bus.0",
            "-drive", f"if=none,format=raw,id=xpers,file={persistent}",
            "-device", "virtio-blk-device,drive=xpers,bus=virtio-mmio-bus.1",
            "-drive", f"if=none,format=raw,id=xmodels,file={models}",
            "-device", "virtio-blk-device,drive=xmodels,bus=virtio-mmio-bus.4",
            "-drive", f"if=none,format=raw,id=xadmin,file={admin}",
            "-device", "virtio-blk-device,drive=xadmin,bus=virtio-mmio-bus.5",
            # The signed A/B system volume, on both transports as the other
            # architectures present it.
            "-blockdev", f"driver=file,node-name=sysf,filename={system},locking=off",
            "-blockdev", "driver=raw,node-name=sysraw,file=sysf",
            "-device", "virtio-blk-pci,drive=sysraw,bootindex=1,disable-legacy=on",
            "-blockdev", f"driver=file,node-name=sysf2,filename={system},locking=off",
            "-blockdev", "driver=raw,node-name=sysraw2,file=sysf2",
            "-device", "virtio-blk-device,drive=sysraw2,bus=virtio-mmio-bus.6",
            "-device", "virtio-rng-pci,disable-legacy=on",
            "-netdev", "user,id=n0",
            "-device", "virtio-net-pci,netdev=n0,disable-legacy=on",
        ]
        guest = subprocess.Popen(command, cwd=str(ROOT),
                                 stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + timeout
        try:
            while time.monotonic() < deadline:
                if guest.poll() is not None:
                    break
                if LOG.is_file():
                    tail = LOG.read_text(encoding="utf-8", errors="replace")
                    if FINAL_MARKER in tail or "CYAN SCREEN" in tail:
                        break
                time.sleep(1.0)
        finally:
            if guest.poll() is None:
                guest.kill()
                guest.wait()

    if not LOG.is_file() or LOG.stat().st_size == 0:
        print("the guest produced no serial output at all", file=sys.stderr)
        return 1
    output = LOG.read_text(encoding="utf-8", errors="replace")
    failures = rvgate.problems(output, REQUIRED,
                              minimum_self_tests=MINIMUM_SELF_TESTS,
                              forbidden=FORBIDDEN)
    self_tests = rvgate.self_tests(output)
    if failures:
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        print(f"whole boot saved to {LOG.relative_to(ROOT)}", file=sys.stderr)
        return 1

    print(f"qemu-riscv64-boot-media-gate: booted from its own disk through "
          f"UEFI to a login prompt with sshd listening, {self_tests} "
          f"self-tests passed, no errors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
