#!/usr/bin/env python3
"""Boot XAIOS on the QEMU RISC-V `virt` board and check what actually ran.

This gate used to assert a bring-up: a console, a trap, a page table and a
hash, printed by a short program that ran instead of the kernel. The kernel
boots on this architecture now, so the gate asserts the boot -- and the
markers below are chosen so that a kernel which printed them and did nothing
would be caught by another one. "PCI: enumerated" without "virtio-blk:
capacity_sectors=" would mean a bus with nothing on it; the mount line without
"/init returned to kernel exit_code=0" would mean a filesystem nobody read.

Four harts, deliberately. Firmware picks its own boot hart and it is not
always hart 0 -- on this board it has been observed as 0, 1, 2 and 3 across
consecutive runs of an identical command -- so a single-hart gate cannot see
the class of bug where the kernel assumes which one it is. Running with four
means every run draws again.

The output goes to a file through QEMU's own serial sink rather than through a
pipe. QEMU block-buffers its console when stdout is redirected and drops the
buffer when it is killed, so a timed-out run read back as a kernel that
printed nothing at all -- and a whole session went into bisecting an
application that was never at fault.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
KERNEL = ROOT / "build" / "kernel-riscv64" / "kernel.elf"
INITFS = ROOT / "build" / "xaios-riscv64-initfs.img"
IMAGE_BUILDER = ROOT / "scripts" / "build-riscv64-image.sh"
LOG = ROOT / "build" / "qemu-riscv64-gate.log"

REQUIRED = [
    # The machine described from its own device tree rather than from
    # constants, and free memory that excludes the kernel and the tree itself.
    "boot: memory_map=",
    # Sv48, because XAIOS_USER_BASE is past what Sv39 can address.
    "vmm: sv48 enabled",
    "vmm: self-test passed (map, translate, write, unmap)",
    # A bus that was enumerated, and a device on it that answered. The second
    # line is what stops the first from being a bus with nothing attached.
    "PCI: ECAM mapped bus=0",
    "PCI: enumerated",
    # Both virtio transports carry a disk on this machine, and the gate
    # names one line from each: the boot volume arrives over MMIO at the
    # window read from the device tree, and version=2 is the part worth
    # asserting because QEMU's transports default to a legacy interface the
    # driver refuses, and every slot then reads as empty with nothing said.
    "virtio-blk: mmio base=0x10001000 version=2",
    "virtio-blk: capacity_sectors=",
    # The model volume, which is the one that arrives over the other
    # transport -- a machine that finds only one of the two mounts no models.
    "xaifs: mounted /models",
    # A filesystem that was read, and the applications in it.
    "initramfs: mounted rofs version=2",
    # Every hart, scheduling. Not "started" -- scheduling.
    "smp: riscv64 4 harts scheduling online=4",
    # A clock with a real epoch rather than an assumed one.
    "rtc: self-test passed",
    # Userspace: loaded, run, and returned from through its own exit syscall.
    "/init: service setup complete",
    "kernel: /init returned to kernel exit_code=0",
    "kernel: /bin/service-manager returned to kernel exit_code=0",
    # The hosted ISO C99 library, running rather than merely linking.
    "kernel: /bin/helloworldc99 returned to kernel exit_code=0",
    "C99-TERMINATION-PROBES-PASS",
    # The control plane rendering every command it claims to.
    "/bin/xaiosctl: control commands passed human=14 json=14",
    # And the end of it: a complete boot, a login prompt and a server that is
    # actually listening.
    "[########################################] 100%",
    "xaios login:",
    "SSH server: up and running",
]

FORBIDDEN = [
    "ERROR:",
    "CYAN SCREEN OF DEATH",
    "assertion failed",
    "is not in the initial filesystem",
    "Sv48 refused",
    # Only the block device: this board genuinely has no virtio console, GPU
    # or entropy device, and those drivers say so on every healthy boot. A
    # blanket "no pci device" made the gate fail on a working machine.
    "virtio-blk: no pci device",
]

# How many self-tests the shared kernel is expected to pass. A floor rather
# than an exact count, so adding a test does not fail the gate -- but a boot
# that quietly stopped running them does.
MINIMUM_SELF_TESTS = 78

# The last thing a complete boot prints. Watched for, so a good run ends when
# the boot ends rather than when the timeout does.
FINAL_MARKER = "SSH server: up and running"


def main() -> int:
    qemu = shutil.which("qemu-system-riscv64")
    if qemu is None:
        print("qemu-system-riscv64 is not installed; skipping", file=sys.stderr)
        return 0
    if not KERNEL.is_file():
        print(f"no kernel at {KERNEL}; run scripts/build-riscv64.sh first",
              file=sys.stderr)
        return 2
    if not INITFS.is_file():
        print(f"no initial filesystem at {INITFS}; run "
              f"{IMAGE_BUILDER.relative_to(ROOT)} first", file=sys.stderr)
        return 2

    timeout = int(os.environ.get("XAIOS_RISCV64_TIMEOUT", "600"))
    LOG.parent.mkdir(parents=True, exist_ok=True)
    if LOG.exists():
        LOG.unlink()

    # A scratch copy, because the guest writes to its volumes and a gate that
    # mutates its own inputs passes differently the second time.
    # The machine shape lives in platform/qemu/run-qemu-riscv64.sh, next to
    # the runners for the other two architectures, so the gate and a person
    # debugging by hand drive exactly the same machine.
    runner = ROOT / "platform/qemu/run-qemu-riscv64.sh"
    if not runner.is_file():
        print(f"no runner at {runner}", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory() as scratch:
        environment = dict(os.environ)
        environment["XAIOS_RISCV64_LOG"] = str(LOG)
        environment["XAIOS_RISCV64_STATE"] = scratch
        guest = subprocess.Popen([str(runner)], cwd=str(ROOT), env=environment,
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
        print("the guest produced no serial output at all -- qemu did not "
              "start, or started and printed nothing", file=sys.stderr)
        return 1
    output = LOG.read_text(encoding="utf-8", errors="replace")

    missing = [marker for marker in REQUIRED if marker not in output]
    present = [marker for marker in FORBIDDEN if marker in output]
    self_tests = output.count("self-test passed")

    if missing or present or self_tests < MINIMUM_SELF_TESTS:
        for marker in missing:
            print(f"  missing: {marker}", file=sys.stderr)
        for marker in present:
            print(f"  forbidden: {marker}", file=sys.stderr)
        if self_tests < MINIMUM_SELF_TESTS:
            print(f"  only {self_tests} self-tests passed, expected at least "
                  f"{MINIMUM_SELF_TESTS}", file=sys.stderr)
        print(f"whole boot saved to {LOG.relative_to(ROOT)}", file=sys.stderr)
        return 1

    print(f"qemu-riscv64-gate: booted to 100% on 4 harts with a login "
          f"prompt and sshd listening, {self_tests} self-tests passed, "
          f"no errors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
