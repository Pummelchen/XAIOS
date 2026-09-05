#!/usr/bin/env python3
"""Kill QEMU at system-metadata write points and prove reboot recovery.

Two architectures, because the code being tested is shared and the machine
under it is not. The A/B metadata writer, its backup-first ordering and the
durable filesystem's recovery are one implementation; what differs is the
block device it writes through, the cache the emulator keeps in front of it,
and -- on RISC-V -- the fact that the machine has to be started through UEFI
firmware for a system volume to have been chosen at all. A power-loss test
that only ever ran on one of those is a test of one driver.
"""

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
sys.path.insert(0, str(ROOT / "tests" / "scripts"))
from qemu_gate_lib import (arch_from_argv, qemu_boot_environment, qemu_runner,
                           smoke_timeout)

POINTS = ("system-backup-flushed", "system-primary-written")

# What "build a kernel armed to die at this point" means, per architecture.
#
# The crash points themselves are shared kernel code; only the switch that
# compiles them in, the kernel the signed slot is filled from, and the way the
# machine starts differ. RISC-V must boot through UEFI: with -kernel nothing
# has chosen a system slot, the guest logs "system-slot: unavailable", and
# this gate would pass having watched a machine that never wrote metadata.
ARCHITECTURES = {
    "aarch64": {
        "build": ["./scripts/build-image.sh"],
        "system": BUILD / "xaios-system.img",
        "kernel": "build/kernel/kernel.elf",
        "boot_mode": None,
    },
    "riscv64": {
        "build": ["./scripts/build-riscv64.sh"],
        "system": BUILD / "xaios-riscv64-system.img",
        "kernel": "build/kernel-riscv64/kernel.elf",
        "boot_mode": "uefi",
    },
}

# The durable volume, at both sizes that decide its format.
#
# xaibootFS formats v6 on a device with room for a gibibyte of data and v5 on
# anything smaller, and every profile in this tree creates the smaller one --
# so until now every power-loss trial this gate ran had been against a v5
# volume, and v6's extent records, its thousand nodes and its bit-packed
# bitmap had never been interrupted at all. Both, now: the format is chosen by
# the size, so asking for both sizes is what exercises both formats.
VOLUME_SIZES = (
    ("v5", 32768),
    ("v6", 2400000),
)
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
    arch: str, env: dict[str, str], targets: tuple[str, ...], timeout: int,
    hard: bool
) -> str:
    process = subprocess.Popen(
        [qemu_runner(arch)],
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
    # The whole boot, kept on disk, not just the end of it.
    #
    # This used to raise with the last four thousand characters and nothing
    # else. The filesystem mounts early, so on a failed recovery every line
    # explaining why had already scrolled out of that window by the time the
    # guest reached a login prompt -- which is exactly the failure this gate
    # exists to catch. B-23 sat undiagnosed behind it: the tail showed a
    # machine booting perfectly, with no way to tell a volume that was refused
    # from one that was silently reformatted.
    BUILD.mkdir(parents=True, exist_ok=True)
    failure_log = BUILD / "qemu-storage-crash-failure.log"
    failure_log.write_text(text, encoding="utf-8")
    #
    #
    # The excerpt is the mount, and only the mount. Keeping the whole log
    # fixed half the problem; the first attempt at this then printed the last
    # forty filesystem lines, which on a guest that boots to a shell are the
    # POSIX test tidying its scratch files -- the same uninformative tail,
    # filtered. Printing the first forty was no better: a small early volume
    # mounts before the persistent one and fills the window with itself.
    #
    # What actually answers the question is five lines out of three and a
    # half thousand, and a failed recovery is diagnosed by which of them are
    # missing: `persistent mounted v5 nodes=256` against `v6 nodes=1024` says
    # which format came back, and `no valid filesystem at sector=N; formatting`
    # says a volume was reformatted rather than refused. They are named
    # exactly rather than matched loosely -- a looser pass matched "slot" and
    # returned the ACPI CPU table.
    mount_lines = [line for line in text.splitlines() if any(
        token in line for token in
        ("xaibootfs: persistent", "xaibootfs: mounted",
         "xaibootfs: no valid", "xaibootfs: mirror",
         "xaibootfs: formatting"))]
    raise RuntimeError(
        f"QEMU did not reach {missing}; whole boot saved to {failure_log}\n"
        f"every mount decision in that boot -- which format came back, and\n"
        f"whether a volume was refused or silently reformatted:\n"
        + ("\n".join(mount_lines) if mount_lines else
           "  (none: the guest never reached a filesystem mount)")
        + "\nand where the boot stopped:\n"
        + "\n".join(text.splitlines()[-12:])
    )


def build_crash_image(arch: str, point: str, system_image: Path) -> None:
    profile = ARCHITECTURES[arch]
    shutil.copyfile(profile["system"], system_image)
    env = os.environ.copy()
    env["XAIOS_BOOT_TEST_APPS"] = "1"
    env["XAIOS_STORAGE_CRASH_POINT"] = point
    env["XAIOS_SYSTEM_VOLUME_IMAGE"] = str(system_image)
    run(profile["build"], env)
    create_env = os.environ.copy()
    create_env["PYTHONPATH"] = str(ROOT)
    run(
        [
            sys.executable,
            "tools/xaios_system_volume.py",
            "create",
            str(system_image),
            profile["kernel"],
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
    arch = arch_from_argv(sys.argv)
    if arch not in ARCHITECTURES:
        raise SystemExit(
            f"qemu-storage-crash: not ported to {arch}. The gate needs a "
            f"builder that takes XAIOS_STORAGE_CRASH_POINT and a boot path "
            f"that chooses a system slot; neither exists for {arch} yet.")
    profile = ARCHITECTURES[arch]
    # The injected commit point follows the deterministic diagnostic boot
    # workload. On TCG this may take materially longer than a normal service
    # boot, so retain a bounded but realistic per-boot deadline.
    # A v6 volume is a gibibyte of data region: formatting it and running fsck
    # over two million sectors under TCG takes materially longer than the same
    # boot against v5, and 240 seconds is not enough for it. The v5 passes are
    # unaffected -- this is a deadline, not a delay.
    #
    # RISC-V gets the same deadline scaled for the machine, not a different
    # one: it runs this closure through an interpreter with no acceleration
    # available, and reusing AArch64's numbers would report a slower machine
    # as a broken one.
    timeout = smoke_timeout(
        arch, int(os.environ.get("XAIOS_QEMU_STORAGE_CRASH_TIMEOUT", "720")))
    work = BUILD / "storage-crash" / arch
    work.mkdir(parents=True, exist_ok=True)
    try:
        for point in POINTS:
            print(f"qemu-storage-crash: preparing arch={arch} point={point}",
                  flush=True)
            system_image = work / f"{point}.img"
            for label, sectors in VOLUME_SIZES:
                # Rebuilt and re-armed for every pass, not once per point.
                # The crash point fires while the pending slot is being
                # committed, and the pass that crashes then recovers commits
                # it -- so a second pass against the same system volume finds
                # nothing pending, never reaches the point, and fails having
                # tested nothing. That is exactly how the first v6 run failed.
                build_crash_image(arch, point, system_image)
                persistent_image = work / f"{point}-persistent-{label}.img"
                persistent_image.unlink(missing_ok=True)
                env = os.environ.copy()
                # TCG on every architecture, deliberately: a hypervisor
                # writes through host page cache the emulator does not
                # control, and this gate's whole subject is what reached the
                # platter before the power went.
                env["XAIOS_QEMU_ACCEL"] = "tcg"
                env = qemu_boot_environment(
                    arch, env,
                    system_volume=system_image,
                    persistent=persistent_image,
                    persistent_sectors=sectors,
                    state_dir=work / f"{point}-{label}-state",
                    hostfwd_port="none",
                    boot_mode=profile["boot_mode"],
                    serial_to_stdout=True)
                marker = f"storage-crash: reached point={point}"
                # The volume has to have been formatted as the version this
                # pass is for, or the pass is a second v5 trial wearing a
                # label. The kill happens after the format, so the marker is
                # in the same boot.
                format_marker = f"formatting {label}"
                boot_until(arch, env, (marker, format_marker), timeout,
                           hard=True)
                validate_committed_metadata(system_image)
                print(f"qemu-storage-crash: power loss observed "
                      f"arch={arch} point={point} volume={label}", flush=True)
                boot_until(
                    arch,
                    env,
                    (
                        "system-slot: attached active=1 pending=4294967295",
                        "system-slot: self-test passed",
                        # And the durable volume came back rather than being
                        # reformatted, which is the claim a power-loss test on
                        # a filesystem is actually making.
                        "xaibootfs: persistent loaded",
                    ),
                    timeout,
                    hard=False,
                )
                print(f"qemu-storage-crash: recovered arch={arch} "
                      f"point={point} volume={label}", flush=True)
    finally:
        # The tree is left holding a kernel that dies on purpose otherwise,
        # and the next gate to run would inherit it.
        restore_env = os.environ.copy()
        restore_env["XAIOS_BOOT_TEST_APPS"] = "1"
        restore_env.pop("XAIOS_STORAGE_CRASH_POINT", None)
        restore_env.pop("XAIOS_SYSTEM_VOLUME_IMAGE", None)
        run(profile["build"], restore_env)
    print(f"qemu-storage-crash: all metadata kill points recovered on "
          f"v5 and v6 durable volumes ({arch})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
