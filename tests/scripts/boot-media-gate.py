#!/usr/bin/env python3
"""Check the hardware kits against what their READMEs tell people to do.

`vm-package-gate` boots each virtual-machine kit out of its own archive, which
is the strongest thing a gate can say about a kit: the thing that was
downloaded starts. Neither kit here can be tested that way *end to end*.
Booting the USB kit means a physical stick in a physical machine, and booting
the netboot kit the way a netboot kit is used means firmware fetching from a
server on a real network -- and a gate that pretended otherwise would be worse
than none, because it would read as evidence.

One part of that was conceded too early. The shipped netboot binaries had
never been started at all, because `qemu-netboot-gate` deliberately boots a
different binary: its stages need a boot-time install self-test that no
shipped image may carry. The fetch cannot be tested here, but everything after
the fetch can -- a netbooted machine runs the same image from memory that a
medium would hand it -- so this now puts each shipped binary on an EFI System
Partition and requires it to reach a login. What remains untested is firmware
fetching it, not the binary.

There are six kits rather than two, because a release is one image per
architecture and so are the kits built from it. That is what makes the RISC-V
netboot binary reachable here: while the netboot kit was one directory holding
several binaries, this gate named one of them and started only that.

So this checks the half that does live here, and says plainly that it is a
half. Two things go wrong with a kit without anyone noticing, and neither needs
hardware to catch:

  * A file is missing, or is not the file the release note gives a checksum
    for. Both kits carry the image or the binaries that were gated elsewhere;
    shipping something else is a packaging fault, and it is silent.
  * A script's own instructions have rotted -- it no longer runs, or the
    command it exists to wrap is no longer spelled the way the README spells
    it.

What this does not check: that a stick boots, that dnsmasq serves, or that any
firmware anywhere accepts these files. See release/xaios_b<n>.md.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
RELEASE = ROOT / "release"
STAGE = BUILD / "boot-media"
REPORT = BUILD / "boot-media-gate.json"

BUILD_NUMBER = (ROOT / "BUILD_NUMBER").read_text().strip()

# One architecture, one pair of kits. A release used to be a single image and
# so were these: one USB kit and one netboot kit, the latter carrying two
# binaries in one directory. The split makes each kit about one machine, which
# is also what lets this gate boot each shipped netboot binary rather than only
# the one architecture that happened to be first in the directory.
ARCHS = ("aarch64", "x86_64", "riscv64")
LOADER_NAME = {"aarch64": "BOOTAA64.EFI",
               "x86_64": "BOOTX64.EFI",
               "riscv64": "BOOTRISCV64.EFI"}


def image_name(arch: str) -> str:
    return f"xaios_b{BUILD_NUMBER}-{arch}.iso"

# The PE sections that make a netboot image a whole system rather than a
# loader. A binary missing any one of them boots and then asks firmware for a
# file that network boot will never give it.
NETBOOT_SECTIONS = (".xaiosl", ".xaiosk", ".xaiosi", ".xaiose")

# What each kit has to contain. Anything else in the archive is fine; these
# are the files the READMEs tell a person to use.
REQUIRED = {}
for _arch in ARCHS:
    REQUIRED[f"xaios_b{BUILD_NUMBER}-{_arch}-usb"] = (
        image_name(_arch), "write-usb.sh", "README.md", "SHA256SUMS")
    REQUIRED[f"xaios_b{BUILD_NUMBER}-{_arch}-netboot"] = (
        LOADER_NAME[_arch], "serve-netboot.sh", "README.md", "SHA256SUMS")


# The firmware each machine needs to launch a loader from a medium, and the
# QEMU it needs to be. Kept here rather than borrowed from platform/qemu
# because those runners boot a kernel this gate is deliberately not using: the
# claim is about the binary in the kit, started the way firmware starts it.
FIRMWARE = {
    "aarch64": ("/opt/homebrew/share/qemu/edk2-aarch64-code.fd",
                "/usr/local/share/qemu/edk2-aarch64-code.fd",
                "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd",
                "/usr/share/edk2/aarch64/QEMU_EFI.fd"),
    "x86_64": ("/opt/homebrew/share/qemu/edk2-x86_64-code.fd",
               "/usr/local/share/qemu/edk2-x86_64-code.fd",
               "/usr/share/OVMF/OVMF_CODE.fd",
               "/usr/share/ovmf/OVMF.fd"),
    "riscv64": ("/opt/homebrew/share/qemu/edk2-riscv-code.fd",
                "/usr/local/share/qemu/edk2-riscv-code.fd",
                "/usr/share/qemu/edk2-riscv-code.fd",
                "/usr/share/qemu-efi-riscv64/RISCV_VIRT_CODE.fd"),
}
QEMU_BINARY = {"aarch64": "qemu-system-aarch64",
               "x86_64": "qemu-system-x86_64",
               "riscv64": "qemu-system-riscv64"}


def boot_shipped_binary(arch: str) -> tuple[bool | None, str]:
    """Boot the netboot binary this architecture's kit ships.

    `qemu-netboot-gate` boots an AArch64 binary, but not this one: its stages
    need a boot-time install self-test that no shipped image may carry, so the
    binary it proves is deliberately not the binary anybody downloads. That
    left the shipped one never having been started at all.

    It used to be that only the AArch64 one was started here, because the kit
    was one directory with two binaries in it and this function named one of
    them. Per-architecture kits make the other two addressable, which matters
    most for RISC-V: its netboot binary is the newest thing in the release and
    nothing had ever started it.

    Firmware fetching over a network still cannot be tested here. What can is
    the half after the fetch: put the binary on an EFI System Partition, as the
    medium stages do, and require it to reach a login. A netbooted machine runs
    the same image from memory, so a binary that cannot boot from a medium
    cannot boot from a server either.

    Returns (None, reason) when the tools to try are absent, so a machine
    without QEMU reports a skip rather than a failure.
    """
    binary = STAGE / f"xaios_b{BUILD_NUMBER}-{arch}-netboot" / LOADER_NAME[arch]
    if not binary.is_file():
        return None, f"the kit has no {LOADER_NAME[arch]} to boot"
    if shutil.which(QEMU_BINARY[arch]) is None:
        return None, f"{QEMU_BINARY[arch]} is not installed"
    for tool in ("mformat", "mmd", "mcopy"):
        if shutil.which(tool) is None:
            return None, f"{tool} is required to build the medium"
    firmware = next((path for path in FIRMWARE[arch] if Path(path).is_file()),
                    None)
    if firmware is None:
        return None, f"no UEFI firmware for {arch} found"

    medium = BUILD / f"boot-media-shipped-{arch}.img"
    medium.unlink(missing_ok=True)
    with medium.open("wb") as handle:
        handle.truncate(48 * 1024 * 1024)
    for command in (["mformat", "-i", str(medium), "-v", "XAIOSNET", "::"],
                    ["mmd", "-i", str(medium), "::/EFI", "::/EFI/BOOT"],
                    ["mcopy", "-i", str(medium), str(binary),
                     f"::/EFI/BOOT/{LOADER_NAME[arch]}"]):
        if subprocess.run(command, check=False, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode != 0:
            return None, f"could not build the medium: {command[0]}"

    log = BUILD / f"boot-media-shipped-{arch}.log"
    log.unlink(missing_ok=True)
    # The network device is named rather than left to QEMU.
    #
    # It used to be left out entirely, and the AArch64 boot reached "SSH
    # server: up and running" anyway -- because QEMU attaches a default NIC
    # when none is given, and on that board the default happened to be one
    # this image's driver binds. That is a check passing on an emulator
    # default it never mentions: change the default and it breaks for a reason
    # that has nothing to do with XAIOS, and on a board whose default the
    # driver does not bind it fails the same way for the opposite reason.
    #
    # RISC-V was where that showed: the binary booted to 90% and stopped at
    # "SSH service withheld; IPv4 network is not ready", which reads as a
    # broken netboot binary and was a missing flag. Each machine now gets the
    # interface its own kit launcher gives it -- MMIO bus 2 on the two boards
    # whose driver scans the MMIO windows first, PCI with disable-legacy=on
    # where that is the transport.
    net = ["-netdev", "user,id=n0"]
    if arch == "aarch64":
        machine = ["-machine", "virt,gic-version=3", "-cpu", "cortex-a72"]
        pflash = ["-drive",
                  f"if=pflash,format=raw,readonly=on,file={firmware}"]
        boot = ["-device", "virtio-blk-pci,drive=boot,bootindex=0"]
        net += ["-device",
                "virtio-net-device,netdev=n0,bus=virtio-mmio-bus.2"]
    elif arch == "x86_64":
        machine = ["-machine", "q35", "-cpu", "max"]
        pflash = ["-drive",
                  f"if=pflash,format=raw,readonly=on,file={firmware}"]
        boot = ["-device",
                "virtio-blk-pci,drive=boot,bootindex=0,disable-legacy=on"]
        net += ["-device", "virtio-net-pci,netdev=n0,disable-legacy=on"]
    else:
        # acpi=off: with ACPI on, this EDK2 build publishes no device tree, and
        # the RISC-V port reads its interrupt controller, timebase and virtio
        # window from one.
        machine = ["-machine", "virt,acpi=off", "-cpu", "rv64"]
        # EDK2 for RISC-V is a code image and a writable variable store, and
        # the two are a pair. The store is written on every boot, so this uses
        # a copy rather than the one the package manager installed.
        vars_source = Path(re.sub(r"-code\.fd$", "-vars.fd",
                                  re.sub(r"_CODE\.fd$", "_VARS.fd", firmware)))
        if not vars_source.is_file():
            return None, (f"found {firmware} but no variable store at "
                          f"{vars_source}; EDK2 ships the two together")
        vars_copy = BUILD / f"boot-media-shipped-{arch}-vars.fd"
        shutil.copy(vars_source, vars_copy)
        pflash = ["-drive",
                  f"if=pflash,format=raw,unit=0,readonly=on,file={firmware}",
                  "-drive", f"if=pflash,format=raw,unit=1,file={vars_copy}"]
        boot = ["-device",
                "virtio-blk-pci,drive=boot,bootindex=0,disable-legacy=on"]
        net += ["-device",
                "virtio-net-device,netdev=n0,bus=virtio-mmio-bus.2"]

    process = subprocess.Popen(
        [QEMU_BINARY[arch], *machine, "-smp", "4", "-m", "2048",
         "-global", "virtio-mmio.force-legacy=false",
         *pflash,
         "-drive", f"if=none,format=raw,readonly=on,id=boot,file={medium}",
         *boot, *net,
         "-display", "none", "-serial", f"file:{log}"],
        cwd=str(ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # A login prompt is the whole claim. Reaching it means the appended
    # sections were found and read, the kernel came up and userspace started.
    wanted = ("xaios login:", "SSH server: up and running (tcp/22)")
    # Only AArch64 runs on this host's own instruction set. The other two go
    # through an interpreter and take several times longer to reach the same
    # line; a timeout that suited one of them would report the other two as
    # broken.
    deadline = time.monotonic() + (240 if arch == "aarch64" else 720)
    seen = ""
    try:
        while time.monotonic() < deadline:
            time.sleep(2)
            seen = log.read_text(errors="replace") if log.is_file() else ""
            if all(marker in seen for marker in wanted):
                break
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
    missing = [marker for marker in wanted if marker not in seen]
    if missing:
        return False, f"never reached {missing!r}; log at {log}"
    return True, f"reached a login with SSH listening; log at {log}"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def objdump_sections(binary: Path) -> set[str]:
    for candidate in ("llvm-objdump", "/opt/homebrew/opt/llvm/bin/llvm-objdump",
                      "objdump"):
        try:
            result = subprocess.run([candidate, "-h", str(binary)],
                                    capture_output=True, text=True, check=True)
        except (FileNotFoundError, subprocess.CalledProcessError):
            continue
        return {name for name in NETBOOT_SECTIONS if name in result.stdout}
    return set()


def main() -> int:
    failures: list[str] = []
    checks: list[dict] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "passed": bool(ok), "detail": detail})
        if not ok:
            failures.append(f"{name}{': ' + detail if detail else ''}")

    for kit, required in REQUIRED.items():
        directory = STAGE / kit
        archive = RELEASE / f"{kit}.zip"

        if not directory.is_dir():
            check(f"{kit}: staged", False,
                  f"no {directory}; run make boot-media")
            continue
        check(f"{kit}: staged", True)

        for name in required:
            check(f"{kit}: carries {name}", (directory / name).is_file())

        # A script a person is told to run, that is not executable, is a
        # README that does not work.
        for script in directory.glob("*.sh"):
            import os
            check(f"{kit}: {script.name} is executable",
                  os.access(script, os.X_OK))

        # The kit's own SHA256SUMS has to describe the kit, or verifying a
        # download proves nothing about it.
        sums = directory / "SHA256SUMS"
        if sums.is_file():
            listed = {}
            for line in sums.read_text().splitlines():
                digest, _, name = line.partition("  ")
                if name:
                    listed[name] = digest
            mismatched = [name for name, digest in listed.items()
                          if not (directory / name).is_file()
                          or sha256(directory / name) != digest]
            check(f"{kit}: SHA256SUMS matches the files beside it",
                  not mismatched, ", ".join(mismatched[:4]))
            missing = [name for name in required
                       if name != "SHA256SUMS" and name not in listed]
            check(f"{kit}: SHA256SUMS covers every required file",
                  not missing, ", ".join(missing))

        if not archive.is_file():
            check(f"{kit}: archived", False, f"no {archive}")
            continue
        with zipfile.ZipFile(archive) as bundle:
            names = {Path(entry).name for entry in bundle.namelist()}
        check(f"{kit}: archive carries every required file",
              set(required) <= names,
              ", ".join(sorted(set(required) - names)))

    # Each USB kit ships its own architecture's image, and it has to be the
    # released one -- the file the release note gives a checksum for and the
    # gates booted.
    #
    # Checked against release/ rather than build/ on purpose, and reported as a
    # skip with its reason when release/ has no copy yet, because "the kit
    # matches the file the builder just made" is a much weaker statement than
    # "the kit matches the file that ships" and the two should not be allowed
    # to look alike.
    for arch in ARCHS:
        usb_image = STAGE / f"xaios_b{BUILD_NUMBER}-{arch}-usb" / image_name(arch)
        released = RELEASE / image_name(arch)
        if not usb_image.is_file():
            check(f"{arch} usb kit ships the released image", False,
                  "the kit has no image in it")
        elif not released.is_file():
            print(f"  skip {arch} usb kit ships the released image -- "
                  f"release/{image_name(arch)} does not exist yet; "
                  f"run make release-package")
        else:
            check(f"{arch} usb kit ships the released image",
                  sha256(usb_image) == sha256(released),
                  "the kit's copy is not the file in release/")

    # Every netboot binary has to be a whole system. One per architecture now:
    # the two that used to share a directory are in kits of their own, and
    # RISC-V has joined them.
    for arch in ARCHS:
        binary = LOADER_NAME[arch]
        path = STAGE / f"xaios_b{BUILD_NUMBER}-{arch}-netboot" / binary
        if not path.is_file():
            check(f"{binary}: carries its payload sections", False, "missing")
            continue
        found = objdump_sections(path)
        check(f"{binary}: carries its payload sections",
              found == set(NETBOOT_SECTIONS),
              "absent: " + ", ".join(sorted(set(NETBOOT_SECTIONS) - found)))

    # The install command is the reason both kits exist. If the client stops
    # spelling it this way, the READMEs are telling people to type something
    # that no longer works.
    client = (ROOT / "userspace/lib/xaios_control_client.c").read_text()
    for token, why in (('"install"', "the install verb"),
                       ('"--confirm-device"', "the confirmation flag"),
                       ('"from"', 'the "from" keyword the READMEs use')):
        check(f"the client still accepts {why}", token in client)

    for kit in REQUIRED:
        readme = STAGE / kit / "README.md"
        if readme.is_file():
            text = readme.read_text()
            check(f"{kit}: README gives the install command",
                  re.search(r"xaiosctl storage install", text) is not None)

    # Each architecture's shipped netboot binary, started the way firmware
    # starts it. An architecture whose tools are not on this machine is a skip
    # with its reason, never a pass.
    only = os.environ.get("XAIOS_BOOT_MEDIA_ONLY_ARCH")
    for arch in ARCHS:
        if only is not None and arch != only:
            continue
        booted, detail = boot_shipped_binary(arch)
        if booted is None:
            print(f"  skip the shipped {arch} netboot binary boots -- {detail}")
        else:
            check(f"the shipped {arch} netboot binary boots to a login",
                  booted, detail)

    REPORT.write_text(json.dumps(
        {"schema": "xaios.boot-media.v1", "build": BUILD_NUMBER,
         "checks": checks, "failures": failures, "passed": not failures},
        indent=2) + "\n")

    for entry in checks:
        print(f"  {'ok  ' if entry['passed'] else 'FAIL'} {entry['name']}"
              + (f" -- {entry['detail']}" if entry["detail"]
                 and not entry["passed"] else ""))
    if failures:
        print(f"boot-media-gate: {len(failures)} failed")
        return 1
    print(f"boot-media-gate: passed, {len(checks)} checks; this does not "
          f"establish that a stick boots or that a server serves")
    print(f"boot-media-gate: report written to {REPORT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
