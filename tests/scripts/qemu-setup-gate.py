#!/usr/bin/env python3
"""Set a machine up the way a person does, and check it can then be used.

Every other gate boots an image that already has an account, because every
image used to package one. This boots an image that packages none -- which is
what a released image is -- and answers the questions setup asks, then checks
the machine that results is one somebody can log into.

That distinction is the whole point. A setup routine that runs, prints
plausible things and produces a machine with no usable account would pass any
check that only looked at setup's own output, and it would be exactly as
broken as no setup routine at all. So the assertions here are about the
machine afterwards: the name on its login prompt, the password opening a
shell, and a command in that shell being accepted rather than denied as an
unknown user.

The last one has failed for real. The command dispatcher caches which account
a machine has, boot self-tests filled that cache before the account existed,
and every command typed by the person who had just set the machine up was
refused. Setup looked perfect. Nothing but running a command in the resulting
shell would have caught it.

Input is driven by watching for each prompt rather than by sleeping. Under TCG
the PBKDF2 work takes tens of seconds and varies with the host, so a script
paced by wall clock answers a question that has not been asked yet and every
answer after it lands in the wrong field.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
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
WORK = BUILD / f"setup-gate{SUFFIX}"
REPORT = BUILD / f"qemu-setup-gate{SUFFIX}.json"

TIMEOUT_S = smoke_timeout(
    ARCH, int(os.environ.get("XAIOS_SETUP_GATE_TIMEOUT", "1500")))

# Setting a machine up is a conversation with a person, and the questions do
# not change with the instruction set. What changes is how the machine is
# started: which emulator, which firmware, which bus each volume hangs off,
# and -- on this board -- that the kernel is handed to the machine directly
# rather than found by a loader on the medium. All of that is named here so
# the conversation itself stays one script.
ARCHITECTURES = {
    "aarch64": {
        "qemu": "qemu-system-aarch64",
        "machine": ["-machine", "virt,gic-version=3", "-cpu", "cortex-a72"],
        "build": [["./scripts/build-image.sh"]],
        "boot_image": BUILD / "xaios-aarch64.img",
        "initfs": BUILD / "xaios-virtio-test.img",
        "firmware_code": (
            "/opt/homebrew/share/qemu/edk2-aarch64-code.fd",
            "/usr/local/share/qemu/edk2-aarch64-code.fd",
            "/usr/share/AAVMF/AAVMF_CODE.fd",
            "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd",
        ),
        "firmware_vars": (),
        # The medium carries a loader; firmware finds it and it finds the
        # kernel.
        "direct_kernel": None,
        "install_machine": ["-machine", "virt,gic-version=3",
                            "-cpu", "cortex-a72"],
        "rng": ["-device", "virtio-rng-device,bus=virtio-mmio-bus.3"],
        "net": ["-device",
                "virtio-net-device,netdev=net0,bus=virtio-mmio-bus.2"],
    },
    "riscv64": {
        "qemu": "qemu-system-riscv64",
        "machine": ["-machine", "virt", "-cpu", "rv64", "-bios", "default"],
        "build": [["./scripts/build-riscv64.sh"],
                  ["./scripts/build-riscv64-image.sh"]],
        "boot_image": BUILD / "xaios-riscv64.img",
        "initfs": BUILD / "xaios-riscv64-initfs.img",
        "firmware_code": ("/opt/homebrew/share/qemu/edk2-riscv-code.fd",
                          "/usr/share/qemu/edk2-riscv-code.fd"),
        "firmware_vars": ("/opt/homebrew/share/qemu/edk2-riscv-vars.fd",
                          "/usr/share/qemu/edk2-riscv-vars.fd"),
        # SBI hands the kernel over; there is no loader in the way for the
        # run-from-the-medium half. The install half needs one, and gets
        # firmware instead.
        "direct_kernel": BUILD / "kernel-riscv64" / "kernel.elf",
        "install_machine": ["-machine", "virt,acpi=off", "-cpu", "rv64"],
        "rng": ["-device", "virtio-rng-pci,disable-legacy=on"],
        "net": ["-device", "virtio-net-pci,netdev=net0,disable-legacy=on"],
    },
}
PROFILE = ARCHITECTURES[ARCH]

HOSTNAME = "rackbox"
USERNAME = "operator"
PASSWORD = "sw0rdfish99"
PIN = "246813"

# What to say, and what to wait for before saying it. Waiting for the prompt
# is what makes this deterministic: the guest decides when it is ready.
SCRIPT: list[tuple[str, str]] = [
    ("Choose [1/2]: ", "1"),
    ("Hostname [xaios]: ", HOSTNAME),
    ("Username: ", USERNAME),
    ("Password: ", PASSWORD),
    ("Repeat password: ", PASSWORD),
    ("Set a quick login PIN? [y/N]: ", "y"),
    ("PIN (6 digits): ", PIN),
    ("Repeat PIN: ", PIN),
    ("Allow logging in over SSH? [Y/n]: ", "y"),
    ("Log in automatically on this console? [y/N]: ", "n"),
    # Setup has finished; the machine now asks who is there.
    (f"{HOSTNAME} login: ", USERNAME),
    ("Password: ", PASSWORD),
    # A command, because a shell that cannot run one is not a usable machine.
    ("$ ", "xaiosctl version"),
]


def build_image() -> None:
    """Build an image that packages no account, which is what a release is."""
    environment = dict(os.environ)
    environment["XAIOS_BOOT_TEST_APPS"] = "1"
    # "none" is what asks for a development image with no packaged credential;
    # without it every development build has one and setup never runs.
    environment["XAIOS_SSH_USERS_FILE"] = "none"
    for command in PROFILE["build"]:
        subprocess.run(command, cwd=ROOT, env=environment, check=True,
                       stdout=subprocess.DEVNULL)


def firmware() -> str | None:
    for candidate in PROFILE["firmware_code"]:
        if Path(candidate).is_file():
            return candidate
    return None


def firmware_vars() -> str | None:
    """A writable copy of the variable store, where the firmware keeps one.

    EDK2 on RISC-V writes its boot variables to a second pflash unit. Copied
    per run: the file belongs to whatever installed QEMU, and a gate that
    edits it in place changes every later run on the host.
    """
    for candidate in PROFILE["firmware_vars"]:
        if Path(candidate).is_file():
            target = WORK / "vars.fd"
            WORK.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(candidate, target)
            return str(target)
    return None


def build_unified() -> Path:
    """The image a USB stick actually carries, built with no account.

    The install run needs this rather than the test bench's boot image. That
    one is a bare FAT filesystem with no partition table, so it has no EFI
    System Partition -- and an install copies from one. A machine booted from
    it has nothing to install *from*, which is a fact about the bench and not
    about the installer, and testing against it would only ever prove the
    installer refuses what it should refuse."""
    environment = dict(os.environ)
    environment["XAIOS_SSH_USERS_FILE"] = "none"
    # One image carries all three architectures' loaders and kernels, so the
    # same file is what a RISC-V machine installs from too.
    subprocess.run(["make", "unified-image"], cwd=ROOT, env=environment,
                   check=True, stdout=subprocess.DEVNULL)
    number = (ROOT / "BUILD_NUMBER").read_text().strip()
    return BUILD / f"xaios_b{number}.iso"


def run(script: list, spare_disk: bool = False,
        image: Path | None = None) -> tuple[str, list[str]]:
    WORK.mkdir(parents=True, exist_ok=True)
    boot = WORK / "boot.img"
    initfs = WORK / "initfs.img"
    data = WORK / "data.img"
    # Each guest gets its own copy: two emulators cannot open one image, and
    # a leftover from a previous run boots a machine that is already set up.
    shutil.copyfile(image if image is not None else PROFILE["boot_image"],
                    boot)
    shutil.copyfile(PROFILE["initfs"], initfs)
    data.unlink(missing_ok=True)
    with data.open("wb") as sink:
        sink.truncate(64 * 1024 * 1024)

    unified = image is not None
    # Firmware for the install run, which has to find a loader on the medium.
    # The run-from-the-medium half on this board needs none: SBI hands the
    # kernel over directly, which is how every other RISC-V gate starts a
    # machine and is what a person setting one up here would see.
    direct = PROFILE["direct_kernel"] if not unified else None
    command = [PROFILE["qemu"]]
    if direct is not None:
        command += [*PROFILE["machine"], "-smp", "4", "-m", "2048",
                    "-global", "virtio-mmio.force-legacy=false",
                    "-kernel", str(direct)]
    else:
        code = firmware()
        if code is None:
            raise SystemExit(
                f"no UEFI firmware found for {ARCH}; install qemu")
        command += [*PROFILE["install_machine"], "-smp", "4", "-m", "2048",
                    "-global", "virtio-mmio.force-legacy=false",
                    "-drive",
                    f"if=pflash,format=raw,unit=0,readonly=on,file={code}"]
        variables = firmware_vars()
        if variables is not None:
            command += ["-drive",
                        f"if=pflash,format=raw,unit=1,file={variables}"]
    command += [
        "-drive", f"if=none,format=raw,readonly=on,id=xaios,file={boot}",
        "-device", "virtio-blk-pci,drive=xaios,bootindex=0",
    ]
    if not unified:
        # The bench attaches every volume as its own device.
        command += [
            "-drive", f"if=none,format=raw,id=t0,file={initfs}",
            "-device", "virtio-blk-device,drive=t0,bus=virtio-mmio-bus.0",
            "-drive", f"if=none,format=raw,id=t1,file={data}",
            "-device", "virtio-blk-device,drive=t1,bus=virtio-mmio-bus.1",
        ]
    command += [
        # Setup refuses to mint a credential without secure entropy, which is
        # correct and means the machine needs a source of it.
        *PROFILE["rng"],
        "-netdev", "user,id=net0",
        *PROFILE["net"],
        "-display", "none", "-serial", "mon:stdio",
    ]

    if spare_disk:
        # Slot 5 is where the storage layer attaches a scratch device, which
        # is the disk an install can be offered. Blank, so the install is a
        # real one rather than a rewrite of something already formatted.
        target = WORK / "target.img"
        target.unlink(missing_ok=True)
        with target.open("wb") as sink:
            sink.truncate(256 * 1024 * 1024)
        command += [
            "-drive", f"if=none,format=raw,id=t5,file={target}",
            "-device", "virtio-blk-device,drive=t5,bus=virtio-mmio-bus.5",
        ]

    log = WORK / "console.log"
    log.unlink(missing_ok=True)
    transcript: list[str] = []
    process = subprocess.Popen(
        command, cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, start_new_session=True)

    # Two buffers on purpose. `pending` is consumed as each prompt is matched,
    # so the same prompt string appearing again is a new question rather than
    # the one already answered. `full` keeps everything, because the checks
    # afterwards read the whole session and consuming the transcript to drive
    # it would leave nothing to check.
    full = ""
    pending = ""
    index = 0
    deadline = time.monotonic() + TIMEOUT_S
    try:
        os.set_blocking(process.stdout.fileno(), False)
        while index < len(script) and time.monotonic() < deadline:
            chunk = process.stdout.read(65536)
            if chunk:
                decoded = chunk.decode("utf-8", "replace")
                full += decoded
                pending += decoded
            elif process.poll() is not None:
                break
            else:
                time.sleep(0.05)
                continue
            expect, answer = script[index]
            if expect in pending:
                pending = pending.split(expect, 1)[1]
                transcript.append(expect)
                reply = answer(full) if callable(answer) else answer
                process.stdin.write((reply + "\n").encode())
                process.stdin.flush()
                index += 1
        # Let the last command produce its answer.
        settle = time.monotonic() + 60.0
        while time.monotonic() < settle and process.poll() is None:
            chunk = process.stdout.read(65536)
            if chunk:
                full += chunk.decode("utf-8", "replace")
            else:
                time.sleep(0.05)
    finally:
        if process.poll() is None:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            process.wait(timeout=30)
        remainder = process.stdout.read() or b""
        full += remainder.decode("utf-8", "replace")

    # The transcript is written whole, because a failure here is read by
    # somebody trying to work out which question went unanswered.
    log.write_text(full)
    return full, transcript


# The install run answers from what the machine prints, because the disk to
# install onto and the identity that confirms it are facts about this machine
# rather than constants a script can carry.
DEVICE = re.compile(r"device=(/dev/\S+).*?read_only=(\d+)", re.S)
GUID = re.compile(r"disk_guid=(\S+)")


def pick_target(text: str) -> str:
    """The blank disk, which is the last writable one the machine listed.

    Not the medium being booted from, which is read-only and which the
    installer refuses anyway -- picking it would test the refusal rather than
    the install."""
    devices = [name for name, read_only in DEVICE.findall(text)
               if read_only == "0"]
    return devices[-1] if devices else ""


def pick_guid(text: str) -> str:
    found = GUID.findall(text)
    return found[-1] if found else ""


INSTALL_SCRIPT: list = [
    ("Choose [1/2]: ", "2"),
    ("Disk to install onto (blank to cancel): ", pick_target),
    ("disk_guid: ", pick_guid),
    # Empty: accept the partition the machine says it booted from. Typing one
    # would be testing this script's idea of the topology rather than the
    # machine's.
    ("EFI partition to copy from: ", ""),
]


def main() -> int:
    build_image()

    failures: list[str] = []
    checks: list[dict] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "passed": bool(ok), "detail": detail})
        if not ok:
            failures.append(name)

    # ---- setting a machine up to run as it booted
    text, answered = run(SCRIPT)
    unanswered = [prompt for prompt, _ in SCRIPT[len(answered):]]
    check("every question setup asked was answered", not unanswered,
          "never reached: " + ", ".join(repr(p) for p in unanswered[:3]))
    check("setup offered running from the medium or installing",
          "Install onto a disk" in text)
    check("the kernel installed the account", "setup: account installed" in text)
    check("the kernel installed the quick login",
          "setup: quick login installed" in text)
    check("the machine took the name it was given",
          f"{HOSTNAME} login: " in text)
    check("the password opened a shell",
          "XAIOS local console session opened" in text)
    check("the shell names the account and the machine",
          re.search(rf"{USERNAME}@{HOSTNAME}", text) is not None)
    check("a command in that shell ran",
          "Build" in text and "unknown-user" not in text.split(
              "XAIOS local console session opened", 1)[-1],
          "the dispatcher refused the account that had just been created")
    check("the login prompt never asked twice", "Login incorrect" not in text)
    check("nothing crashed",
          "CYAN SCREEN OF DEATH" not in text and "assertion failed" not in text)

    # ---- installing onto a disk from the same menu
    install_text, install_answered = run(INSTALL_SCRIPT, spare_disk=True,
                                         image=build_unified())
    install_unanswered = [p for p, _ in INSTALL_SCRIPT[len(install_answered):]]
    check("the install asked for a disk, its identity and a source",
          not install_unanswered,
          "never reached: " + ", ".join(repr(p) for p in install_unanswered[:3]))
    check("the install named a disk to install onto",
          pick_target(install_text) != "",
          "the machine listed no writable disk")
    check("the install wrote a partition table and a filesystem",
          "install: " in install_text and "Installed." in install_text,
          "the install did not report finishing")
    check("the install did not crash",
          "CYAN SCREEN OF DEATH" not in install_text and
          "assertion failed" not in install_text)

    REPORT.write_text(json.dumps(
        {"schema": "xaios.setup.v1", "architecture": ARCH,
         "hostname": HOSTNAME,
         "username": USERNAME, "checks": checks, "failures": failures,
         "passed": not failures, "console": str(WORK / "console.log")},
        indent=2) + "\n")

    for entry in checks:
        mark = "ok  " if entry["passed"] else "FAIL"
        suffix = f" -- {entry['detail']}" if entry["detail"] and not entry[
            "passed"] else ""
        print(f"  {mark} {entry['name']}{suffix}")
    if failures:
        print(f"setup-gate: {len(failures)} failed; console at "
              f"{WORK / 'console.log'}")
        return 1
    print("setup-gate: a machine with no account was set up by hand, the "
          "account it was given works, and the same menu installed onto a "
          "disk")
    print(f"setup-gate: passed report={REPORT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
