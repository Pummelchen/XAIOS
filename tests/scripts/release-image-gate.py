#!/usr/bin/env python3
"""Boot each released image on every environment that can run it.

A release is three files now, one per architecture, each a single image meant
to boot as optical media, as a disk, or from a USB stick. Between them they
cover five environments -- QEMU on three architectures, VMware Fusion, Apple
Virtualization.framework. Nothing checked that until this gate existed: the
per-platform gates each boot their own per-platform image, built for the
occasion, so every one of them can pass while the files a release actually
contains boot nothing at all.

That is not hypothetical. Getting the AArch64 image to boot on Fusion turned on
a detail no per-platform gate would ever have exercised -- the name of the
kernel file -- and the x86_64 image asserted on a device self-test that does
not apply when the initial filesystem arrives on the boot medium rather than as
a separate drive. Both were found by hand, once, and nothing would have caught
either coming back.

The images used to be one file carrying all three architectures. Splitting them
changed what this gate must be careful about rather than removing the need for
it: each environment now has its own medium to be stale, missing or built from
the wrong tree, so each is resolved and checked separately below. An
architecture whose image was never built is reported as such and fails, because
a release that is short an image is the failure this gate is for.

What this checks is deliberately shallower than the per-platform gates: that
each shipped file boots its environments to a working system. Depth is their
job. Breadth is this one's.

Environments that cannot run here are reported as skipped, never as passed. A
gate that quietly counts an absent hypervisor as a success is worse than one
that fails, because it reads as evidence.
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
def _build_number() -> str:
    """The build this tree produces, so the gate looks for the right file."""
    try:
        return (ROOT / "BUILD_NUMBER").read_text(encoding="utf-8").strip()
    except OSError:
        return "0"


# Each architecture's own image, and an override per architecture rather than
# one for "the image": there is no longer a single file to point at, and a
# variable that names one would silently apply to whichever environment asked
# last.
def image_for(arch: str) -> Path:
    override = os.environ.get(f"XAIOS_RELEASE_IMAGE_{arch.upper()}")
    if override:
        return Path(override)
    return BUILD / f"xaios_b{_build_number()}-{arch}.iso"


# What each architecture's image is built from. Checked against the image's own
# timestamp before that image is booted; see staleness().
SOURCES = {
    "aarch64": (BUILD / "kernel" / "kernel.elf",
                BUILD / "xaios-virtio-test.img",
                BUILD / "uefi" / "BOOTAA64.EFI"),
    "x86_64": (BUILD / "kernel-x86_64" / "kernel.elf",
               BUILD / "xaios-x86-virtio-test.img",
               BUILD / "uefi-x86_64" / "BOOTX64.EFI"),
    "riscv64": (BUILD / "kernel-riscv64" / "kernel.elf",
                BUILD / "xaios-riscv64-initfs.img",
                BUILD / "riscv64-uefi" / "BOOTRISCV64.EFI"),
}
VZ = BUILD / "vz"
FUSION_VM = BUILD / "vmware-fusion" / "XAIOS.vmwarevm"
REPORT = BUILD / "release-image-gate.json"
VMRUN = Path(os.environ.get(
    "XAIOS_FUSION_VMRUN",
    "/Applications/VMware Fusion.app/Contents/Library/vmrun"))

# The common ground: what every environment says when this image works. The
# per-platform gates assert far more, and should -- device inventories differ,
# so a marker list long enough to be thorough here would be five lists.
EXPECTED = (
    ("kernel started", re.compile(r"XAIOS Build \d+ kernel starting")),
    ("shell command surface",
     re.compile(r"/bin/xaios-shell: command surface passed")),
    ("SSH server listening", re.compile(r"SSH server: up and running")),
)

FORBIDDEN = (
    ("kernel panic", re.compile(r"CYAN SCREEN OF DEATH")),
    ("assertion failure", re.compile(r"ERROR: assertion failed")),
    ("booted into rescue mode",
     re.compile(r"lifecycle initialized[^\n]*rescue=1")),
)


def settled(text: str) -> bool:
    if any(pattern.search(text) for _, pattern in FORBIDDEN):
        return True
    return all(pattern.search(text) for _, pattern in EXPECTED)


def run_until_settled(command, log_path, timeout_s, environment=None):
    """Run a boot, stop as soon as it has said enough, and return its output."""
    with log_path.open("wb") as handle:
        process = subprocess.Popen(command, stdout=handle,
                                   stderr=subprocess.STDOUT,
                                   stdin=subprocess.DEVNULL,
                                   env=environment, cwd=str(ROOT))
        deadline = time.monotonic() + timeout_s
        try:
            while time.monotonic() < deadline:
                time.sleep(5)
                if settled(log_path.read_bytes().decode("utf-8", "replace")):
                    break
                if process.poll() is not None:
                    break
        finally:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
    return log_path.read_bytes().decode("utf-8", "replace")


def fresh_state(name: str) -> Path:
    """A scratch directory of this gate's own, emptied per run.

    RISC-V keeps its writable volumes in a directory rather than naming each
    one; a leftover from a previous run boots a machine that is already set
    up, which is not what booting a release image should show.
    """
    directory = BUILD / name
    shutil.rmtree(directory, ignore_errors=True)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def fresh_persistent(name: str) -> Path:
    """A durable volume of this gate's own, regenerated per run.

    The shared build/xaios-persistent.img carries the lifecycle record, and
    rescue mode is latched by a marker file on it. Every gate that boots writes
    to it, and enough hard power-offs -- which is how gates end -- set that
    marker. After it is set the guest still boots, mounts and listens, and
    refuses ordinary commands, so this gate would report a failure caused by
    how many times unrelated gates had run. It found exactly that on its first
    execution.
    """
    image = BUILD / name
    image.unlink(missing_ok=True)
    subprocess.run([str(ROOT / "scripts/create-persistent-image.sh")],
                   env={**os.environ, "XAIOS_PERSISTENT_IMAGE": str(image)},
                   check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)
    return image


def boot_qemu(arch: str) -> tuple[str, str | None]:
    runner = ROOT / "platform" / "qemu" / f"run-qemu-{arch}.sh"
    if not runner.is_file():
        return "", f"missing {runner.relative_to(ROOT)}"
    # The two runners name both of these differently, and setting only the
    # AArch64 spelling left x86_64 booting the shared durable volume -- which
    # was already in rescue mode, so the gate failed on state rather than on
    # the image. Set the pair each runner actually reads.
    # Boot a copy, never the artifact. The x86_64 guest writes to the medium
    # it booted from -- its virtio-blk self-test exercises write, error and
    # reset against device zero -- so pointing a runner at a release image
    # changes that image. It was noticed when a release checksum moved between
    # being gated and being published, and the file that had been verified was
    # no longer the file on disk. Copying costs a second and makes "this exact
    # file booted" true rather than nearly true.
    scratch = BUILD / f"release-boot-{arch}.img"
    shutil.copy(image_for(arch), scratch)
    image_variable = {"aarch64": "XAIOS_AARCH64_IMAGE",
                      "x86_64": "XAIOS_X86_64_IMAGE",
                      "riscv64": "XAIOS_RISCV64_IMAGE"}[arch]
    persistent_variable = ("XAIOS_X86_PERSISTENT_IMAGE" if arch == "x86_64"
                           else "XAIOS_PERSISTENT_IMAGE")
    environment = {**os.environ, image_variable: str(scratch),
                   persistent_variable:
                       str(fresh_persistent(f"release-{arch}-persistent.img")),
                   # No A/B system volume, which is the whole point.
                   #
                   # The loader prefers a verified slot over the kernel on the
                   # medium, so with the tree's own system volume attached this
                   # gate booted the image's *loader* and then a kernel from
                   # build/ -- "XAIOS loader loaded verified A/B system slot"
                   # is in every log it ever produced. A first boot on a real
                   # machine has no such volume, and taking it away is what
                   # makes "this image boots" true rather than nearly true.
                   "XAIOS_SYSTEM_VOLUME_IMAGE": "none"}
    if arch == "riscv64":
        # This board is started from the ELF unless told otherwise; the point
        # here is the medium, so it boots through firmware like the others.
        environment["XAIOS_RISCV64_BOOT"] = "uefi"
        environment["XAIOS_RISCV64_SERIAL"] = "stdio"
        environment["XAIOS_RISCV64_STATE"] = str(
            fresh_state(f"release-{arch}-state"))
    # x86_64 has no hardware acceleration on an ARM host, so it boots through
    # an interpreter and takes several times longer than anything else here.
    timeout = int(os.environ.get(
        "XAIOS_RELEASE_QEMU_TIMEOUT",
        "540" if arch in ("x86_64", "riscv64") else "240"))
    log = BUILD / f"release-qemu-{arch}.log"
    return run_until_settled([str(runner)], log, timeout, environment), None


def boot_vz() -> tuple[str, str | None]:
    harness = VZ / "xaios-vz"
    if sys.platform != "darwin":
        return "", "needs macOS"
    if not harness.is_file():
        return "", "harness missing; run make vz-harness"
    # The image is the boot disk. The data volumes stay separate, which is the
    # arrangement this image is designed for: it is read-only, and the durable
    # filesystem has to live somewhere writable.
    volumes = ["vz-test.img", "vz-persistent.img", "vz-model.img",
               "vz-storage-admin.img", "vz-system.img", "vz-system2.img"]
    for name in volumes:
        if not (VZ / name).is_file():
            return "", f"missing {name}; run make vz-gate once to create the volumes"
    boot_disk = VZ / "release-boot.img"
    shutil.copy(image_for("aarch64"), boot_disk)
    shutil.copy(fresh_persistent("release-vz-persistent.img"),
                VZ / "vz-persistent.img")
    command = [str(harness), str(boot_disk)] + [str(VZ / v) for v in volumes]
    command += ["--memory-mib", "2048", "--cpus", "4"]
    log = BUILD / "release-vz.log"
    return run_until_settled(command, log, 240), None


def boot_fusion() -> tuple[str, str | None]:
    if sys.platform != "darwin":
        return "", "needs macOS"
    if not VMRUN.is_file():
        return "", "VMware Fusion is not installed"
    vmx = FUSION_VM / "XAIOS.vmx"
    if not vmx.is_file():
        return "", "no VM bundle; run make vmware-fusion-image once"

    # Fusion boots this as optical media, so the image goes in the bundle and
    # the VM is pointed at it. The original setting is restored afterwards
    # whatever happens -- leaving a developer's VM pointed at a gate artifact
    # would be a rude thing for a test to do.
    # A fresh data disk, for the reason vz-gate builds a fresh durable volume:
    # the lifecycle record lives on it and rescue mode is latched by a marker
    # there, so enough hard stops -- which is how every gate run ends -- put
    # the guest into a state where it boots, mounts, listens and refuses
    # ordinary commands. This gate inherited whatever previous runs left, and
    # eventually reported a failure caused by how often it had been run.
    data_disk = FUSION_VM / "xaios-fusion.vmdk"
    manager = Path(os.environ.get(
        "XAIOS_FUSION_VDISK_MANAGER",
        "/Applications/VMware Fusion.app/Contents/Library/vmware-vdiskmanager"))
    if manager.is_file():
        for stale in FUSION_VM.glob("xaios-fusion*.vmdk"):
            stale.unlink(missing_ok=True)
        subprocess.run(
            [str(manager), "-c", "-s", "256MB", "-a", "lsilogic", "-t", "0",
             str(data_disk)],
            check=False, capture_output=True, timeout=120)

    staged = FUSION_VM / "release-gate.iso"
    shutil.copy(image_for("aarch64"), staged)
    original = vmx.read_text(encoding="utf-8")
    serial = FUSION_VM / "fusion-serial.log"
    try:
        vmx.write_text(
            re.sub(r'sata0:0\.fileName = "[^"]*"',
                   'sata0:0.fileName = "release-gate.iso"', original),
            encoding="utf-8")
        serial.unlink(missing_ok=True)
        subprocess.run([str(VMRUN), "-T", "fusion", "start", str(vmx), "nogui"],
                       check=False, capture_output=True, timeout=120)
        deadline = time.monotonic() + int(
            os.environ.get("XAIOS_RELEASE_FUSION_TIMEOUT", "240"))
        text = ""
        while time.monotonic() < deadline:
            time.sleep(5)
            if serial.is_file():
                text = serial.read_bytes().decode("utf-8", "replace")
                if settled(text):
                    break
        return text, None
    finally:
        subprocess.run([str(VMRUN), "-T", "fusion", "stop", str(vmx), "hard"],
                       check=False, capture_output=True, timeout=120)
        vmx.write_text(original, encoding="utf-8")
        staged.unlink(missing_ok=True)


# Environment, the architecture whose image it boots, and how to boot it.
#
# The architecture is here rather than inferred from the name because two of
# these are not named for one. VMware Fusion and Virtualization.framework both
# run AArch64 guests on this host, so both boot the AArch64 image; an x86-64 or
# RISC-V guest here would be emulation, which is what the QEMU entries are.
ENVIRONMENTS = (
    ("qemu-aarch64", "aarch64", lambda: boot_qemu("aarch64")),
    ("qemu-x86_64", "x86_64", lambda: boot_qemu("x86_64")),
    ("qemu-riscv64", "riscv64", lambda: boot_qemu("riscv64")),
    ("virtualization-framework", "aarch64", boot_vz),
    ("vmware-fusion", "aarch64", boot_fusion),
)


def staleness(arch: str) -> str | None:
    """Whether this architecture's image is older than what it should contain.

    make release-image-gate rebuilds the images first; running this script
    directly does not, and then it tests whatever is on disk. That is how an
    hour went into diagnosing three Fusion failures that were a stale image and
    nothing else -- the guest under test was not the code under test. Refuse
    rather than report a result about the wrong bytes.

    Per architecture, because the images are per architecture: rebuilding one
    used to refresh the timestamp that vouched for all three, so a stale RISC-V
    payload was covered by an AArch64 build that had nothing to do with it.
    """
    image = image_for(arch)
    if not image.is_file():
        return (f"{image} is missing; a release is short its {arch} image "
                f"and this gate cannot say anything about it")
    built = image.stat().st_mtime
    for source in SOURCES[arch]:
        if source.is_file() and source.stat().st_mtime > built:
            return (f"{image.name} is older than "
                    f"{source.relative_to(BUILD)}, so it does not contain it")
    return None


def main() -> int:
    only = os.environ.get("XAIOS_RELEASE_ONLY")
    selected = [e for e in ENVIRONMENTS if only is None or e[0] == only]

    # Every image this run will touch, checked before any of them is booted.
    # Finding the third image stale after two twenty-minute boots is the same
    # answer an hour later.
    stale = []
    for arch in dict.fromkeys(arch for _, arch, _ in selected):
        reason = staleness(arch)
        if reason is not None:
            stale.append((arch, reason))
    if stale:
        for arch, reason in stale:
            print(f"release-image-gate: {reason}")
            print(f"  Run: make release-image-{arch}")
        return 1

    results = []
    for name, arch, boot in selected:
        text, unavailable = boot()
        if unavailable is not None:
            results.append({"environment": name, "architecture": arch,
                            "image": str(image_for(arch)),
                            "status": "skipped", "reason": unavailable})
            print(f"  skip {name}: {unavailable}")
            continue
        checks = [{"name": label, "passed": bool(pattern.search(text))}
                  for label, pattern in EXPECTED]
        faults = [{"name": label, "seen": bool(pattern.search(text))}
                  for label, pattern in FORBIDDEN]
        passed = all(c["passed"] for c in checks) and \
            not any(f["seen"] for f in faults)
        results.append({"environment": name, "architecture": arch,
                        "image": str(image_for(arch)),
                        "status": "passed" if passed else "failed",
                        "checks": checks, "faults": faults})
        print(f"  {'ok  ' if passed else 'FAIL'} {name}")
        if not passed:
            for check in checks:
                if not check["passed"]:
                    print(f"       missing: {check['name']}")
            for fault in faults:
                if fault["seen"]:
                    print(f"       fault:   {fault['name']}")

    ran = [r for r in results if r["status"] != "skipped"]
    passed = bool(ran) and all(r["status"] == "passed" for r in ran)
    REPORT.write_text(json.dumps({
        "images": {arch: str(image_for(arch))
                   for arch in dict.fromkeys(a for _, a, _ in selected)},
        "qualification_evidence": False,
        "environments": results,
        "passed": passed,
    }, indent=2) + "\n", encoding="utf-8")
    print(f"release-image-gate: report written to {REPORT}")

    if not ran:
        print("release-image-gate: no environment could run; nothing was proved")
        return 1
    if not passed:
        failed = [r["environment"] for r in ran if r["status"] != "passed"]
        print(f"release-image-gate: failed on {', '.join(failed)}")
        return 1
    skipped = [r["environment"] for r in results if r["status"] == "skipped"]
    booted = len(dict.fromkeys(r["architecture"] for r in ran))
    summary = (f"release-image-gate: {len(ran)} environments booted "
               f"{booted} released image{'s' if booted != 1 else ''}")
    if skipped:
        summary += f"; skipped {', '.join(skipped)}"
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
