#!/usr/bin/env python3
"""Boot the one unified image on every environment that can run it.

build/xaios.iso is a single file meant to boot four different environments --
QEMU on two architectures, VMware Fusion, Apple Virtualization.framework -- as
optical media, as a disk, or from a USB stick. Nothing checked that until this
gate existed: the per-platform gates each boot their own per-platform image, so
every one of them can pass while the unified image boots nothing at all.

That is not hypothetical. Getting this image to boot on Fusion turned on a
detail no per-platform gate would ever have exercised -- the name of the kernel
file -- and the x86_64 half asserted on a device self-test that does not apply
when the initial filesystem arrives on the boot medium rather than as a
separate drive. Both were found by hand, once, and nothing would have caught
either coming back.

What this checks is deliberately shallower than the per-platform gates: that
the one file boots each environment to a working system. Depth is their job.
Breadth is this one's.

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


IMAGE = Path(os.environ.get(
    "XAIOS_UNIFIED_IMAGE", BUILD / f"xaios_b{_build_number()}.iso"))
VZ = BUILD / "vz"
FUSION_VM = BUILD / "vmware-fusion" / "XAIOS.vmwarevm"
REPORT = BUILD / "unified-image-gate.json"
VMRUN = Path(os.environ.get(
    "XAIOS_FUSION_VMRUN",
    "/Applications/VMware Fusion.app/Contents/Library/vmrun"))

# The common ground: what every environment says when this image works. The
# per-platform gates assert far more, and should -- device inventories differ,
# so a marker list long enough to be thorough here would be four lists.
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
    scratch = BUILD / f"unified-boot-{arch}.img"
    shutil.copy(IMAGE, scratch)
    image_variable = ("XAIOS_AARCH64_IMAGE" if arch == "aarch64"
                      else "XAIOS_X86_64_IMAGE")
    persistent_variable = ("XAIOS_PERSISTENT_IMAGE" if arch == "aarch64"
                           else "XAIOS_X86_PERSISTENT_IMAGE")
    environment = {**os.environ, image_variable: str(scratch),
                   persistent_variable:
                       str(fresh_persistent(f"unified-{arch}-persistent.img"))}
    # x86_64 has no hardware acceleration on an ARM host, so it boots through
    # an interpreter and takes several times longer than anything else here.
    timeout = int(os.environ.get(
        "XAIOS_UNIFIED_QEMU_TIMEOUT", "540" if arch == "x86_64" else "240"))
    log = BUILD / f"unified-qemu-{arch}.log"
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
    boot_disk = VZ / "unified-boot.img"
    shutil.copy(IMAGE, boot_disk)
    shutil.copy(fresh_persistent("unified-vz-persistent.img"),
                VZ / "vz-persistent.img")
    command = [str(harness), str(boot_disk)] + [str(VZ / v) for v in volumes]
    command += ["--memory-mib", "2048", "--cpus", "4"]
    log = BUILD / "unified-vz.log"
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
    staged = FUSION_VM / "unified-gate.iso"
    shutil.copy(IMAGE, staged)
    original = vmx.read_text(encoding="utf-8")
    serial = FUSION_VM / "fusion-serial.log"
    try:
        vmx.write_text(
            re.sub(r'sata0:0\.fileName = "[^"]*"',
                   'sata0:0.fileName = "unified-gate.iso"', original),
            encoding="utf-8")
        serial.unlink(missing_ok=True)
        subprocess.run([str(VMRUN), "-T", "fusion", "start", str(vmx), "nogui"],
                       check=False, capture_output=True, timeout=120)
        deadline = time.monotonic() + int(
            os.environ.get("XAIOS_UNIFIED_FUSION_TIMEOUT", "240"))
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


ENVIRONMENTS = (
    ("qemu-aarch64", lambda: boot_qemu("aarch64")),
    ("qemu-x86_64", lambda: boot_qemu("x86_64")),
    ("virtualization-framework", boot_vz),
    ("vmware-fusion", boot_fusion),
)


def main() -> int:
    if not IMAGE.is_file():
        print(f"unified-image-gate: {IMAGE} is missing; run make unified-image")
        return 1

    only = os.environ.get("XAIOS_UNIFIED_ONLY")
    results = []
    for name, boot in ENVIRONMENTS:
        if only is not None and name != only:
            continue
        text, unavailable = boot()
        if unavailable is not None:
            results.append({"environment": name, "status": "skipped",
                            "reason": unavailable})
            print(f"  skip {name}: {unavailable}")
            continue
        checks = [{"name": label, "passed": bool(pattern.search(text))}
                  for label, pattern in EXPECTED]
        faults = [{"name": label, "seen": bool(pattern.search(text))}
                  for label, pattern in FORBIDDEN]
        passed = all(c["passed"] for c in checks) and \
            not any(f["seen"] for f in faults)
        results.append({"environment": name,
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
        "image": str(IMAGE),
        "qualification_evidence": False,
        "environments": results,
        "passed": passed,
    }, indent=2) + "\n", encoding="utf-8")
    print(f"unified-image-gate: report written to {REPORT}")

    if not ran:
        print("unified-image-gate: no environment could run; nothing was proved")
        return 1
    if not passed:
        failed = [r["environment"] for r in ran if r["status"] != "passed"]
        print(f"unified-image-gate: failed on {', '.join(failed)}")
        return 1
    skipped = [r["environment"] for r in results if r["status"] == "skipped"]
    summary = f"unified-image-gate: {len(ran)} environments booted one image"
    if skipped:
        summary += f"; skipped {', '.join(skipped)}"
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
