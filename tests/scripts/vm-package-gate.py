#!/usr/bin/env python3
"""Boot each downloadable kit from its own archive.

The kits are the product a person actually receives: a zip, an image inside it,
and a launcher beside it. Every check that runs against the repository's own
runners tests something else -- those runners carry flags the kit's launcher has
to carry too, and the whole failure mode here is a launcher that boots a machine
which then quietly does less than its README promises.

Four such omissions were found by hand while writing the kits, and each one
produced a machine that started perfectly:

  - -global virtio-mmio.force-legacy=false, without which QEMU presents a
    legacy MMIO device and the driver requires a modern one;
  - the AArch64 network device on the MMIO bus rather than PCI;
  - disable-legacy=on on the x86-64 *boot* disk, without which that disk is not
    counted, every PCI ordinal shifts, and durable storage is looked for past
    the last disk attached;
  - a writable volume on every profile, because the configuration sshd loads
    lives on durable storage.

None of those is visible without starting the kit, and none is caught by any
other gate. This exists so that dropping one of them fails something.

The two QEMU kits run anywhere QEMU does, CI included. The Fusion and
Virtualization.framework kits need macOS on Apple Silicon with those
hypervisors installed, so they are attempted when they can be and reported as
not-run when they cannot -- never quietly skipped into a pass.
"""

from __future__ import annotations

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
WORK = BUILD / "vm-package-gate"
REPORT = BUILD / "vm-package-gate.json"
BOOT_TIMEOUT_S = int(os.environ.get("XAIOS_KIT_TIMEOUT", "420"))
VMRUN = Path(os.environ.get(
    "XAIOS_FUSION_VMRUN",
    "/Applications/VMware Fusion.app/Contents/Public/vmrun"))


def build_number() -> str:
    try:
        return (ROOT / "BUILD_NUMBER").read_text(encoding="utf-8").strip()
    except OSError:
        return "0"


BUILD_NUMBER = build_number()

# What a kit has to reach. Durable storage is on the list because its absence
# is the failure that looks most like success: the machine boots, takes an
# address, and only sshd notices it has nowhere to keep its configuration.
EXPECTED = (
    ("kernel started", re.compile(r"XAIOS Build \d+ kernel starting")),
    ("durable volume mounted",
     re.compile(r"(?:mutable-fs|xaibootfs): persistent mounted")),
    ("address configured", re.compile(r"IPv4: \d+\.\d+\.\d+\.\d+")),
    ("SSH server listening", re.compile(r"SSH server: up and running")),
)

FORBIDDEN = (
    ("kernel panic", re.compile(r"CYAN SCREEN OF DEATH")),
    ("assertion failure", re.compile(r"ERROR: assertion failed")),
    ("booted into rescue mode",
     re.compile(r"lifecycle initialized[^\n]*rescue=1")),
)


def extract(kit: str) -> Path | None:
    archive = RELEASE / f"xaios_b{BUILD_NUMBER}-{kit}.zip"
    if not archive.is_file():
        return None
    target = WORK / kit
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    with zipfile.ZipFile(archive) as handle:
        handle.extractall(target)
    # Restore the executable bit: zipfile does not, and a launcher that cannot
    # be run would fail this gate for a reason that has nothing to do with the
    # kit as a person receives it.
    for script in target.rglob("*.sh"):
        script.chmod(0o755)
    return target / f"xaios_b{BUILD_NUMBER}-{kit}"


def run_launcher(command: list[str], cwd: Path, log: Path,
                 environment: dict[str, str]) -> str:
    log.unlink(missing_ok=True)
    with log.open("wb") as handle:
        process = subprocess.Popen(
            command, cwd=str(cwd), stdout=handle, stderr=subprocess.STDOUT,
            env={**os.environ, **environment}, start_new_session=True)
        deadline = time.monotonic() + BOOT_TIMEOUT_S
        try:
            while time.monotonic() < deadline:
                time.sleep(5)
                text = log.read_bytes().decode("utf-8", "replace")
                if all(p.search(text) for _, p in EXPECTED):
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
    return log.read_bytes().decode("utf-8", "replace")


def evaluate(name: str, text: str) -> dict:
    checks = [{"name": n, "passed": bool(p.search(text))} for n, p in EXPECTED]
    faults = [{"name": n, "seen": bool(p.search(text))} for n, p in FORBIDDEN]
    passed = all(c["passed"] for c in checks) and \
        not any(f["seen"] for f in faults)
    print(f"  {name}:")
    for check in checks:
        print(f"    {'ok  ' if check['passed'] else 'MISS'} {check['name']}")
    for fault in faults:
        if fault["seen"]:
            print(f"    FAULT {fault['name']}")
    return {"kit": name, "checks": checks, "faults": faults, "passed": passed,
            "ran": True}


def not_run(name: str, why: str) -> dict:
    print(f"  {name}: not run -- {why}")
    return {"kit": name, "ran": False, "reason": why, "passed": False}


def qemu_kit(results: list[dict]) -> None:
    root = extract("qemu")
    if root is None:
        results.append(not_run("qemu", "no kit archive; run make vm-packages"))
        return
    if shutil.which("qemu-system-aarch64") is None:
        results.append(not_run("qemu-aarch64", "qemu-system-aarch64 not installed"))
    else:
        # A port per architecture, and neither the default: two kits booting at
        # once would otherwise collide on the host forward and the second would
        # fail to start at all, which reads as a broken launcher.
        text = run_launcher([str(root / "run-aarch64.sh")], root,
                            BUILD / "kit-qemu-aarch64.log",
                            {"XAIOS_SSH_PORT": "27431"})
        results.append(evaluate("qemu-aarch64", text))
    if shutil.which("qemu-system-x86_64") is None:
        results.append(not_run("qemu-x86_64", "qemu-system-x86_64 not installed"))
    else:
        text = run_launcher([str(root / "run-x86_64.sh")], root,
                            BUILD / "kit-qemu-x86_64.log",
                            {"XAIOS_SSH_PORT": "27432"})
        results.append(evaluate("qemu-x86_64", text))


def vz_kit(results: list[dict]) -> None:
    name = "virtualization-framework"
    if sys.platform != "darwin":
        results.append(not_run(name, "needs macOS"))
        return
    root = extract(name)
    if root is None:
        results.append(not_run(name, "no kit archive; run make vm-packages"))
        return
    if shutil.which("swiftc") is None:
        results.append(not_run(name, "swiftc not installed"))
        return
    text = run_launcher([str(root / "build-and-run.sh")], root,
                        BUILD / "kit-vz.log", {})
    results.append(evaluate(name, text))


def fusion_kit(results: list[dict]) -> None:
    name = "vmware-fusion"
    if sys.platform != "darwin" or not VMRUN.is_file():
        results.append(not_run(name, "needs macOS with VMware Fusion"))
        return
    root = extract(name)
    if root is None:
        results.append(not_run(name, "no kit archive; run make vm-packages"))
        return
    bundle = root / "XAIOS.vmwarevm"
    vmx = bundle / "XAIOS.vmx"
    serial = bundle / "fusion-serial.log"
    subprocess.run([str(VMRUN), "-T", "fusion", "start", str(vmx), "nogui"],
                   check=False, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + BOOT_TIMEOUT_S
        text = ""
        while time.monotonic() < deadline:
            time.sleep(5)
            if serial.is_file():
                text = serial.read_bytes().decode("utf-8", "replace")
                if all(p.search(text) for _, p in EXPECTED):
                    break
                if any(p.search(text) for _, p in FORBIDDEN):
                    break
    finally:
        subprocess.run([str(VMRUN), "-T", "fusion", "stop", str(vmx), "hard"],
                       check=False, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
    results.append(evaluate(name, text))


def main() -> int:
    WORK.mkdir(parents=True, exist_ok=True)
    results: list[dict] = []
    qemu_kit(results)
    vz_kit(results)
    fusion_kit(results)

    ran = [r for r in results if r["ran"]]
    # A kit that could not be attempted is not a kit that passed. The gate
    # fails only on a kit that ran and did not work, and reports the rest
    # plainly, so "green" never quietly means "nothing was tried".
    failed = [r for r in ran if not r["passed"]]
    REPORT.write_text(json.dumps({
        "target": "downloadable-vm-kits",
        "build": BUILD_NUMBER,
        "kits": results,
        "attempted": len(ran),
        "passed": not failed and bool(ran),
    }, indent=2) + "\n", encoding="utf-8")
    print(f"vm-package-gate: report written to {REPORT}")
    if not ran:
        print("vm-package-gate: no kit could be attempted here")
        return 1
    if failed:
        print("vm-package-gate: a kit did not come up as its README says")
        return 1
    print(f"vm-package-gate: {len(ran)} kit(s) booted from their archives")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
