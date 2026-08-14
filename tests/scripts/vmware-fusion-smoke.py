#!/usr/bin/env python3
"""Boot the generated Fusion VM and verify serial correctness markers."""

import json
import os
import platform
import plistlib
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
VM_BUNDLE = ROOT / "build" / "vmware-fusion" / "XAIOS.vmwarevm"
VMX = VM_BUNDLE / "XAIOS.vmx"
SERIAL = VM_BUNDLE / "fusion-serial.log"
EVIDENCE = ROOT / "build" / "vmware-fusion" / "fusion-smoke-evidence.json"
VMRUN = Path(os.environ.get(
    "XAIOS_VMRUN",
    "/Applications/VMware Fusion.app/Contents/Library/vmrun",
))
TIMEOUT_SECONDS = int(os.environ.get("XAIOS_FUSION_TIMEOUT", "180"))
MARKERS = [
    "smp: secondary worker barrier passed ready=1",
    "e1000e: ready pci=",
    "ahci: ready pci=",
    "mutable-fs: persistent mounted v5",
    "kernel: persistent network stack enabled device=e1000e",
    "telemetry: boot_summary cpu_online=1",
    "kernel: starting persistent /bin/sshd service",
    "SSH server: up and running (tcp/22)",
]
FATAL_MARKERS = ["System halted", "assertion failed", "CYAN SCREEN OF DEATH"]


def fusion_version() -> str:
    info = Path("/Applications/VMware Fusion.app/Contents/Info.plist")
    with info.open("rb") as handle:
        values = plistlib.load(handle)
    return str(values.get("CFBundleShortVersionString", "unknown"))


def git_revision() -> str:
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()


def main() -> int:
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise SystemExit("VMware Fusion smoke requires Apple Silicon macOS")
    if not VMRUN.is_file() or not os.access(VMRUN, os.X_OK):
        raise SystemExit(f"vmrun is unavailable: {VMRUN}")
    if not VMX.is_file():
        raise SystemExit("Fusion VM is missing; run make vmware-fusion-image")

    SERIAL.unlink(missing_ok=True)
    started = time.monotonic()
    completed = False
    output = ""
    fatal_markers = []
    try:
        subprocess.run(
            [str(VMRUN), "-T", "fusion", "start", str(VMX), "nogui"],
            check=True,
            timeout=60,
        )
        deadline = started + TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            if SERIAL.exists():
                output = SERIAL.read_text(encoding="utf-8", errors="replace")
                fatal_markers = [marker for marker in FATAL_MARKERS
                                 if marker in output]
                if fatal_markers:
                    break
                missing = [marker for marker in MARKERS if marker not in output]
                if not missing:
                    completed = True
                    break
            time.sleep(0.5)
    finally:
        subprocess.run(
            [str(VMRUN), "-T", "fusion", "stop", str(VMX), "hard"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    elapsed = round(time.monotonic() - started, 3)
    missing = [marker for marker in MARKERS if marker not in output]
    evidence = {
        "schema_version": 1,
        "result": "passed" if completed else "failed",
        "host": {"system": platform.system(), "machine": platform.machine()},
        "vmware_fusion_version": fusion_version(),
        "source_commit": git_revision(),
        "elapsed_seconds": elapsed,
        "markers": MARKERS,
        "missing_markers": missing,
        "fatal_markers": fatal_markers,
        "scope": "virtual ARM64 boot, E1000E DHCP, AHCI MutableFS, and SSH service readiness; not physical-performance evidence",
        "performance_evidence": False,
    }
    EVIDENCE.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    if not completed:
        tail = "\n".join(output.splitlines()[-30:])
        print(
            f"Fusion smoke failed; missing markers: {missing}; "
            f"fatal markers: {fatal_markers}\n{tail}",
            file=sys.stderr,
        )
        return 1
    print(
        "VMware Fusion smoke passed: "
        f"version={evidence['vmware_fusion_version']} elapsed={elapsed}s"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
