#!/usr/bin/env python3
"""Keep the firmware-platform profile contract and user docs synchronized."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "tests/scripts/firmware-platform-profiles.py"
SURFACES = ("README.md", "docs/FIRMWARE-PLATFORM-PROFILES.md", "wiki/Firmware-Profiles.md")
REQUIRED = ("macOS QEMU ARM64", "macOS VMware Fusion ARM64", "Intel VPS QEMU x86_64")


def main() -> int:
    result = subprocess.run(
        ["python3", str(RUNNER), "--validate-contract"], cwd=ROOT,
        check=False, capture_output=True, text=True,
    )
    failures = [] if result.returncode == 0 else [result.stdout + result.stderr]
    for relative in SURFACES:
        text = (ROOT / relative).read_text(encoding="utf-8")
        for label in REQUIRED:
            if label not in text:
                failures.append(f"{relative}: missing profile label {label!r}")
    contract_path = ROOT / "contracts/firmware-platform-profiles-v1.json"
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    fusion = next(
        item for item in contract["profiles"]
        if item["id"] == "macos-vmware-fusion-aarch64"
    )
    expected_capabilities = {
        "cpu": "required-single-vcpu",
        "shutdown": "required",
        "repeat_boot": "required",
    }
    for capability, expected in expected_capabilities.items():
        if fusion["capabilities"].get(capability) != expected:
            failures.append(
                f"Fusion capability {capability!r} must be {expected!r}"
            )
    if fusion["gates"] != [{
            "name": "boot_storage_network_ssh_lifecycle",
            "command": ["make", "vmware-fusion-smoke"],
            "timeout_seconds": 600,
    }]:
        failures.append("Fusion must use the complete lifecycle smoke gate")
    vmx = (ROOT / "platform/vmware-fusion/XAIOS.vmx.in").read_text(
        encoding="utf-8"
    )
    if 'numvcpus = "1"' not in vmx:
        failures.append("Fusion VMX must remain an explicit one-vCPU profile")
    if failures:
        print("firmware-profiles-check: failed")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("firmware-profiles-check: contract and three-profile documentation agree")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
