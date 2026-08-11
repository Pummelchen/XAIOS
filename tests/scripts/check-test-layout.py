#!/usr/bin/env python3
"""Enforce the repository's test-runner and Docker-fixture layout."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
TESTS = ROOT / "tests"

RUNTIME_SCRIPTS = {
    "build-image-x86_64.sh",
    "build-image.sh",
    "build-vmware-fusion.sh",
    "create-initfs.py",
    "create-persistent-image.sh",
    "create-sshd-user-config.py",
    "macos-bootstrap.sh",
    "run-qemu-aarch64.sh",
    "run-qemu-x86_64.sh",
    "run-vmware-fusion.sh",
    "run-xaios-ssh-bridge.sh",
    "ssh-xaios-qemu.sh",
    "xaios-ssh-bridge.py",
}


def main() -> int:
    failures: list[str] = []
    script_files = {path.name for path in SCRIPTS.iterdir() if path.is_file()}
    unexpected = sorted(script_files - RUNTIME_SCRIPTS)
    missing = sorted(RUNTIME_SCRIPTS - script_files)
    if unexpected:
        failures.append("non-runtime files remain in scripts/: " + ", ".join(unexpected))
    if missing:
        failures.append("expected runtime scripts are missing: " + ", ".join(missing))

    for path in ROOT.rglob("Dockerfile*"):
        if ".git" in path.parts or "build" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        for source in re.findall(r"^(?:COPY|ADD)\s+([^\s]+)", text, re.MULTILINE):
            if source.startswith(("--", "http://", "https://")):
                continue
            source_path = ROOT / source
            if not source_path.exists():
                failures.append(f"{path.relative_to(ROOT)}: missing Docker source {source}")
            if path.parent == TESTS / "network" and TESTS not in source_path.parents:
                failures.append(
                    f"{path.relative_to(ROOT)}: test image source is outside tests/: {source}"
                )

    required_docs = (TESTS / "README.md", ROOT / "wiki/Testing-XAIOS.md")
    for path in required_docs:
        if not path.is_file():
            failures.append(f"missing test documentation: {path.relative_to(ROOT)}")

    if failures:
        print("test-layout: failed")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("test-layout: test runners and Docker fixtures are contained in tests/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
