#!/usr/bin/env python3
"""Enforce the repository's test-runner and Docker-fixture layout."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"
PLATFORM = ROOT / "platform"
REPOSITORY_CHECKS = ROOT / "tests" / "repository"
TESTS = ROOT / "tests"

RUNTIME_SCRIPTS = {
    "build-c99-app.sh",
    "build-bearssl.sh",
    "build-compiler-rt.sh",
    "build-image-x86_64.sh",
    "build-image.sh",
    "build-user-app.sh",
    "build-xapt-repository.sh",
    "build-libc-runtime-test.sh",
    "build-libc.sh",
    "create-initfs.py",
    "create-persistent-image.sh",
    "create-sshd-user-config.py",
    "macos-bootstrap.sh",
    "prepare-libc-sysroot.py",
    "publish-xapt-repository.sh",
    "run-xaios-ssh-bridge.sh",
    "xaios-ssh-bridge.py",
}


def main() -> int:
    failures: list[str] = []
    script_files = {path.name for path in SCRIPTS.iterdir() if path.is_file()}
    unexpected = sorted(script_files - RUNTIME_SCRIPTS)
    # One directory per supported environment, each holding that environment's
    # own launcher. Before this, Fusion's assets sat in platform/, its scripts
    # in scripts/, and the Virtualization.framework harness in tools/ -- three
    # environments in three unrelated places, with QEMU having no home at all.
    for environment, launcher in (
        ("qemu", "run-qemu-aarch64.sh"),
        ("vmware-fusion", "run-vmware-fusion.sh"),
        ("virtualization-framework", "build-vz-disk.sh"),
    ):
        directory = PLATFORM / environment
        if not directory.is_dir():
            failures.append(f"platform/{environment}/ is missing")
        elif not (directory / launcher).is_file():
            failures.append(
                f"platform/{environment}/{launcher} is missing; each "
                f"environment keeps its own launcher beside its assets"
            )

    # Checks about the repository live apart from gates that boot XAIOS. They
    # answer different questions -- is this tree consistent, versus does the
    # system work -- and mixing them put seventy-four files in one directory
    # where the only clue was a filename prefix.
    if not REPOSITORY_CHECKS.is_dir():
        failures.append("tests/repository/ is missing")
    else:
        for stray in sorted(REPOSITORY_CHECKS.glob("*.py")):
            if not stray.name.startswith("check-"):
                failures.append(
                    f"tests/repository/{stray.name} is not a repository check; "
                    f"gates that boot XAIOS belong in tests/scripts/"
                )
        for stray in sorted((ROOT / "tests" / "scripts").glob("check-*.py")):
            failures.append(
                f"tests/scripts/{stray.name} is a repository check and belongs "
                f"in tests/repository/"
            )

    # A path a test builds at runtime is invisible to a search for the literal
    # string, so moving a script can leave a gate pointing at nothing and the
    # break only shows when that gate runs. That happened: three profile gates
    # failed on a runner that had moved, after a grep for the old path came
    # back clean.
    for source in sorted(TESTS.rglob("*.py")) + sorted(TESTS.rglob("*.sh")):
        if any(part in source.parts for part in (".git", "build")):
            continue
        text = source.read_text(encoding="utf-8", errors="replace")
        for first, second in re.findall(
            r'ROOT\s*/\s*"([^"]+)"\s*/\s*"([^"]+)"', text
        ):
            if not second.endswith((".sh", ".py")):
                continue
            if not (ROOT / first / second).exists():
                failures.append(
                    f"{source.relative_to(ROOT)}: builds a path to "
                    f"{first}/{second}, which does not exist"
                )

    missing = sorted(RUNTIME_SCRIPTS - script_files)
    if unexpected:
        failures.append("non-runtime files remain in scripts/: " + ", ".join(unexpected))
    if missing:
        failures.append("expected runtime scripts are missing: " + ", ".join(missing))

    for path in ROOT.rglob("Dockerfile*"):
        if any(part in path.parts for part in (".git", "build", "third_party")):
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
