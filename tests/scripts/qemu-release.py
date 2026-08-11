#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path
from qemu_gate_lib import BUILD, ROOT, now, status_from_failures, write_report


SCHEMA = "xaios.qemu.release_manifest.v1"
REPORT = BUILD / "qemu-release-manifest.json"

ARTIFACTS = [
    "build/xaios-aarch64.img",
    "build/xaios-virtio-test.img",
    "contracts/qemu-rc-v1.json",
]

REQUIRED_REPORTS = [
    "build/qemu-milestone-62-filesystem-gate.json",
    "build/qemu-milestone-63-app-agent-gate.json",
    "build/qemu-milestone-64-network-full-gate.json",
    "build/qemu-milestone-65-cpu-ai-runtime-gate.json",
    "build/qemu-milestone-66-ai-cell-gate.json",
    "build/qemu-milestone-67-security-gate.json",
    "build/qemu-milestone-68-update-gate.json",
    "build/qemu-milestone-69-soak-gate.json",
]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    failures = []
    artifacts = []
    for relative in ARTIFACTS:
        path = ROOT / relative
        if not path.exists():
            failures.append(f"missing artifact: {relative}")
            continue
        artifacts.append({
            "path": relative,
            "bytes": path.stat().st_size,
            "sha256": sha256(path),
        })

    reports = []
    for relative in REQUIRED_REPORTS:
        path = ROOT / relative
        if not path.exists():
            failures.append(f"missing required report: {relative}")
            continue
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            failures.append(f"invalid required report JSON: {relative}: {exc}")
            continue
        status = report.get("status")
        if status != "pass":
            failures.append(f"required report did not pass: {relative} status={status!r}")
        reports.append({
            "path": relative,
            "status": status,
            "bytes": path.stat().st_size,
            "sha256": sha256(path),
        })

    report = {
        "schema": SCHEMA,
        "status": status_from_failures(failures),
        "milestone": 70,
        "created_at_unix": now(),
        "release": "qemu-macos-aarch64-dev",
        "performance_claims_allowed": False,
        "artifacts": artifacts,
        "required_reports": reports,
        "failures": failures,
    }
    write_report(REPORT, report)
    if failures:
        print("qemu-release: failed")
        for failure in failures:
            print(f" - {failure}")
        return 1
    print("qemu-release: milestone 70 release manifest written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
