#!/usr/bin/env python3
"""Run or aggregate immutable evidence for XAIOS firmware/platform profiles."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import time
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build" / "firmware-profiles"
CONTRACT = ROOT / "contracts" / "firmware-platform-profiles-v1.json"
LOG_ROOT = Path(
    os.environ.get("XAIOS_FIRMWARE_PROFILE_LOG_DIR", "/var/tmp/xaios-firmware-profiles")
)
PROFILE_IDS = (
    "macos-qemu-aarch64",
    "macos-vmware-fusion-aarch64",
    "intel-vps-qemu-x86_64",
)


def read_contract() -> dict[str, Any]:
    return json.loads(CONTRACT.read_text(encoding="utf-8"))


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def git_revision() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, check=False,
        capture_output=True, text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else "unknown"


def source_tree_failure() -> str | None:
    for arguments in (("diff", "--quiet"), ("diff", "--cached", "--quiet")):
        result = subprocess.run(
            ["git", *arguments], cwd=ROOT, check=False,
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            return "tracked source tree is dirty; commit or discard tracked changes before collecting evidence"
    return None


def command_version(binary: str) -> dict[str, str]:
    resolved = shutil.which(binary)
    if resolved is None:
        return {"path": "unavailable", "version": "unavailable", "sha256": "unavailable"}
    result = subprocess.run(
        [resolved, "--version"], check=False, capture_output=True, text=True,
    )
    version = (result.stdout or result.stderr).splitlines()
    return {
        "path": resolved,
        "version": version[0] if result.returncode == 0 and version else "not-reported-by-binary",
        "sha256": digest(Path(resolved)),
    }


def host_identity(profile: dict[str, Any]) -> tuple[dict[str, str], list[str]]:
    expected = profile["host"]
    actual = {"system": platform.system(), "machine": platform.machine()}
    failures: list[str] = []
    for key in ("system", "machine"):
        if actual[key] != expected[key]:
            failures.append(f"host {key} expected {expected[key]!r}, got {actual[key]!r}")
    for key, value in expected.get("required_environment", {}).items():
        actual_value = os.environ.get(key)
        if actual_value != value:
            failures.append(f"environment {key} expected {value!r}, got {actual_value!r}")
    actual["hostname"] = platform.node() or "unknown"
    return actual, failures


def firmware_identity(profile: dict[str, Any]) -> tuple[dict[str, str], list[str]]:
    firmware = profile["firmware"]
    result = {"provider": firmware["provider"]}
    failures: list[str] = []
    environment = firmware.get("path_environment")
    if environment:
        path_text = os.environ.get(environment, "")
        path = Path(path_text) if path_text else None
        if path is None or not path.is_file():
            failures.append(f"set {environment} to the qualified firmware file")
            result.update({"path": "unavailable", "sha256": "unavailable"})
        else:
            result.update({"path": str(path), "sha256": digest(path)})
    else:
        info = Path("/Applications/VMware Fusion.app/Contents/Info.plist")
        if not info.is_file():
            failures.append("VMware Fusion Info.plist is unavailable")
            result.update({"path": "unavailable", "sha256": "unavailable"})
        else:
            result.update({"path": str(info), "sha256": digest(info)})
            version = subprocess.run(
                ["/usr/libexec/PlistBuddy", "-c", "Print :CFBundleShortVersionString", str(info)],
                check=False, capture_output=True, text=True,
            ).stdout.strip()
            result["version"] = version or "unknown"
            if version != "26.0.0":
                failures.append(f"VMware Fusion 26H1 requires 26.0.0, got {version!r}")
    return result, failures


def effective_emulator(profile: dict[str, Any]) -> dict[str, str]:
    emulator = profile["emulator"]
    result = command_version(emulator["binary"])
    if profile["id"] == "macos-qemu-aarch64":
        result.update({
            "machine": (
                os.environ.get("XAIOS_QEMU_MACHINE", "virt")
                + ",gic-version=3"
            ),
            "cpu": os.environ.get("XAIOS_QEMU_CPU", emulator["cpu"]),
            "accelerator": os.environ.get("XAIOS_QEMU_ACCEL", emulator["accelerator"]),
        })
    elif profile["id"] == "intel-vps-qemu-x86_64":
        result.update({
            "machine": os.environ.get("XAIOS_QEMU_X86_MACHINE", emulator["machine"]),
            "cpu": os.environ.get("XAIOS_QEMU_X86_CPU", emulator["cpu"]),
            "accelerator": os.environ.get("XAIOS_QEMU_X86_ACCEL", emulator["accelerator"]),
        })
    else:
        result.update({
            "machine": emulator["machine"],
            "cpu": emulator["cpu"],
            "accelerator": emulator["accelerator"],
        })
    return result


def artifact_identity(profile_id: str) -> dict[str, dict[str, str]]:
    candidates: dict[str, Path] = {}
    if profile_id == "macos-vmware-fusion-aarch64":
        candidates = {
            "grub_configuration": ROOT / "platform/vmware-fusion/grub.cfg",
            "grub_chainloader": ROOT / "build/vmware-fusion/BOOTAA64.EFI",
            "fusion_boot_iso": ROOT / "build/vmware-fusion/XAIOS.vmwarevm/xaios-fusion.iso",
            "fusion_vmx": ROOT / "build/vmware-fusion/XAIOS.vmwarevm/XAIOS.vmx",
        }
    return {
        name: {
            "path": str(path.relative_to(ROOT)),
            "sha256": digest(path) if path.is_file() else "unavailable",
        }
        for name, path in candidates.items()
    }


def evidence_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def run_gate(log_directory: Path, gate: dict[str, Any]) -> dict[str, Any]:
    log_directory.mkdir(parents=True, exist_ok=True)
    log_path = log_directory / f"{gate['name']}.log"
    environment = os.environ.copy()
    environment.update(gate.get("environment", {}))
    started = time.monotonic()
    with log_path.open("w", encoding="utf-8") as log:
        process = subprocess.Popen(
            gate["command"], cwd=ROOT, env=environment,
            stdout=log, stderr=subprocess.STDOUT, text=True,
            start_new_session=True,
        )
        try:
            exit_code = process.wait(timeout=gate["timeout_seconds"])
            error = None
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
            exit_code = None
            error = f"timed out after {gate['timeout_seconds']}s"
    output = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
    return {
        "name": gate["name"],
        "command": gate["command"],
        "status": "pass" if exit_code == 0 else "fail",
        "exit_code": exit_code,
        "timeout_seconds": gate["timeout_seconds"],
        "duration_seconds": round(time.monotonic() - started, 3),
        "log": evidence_path(log_path),
        "log_sha256": digest(log_path) if log_path.is_file() else "unavailable",
        "tail": "\n".join(output.splitlines()[-12:]),
        "error": error,
    }


def profile_path(profile_id: str) -> Path:
    return BUILD / f"{profile_id}.json"


def run_profile(profile_id: str, dry_run: bool) -> int:
    contract = read_contract()
    profile = next((item for item in contract["profiles"] if item["id"] == profile_id), None)
    if profile is None:
        raise SystemExit(f"unknown profile: {profile_id}")
    host, host_failures = host_identity(profile)
    firmware, firmware_failures = firmware_identity(profile)
    emulator = effective_emulator(profile)
    source_failure = source_tree_failure()
    failures = host_failures + firmware_failures
    if source_failure is not None:
        failures.append(source_failure)
    gates = []
    log_directory = LOG_ROOT / f"{profile_id}-{git_revision()}-{time.time_ns()}"
    if not failures and not dry_run:
        profile_environment = profile.get("environment", {})
        gates = [
            run_gate(
                log_directory,
                {**gate, "environment": {**profile_environment, **gate.get("environment", {})}},
            )
            for gate in profile["gates"]
        ]
        failures.extend(gate["name"] for gate in gates if gate["status"] != "pass")
    elif dry_run:
        gates = [{"name": gate["name"], "status": "not-run-dry-run",
                  "command": gate["command"]} for gate in profile["gates"]]
    report = {
        "schema": contract["evidence_schema"],
        "profile_id": profile_id,
        "status": "pass" if not failures and not dry_run else "fail" if failures else "not-run",
        "created_at_unix": int(time.time()),
        "source_commit": git_revision(),
        "contract_sha256": digest(CONTRACT),
        "host": host,
        "firmware": firmware,
        "emulator": emulator,
        "platform_artifacts": artifact_identity(profile_id),
        "evidence_log_directory": evidence_path(log_directory),
        "required_firmware_tables": profile["required_firmware_tables"],
        "expected_devices": profile["expected_devices"],
        "capability_outcomes": profile["capabilities"],
        "gates": gates,
        "failures": failures,
        "qemu_correctness_only": profile_id != "macos-vmware-fusion-aarch64",
        "physical_performance_claims_allowed": False,
    }
    BUILD.mkdir(parents=True, exist_ok=True)
    destination = profile_path(profile_id)
    destination.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"firmware-profile: report written to {destination.relative_to(ROOT)}")
    if failures:
        print("firmware-profile: failed " + "; ".join(failures), file=sys.stderr)
        return 1
    if dry_run:
        print(f"firmware-profile: {profile_id} contract validated; gates not run")
        return 0
    print(f"firmware-profile: {profile_id} passed")
    return 0


def aggregate(evidence_paths: list[Path]) -> int:
    contract = read_contract()
    expected_contract = digest(CONTRACT)
    reports: dict[str, dict[str, Any]] = {}
    failures: list[str] = []
    for path in evidence_paths:
        if not path.is_file():
            failures.append(f"missing evidence: {path}")
            continue
        report = json.loads(path.read_text(encoding="utf-8"))
        profile_id = report.get("profile_id")
        if profile_id not in PROFILE_IDS:
            failures.append(f"{path}: unknown profile {profile_id!r}")
            continue
        if profile_id in reports:
            failures.append(f"duplicate evidence for {profile_id}")
            continue
        if report.get("schema") != contract["evidence_schema"]:
            failures.append(f"{profile_id}: evidence schema mismatch")
        if report.get("contract_sha256") != expected_contract:
            failures.append(f"{profile_id}: evidence is for a different contract")
        if report.get("status") != "pass":
            failures.append(f"{profile_id}: evidence status is {report.get('status')!r}")
        reports[profile_id] = {"path": str(path), "sha256": digest(path), "report": report}
    missing = [profile_id for profile_id in PROFILE_IDS if profile_id not in reports]
    failures.extend(f"missing profile evidence: {profile_id}" for profile_id in missing)
    commits = {item["report"].get("source_commit") for item in reports.values()}
    if len(commits) > 1:
        failures.append("profile evidence commits differ")
    aggregate_report = {
        "schema": contract["aggregate_schema"],
        "status": "pass" if not failures else "incomplete",
        "created_at_unix": int(time.time()),
        "contract_sha256": expected_contract,
        "source_commits": sorted(commit for commit in commits if isinstance(commit, str)),
        "profiles": reports,
        "failures": failures,
        "physical_qualification": False,
        "performance_claims_allowed": False,
    }
    BUILD.mkdir(parents=True, exist_ok=True)
    destination = BUILD / "aggregate.json"
    destination.write_text(json.dumps(aggregate_report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"firmware-profile: aggregate written to {destination.relative_to(ROOT)}")
    if failures:
        print("firmware-profile: aggregate incomplete " + "; ".join(failures), file=sys.stderr)
        return 1
    print("firmware-profile: all three virtual-platform reports match")
    return 0


def validate_contract() -> int:
    contract = read_contract()
    failures: list[str] = []
    if contract.get("schema") != "xaios.firmware_platform_profiles.v1":
        failures.append("schema mismatch")
    profiles = contract.get("profiles")
    if not isinstance(profiles, list) or tuple(item.get("id") for item in profiles) != PROFILE_IDS:
        failures.append("profile IDs must be the canonical three-profile order")
    for profile in profiles if isinstance(profiles, list) else []:
        if not profile.get("required_firmware_tables"):
            failures.append(f"{profile.get('id')}: required firmware tables missing")
        if not profile.get("expected_devices"):
            failures.append(f"{profile.get('id')}: expected device inventory missing")
        capability_names = set(profile.get("capabilities", {}))
        required = {"boot", "cpu", "storage", "network_ssh", "shutdown", "repeat_boot"}
        if not required.issubset(capability_names):
            failures.append(f"{profile.get('id')}: lifecycle capability outcomes incomplete")
        for gate in profile.get("gates", []):
            if not isinstance(gate.get("command"), list) or gate.get("timeout_seconds", 0) <= 0:
                failures.append(f"{profile.get('id')}: malformed gate {gate.get('name')!r}")
    if failures:
        print("firmware-profile: contract invalid")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("firmware-profile: contract has three distinct qualified platform profiles")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", choices=PROFILE_IDS)
    parser.add_argument("--aggregate", action="store_true")
    parser.add_argument("--evidence", action="append", type=Path, default=[])
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--validate-contract", action="store_true")
    args = parser.parse_args()
    selected = int(args.profile is not None) + int(args.aggregate) + int(args.validate_contract)
    if selected != 1:
        parser.error("select exactly one of --profile, --aggregate, or --validate-contract")
    if args.aggregate:
        if args.dry_run or not args.evidence:
            parser.error("--aggregate requires one or more --evidence paths and no --dry-run")
        return aggregate(args.evidence)
    if args.validate_contract:
        if args.dry_run or args.evidence:
            parser.error("--validate-contract accepts no other options")
        return validate_contract()
    return run_profile(args.profile, args.dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
