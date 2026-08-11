#!/usr/bin/env python3
import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Tuple


ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
CONTRACT_PATH = ROOT / "contracts/qemu-rc-v1.json"


def run(cmd: Sequence[str], timeout: int = 180,
        env: Dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    print(f"qemu-gate: running {' '.join(cmd)}", flush=True)
    return subprocess.run(
        list(cmd),
        cwd=ROOT,
        env=merged_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
        check=False,
    )


def write_report(path: Path, report: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n",
                    encoding="utf-8")
    print(f"qemu-gate: report written to {path.relative_to(ROOT)}")


def load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def contract() -> Dict[str, Any]:
    return load_json(CONTRACT_PATH)


def parse_telemetry(text: str) -> Dict[str, Any]:
    marker = "telemetry: "
    start = text.rfind(marker)
    if start < 0:
        raise ValueError("missing telemetry marker")
    payload = text[start + len(marker):].strip().splitlines()[0]
    if not payload.startswith("{"):
        raise ValueError("telemetry marker does not contain JSON")
    return json.loads(payload)


def check_markers(text: str, markers: Iterable[str]) -> List[str]:
    return [marker for marker in markers if marker not in text]


def status_from_failures(failures: Sequence[str]) -> str:
    return "pass" if not failures else "fail"


def validate_telemetry_against_contract(telemetry: Dict[str, Any],
                                        rc_contract: Dict[str, Any]) -> List[str]:
    failures: List[str] = []
    schema = rc_contract.get("telemetry_schema", {})
    for key, minimum in schema.get("minimums", {}).items():
        value = telemetry.get(key)
        if not isinstance(value, int) or value < minimum:
            failures.append(f"telemetry.{key} expected >= {minimum}, got {value!r}")
    for key, expected in schema.get("equals", {}).items():
        value = telemetry.get(key)
        if value != expected:
            failures.append(f"telemetry.{key} expected {expected!r}, got {value!r}")
    return failures


def parse_syscall_header() -> Tuple[Dict[str, int], Dict[str, int]]:
    header = ROOT / "kernel/include/xaios/syscall.h"
    text = header.read_text(encoding="utf-8")
    syscalls: Dict[str, int] = {}
    capabilities: Dict[str, int] = {}
    syscall_re = re.compile(r"#define\s+XAIOS_SYSCALL_([A-Z0-9_]+)\s+UINT64_C\((\d+)\)")
    cap_re = re.compile(r"#define\s+(XAIOS_CAP_[A-Z0-9_]+)\s+UINT64_C\((\d+)\)")
    for match in syscall_re.finditer(text):
        syscalls[match.group(1).lower()] = int(match.group(2))
    for match in cap_re.finditer(text):
        capabilities[match.group(1)] = int(match.group(2))
    return syscalls, capabilities


def validate_syscall_abi(rc_contract: Dict[str, Any]) -> List[str]:
    failures: List[str] = []
    source_syscalls, source_caps = parse_syscall_header()
    abi = rc_contract.get("syscall_abi", {})
    for entry in abi.get("syscalls", []):
        name = str(entry.get("name"))
        expected = entry.get("number")
        actual = source_syscalls.get(name)
        if actual != expected:
            failures.append(f"syscall {name} expected {expected}, got {actual}")
    for entry in abi.get("capabilities", []):
        name = str(entry.get("name"))
        expected = entry.get("bit")
        actual = source_caps.get(name)
        if actual != expected:
            failures.append(f"capability {name} expected {expected}, got {actual}")
    contract_syscalls = {
        str(entry.get("name")): entry.get("number")
        for entry in abi.get("syscalls", [])
    }
    if contract_syscalls != source_syscalls:
        missing = sorted(set(source_syscalls) - set(contract_syscalls))
        extra = sorted(set(contract_syscalls) - set(source_syscalls))
        if missing:
            failures.append(f"contract missing source syscalls: {missing}")
        if extra:
            failures.append(f"contract has unknown syscalls: {extra}")
    contract_caps = {
        str(entry.get("name")): entry.get("bit")
        for entry in abi.get("capabilities", [])
    }
    if contract_caps != source_caps:
        missing = sorted(set(source_caps) - set(contract_caps))
        extra = sorted(set(contract_caps) - set(source_caps))
        if missing:
            failures.append(f"contract missing source capabilities: {missing}")
        if extra:
            failures.append(f"contract has unknown capabilities: {extra}")
    numbers = sorted(source_syscalls.values())
    if numbers != list(range(1, len(numbers) + 1)):
        failures.append(f"syscall numbers must be contiguous from 1, got {numbers}")
    return failures


def result(name: str, ok: bool, **extra: Any) -> Dict[str, Any]:
    item: Dict[str, Any] = {"name": name, "status": "pass" if ok else "fail"}
    item.update(extra)
    return item


def now() -> int:
    return int(time.time())
