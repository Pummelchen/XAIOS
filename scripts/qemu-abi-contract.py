#!/usr/bin/env python3
import re
from qemu_gate_lib import (BUILD, CONTRACT_PATH, ROOT, contract, now, result,
                           status_from_failures, validate_syscall_abi,
                           write_report)


SCHEMA = "xaios.qemu.abi_contract.v1"
REPORT = BUILD / "qemu-milestone-54-abi-contract.json"


def validate_contract_shape(rc_contract):
    failures = []
    if rc_contract.get("schema") != "xaios.qemu.release_candidate_contract.v1":
        failures.append("release candidate contract schema mismatch")
    if rc_contract.get("status") != "frozen":
        failures.append("release candidate contract is not frozen")
    required_sections = [
        "syscall_abi",
        "telemetry_schema",
        "filesystem_format",
        "cpu_ai_model_format",
        "ai_cell_descriptor_abi",
        "persistence_format",
        "service_descriptor_format",
        "security_policy",
        "update_system",
        "admin_control_plane",
        "cpu_matrix",
    ]
    for section in required_sections:
        if section not in rc_contract:
            failures.append(f"missing contract section: {section}")
    return failures


def validate_initfs_contract(rc_contract):
    failures = []
    create_initfs = (ROOT / "scripts/create-initfs.py").read_text(encoding="utf-8")
    build_image = (ROOT / "scripts/build-image.sh").read_text(encoding="utf-8")
    fs = rc_contract.get("filesystem_format", {})
    constants = {
        "MAGIC": fs.get("magic"),
        "VERSION": fs.get("version"),
        "MAX_FILES": fs.get("max_files"),
        "PATH_MAX": fs.get("path_max"),
        "HEADER_SECTOR": fs.get("header_sector"),
        "HEADER_BYTES": fs.get("header_bytes"),
        "DATA_OFFSET": fs.get("data_offset"),
    }
    for name, expected in constants.items():
        pattern = rf"^{name}\s*=\s*(.+)$"
        match = re.search(pattern, create_initfs, re.MULTILINE)
        if not match:
            failures.append(f"create-initfs missing constant {name}")
            continue
        value = match.group(1).strip()
        if isinstance(expected, str):
            if repr(expected.encode("ascii")).replace("b'", "b\"").replace("'", "\"") not in value and expected not in value:
                failures.append(f"create-initfs {name} does not match contract {expected!r}")
        elif str(expected) not in value:
            failures.append(f"create-initfs {name} expected {expected}, got {value}")

    required_paths = fs.get("required_paths", [])
    user_apps_match = re.search(r'^USER_APPS="([^"]*)"', build_image, re.MULTILINE)
    user_app_paths = set()
    if user_apps_match:
        user_app_paths = {f"/bin/{name}" for name in user_apps_match.group(1).split()}
    for path in required_paths:
        if path not in create_initfs and path not in build_image and path not in user_app_paths:
            failures.append(f"initfs build inputs missing required path {path}")
    return failures


def validate_model_contract(rc_contract):
    failures = []
    text = (ROOT / "scripts/create-initfs.py").read_text(encoding="utf-8")
    model = rc_contract.get("cpu_ai_model_format", {})
    expected = {
        "CPU_AI_MAGIC": model.get("magic_value"),
        "CPU_AI_VERSION": model.get("version"),
        "CPU_AI_HEADER_BYTES": model.get("header_bytes"),
        "CPU_AI_QUANTIZATION_SUPPORTED": model.get("quantization"),
    }
    for name, value in expected.items():
        match = re.search(rf"^{name}\s*=\s*(.+)$", text, re.MULTILINE)
        if not match:
            failures.append(f"create-initfs missing model constant {name}")
            continue
        source_value = match.group(1).strip()
        if isinstance(value, str) and value.startswith("0x"):
            matches = source_value.lower() == value.lower()
        else:
            matches = source_value == str(value)
        if not matches:
            failures.append(f"model contract value for {name} not present in create-initfs.py")
    if "CPU_AI_FLAG_CPU_ONLY" not in text:
        failures.append("model format does not enforce CPU-only flag in initfs generator")
    return failures


def validate_memory_map_contract(_rc_contract):
    failures = []
    vmm_header = (ROOT / "kernel/include/xaios/vmm.h").read_text(encoding="utf-8")
    user_linker = (ROOT / "userspace/init/linker.ld").read_text(encoding="utf-8")
    kernel_linker = (ROOT / "kernel/arch/aarch64/linker.ld").read_text(
        encoding="utf-8"
    )
    expected = {
        "XAIOS_USER_BASE": "0x100000000",
        "XAIOS_USER_LIMIT": "0x140000000",
        "XAIOS_USER_STACK_TOP": "0x13f000000",
    }
    for name, value in expected.items():
        declaration = f"#define {name} UINT64_C({value})"
        if declaration not in vmm_header:
            failures.append(f"memory map missing {declaration}")
    if ". = 0x100000000;" not in user_linker:
        failures.append("userspace linker base does not match XAIOS_USER_BASE")
    if "ASSERT(__kernel_end <= 0x100000000" not in kernel_linker:
        failures.append("kernel linker does not guard the userspace VA boundary")
    return failures


def validate_qemu_launcher_contract(_rc_contract):
    launcher = (ROOT / "scripts/run-qemu-aarch64.sh").read_text(encoding="utf-8")
    failures = []
    if 'accel="${XAIOS_QEMU_ACCEL:-tcg}"' not in launcher:
        failures.append("AArch64 QEMU launcher must default to TCG")
    if "AArch64 HVF is experimental" not in launcher:
        failures.append("AArch64 QEMU launcher must warn on explicit HVF use")
    return failures


def main() -> int:
    rc_contract = contract()
    checks = []
    failures = []
    validators = [
        ("contract_shape", validate_contract_shape),
        ("syscall_abi", validate_syscall_abi),
        ("initfs_format", validate_initfs_contract),
        ("cpu_ai_model_format", validate_model_contract),
        ("memory_map", validate_memory_map_contract),
        ("qemu_launcher", validate_qemu_launcher_contract),
    ]
    for name, validator in validators:
        result_failures = validator(rc_contract)
        checks.append(result(name, not result_failures, failures=result_failures))
        failures.extend(result_failures)

    report = {
        "schema": SCHEMA,
        "status": status_from_failures(failures),
        "milestone": 54,
        "created_at_unix": now(),
        "description": "ABI, format, and QEMU launcher contract checks for syscall, telemetry, initfs, AI Cell, persistence, service, and CPU-AI model contracts.",
        "contract": str(CONTRACT_PATH.relative_to(ROOT)),
        "checks": checks,
        "failures": failures,
    }
    write_report(REPORT, report)
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
