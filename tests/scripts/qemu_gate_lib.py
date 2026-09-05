#!/usr/bin/env python3
import json
import os
import signal
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
    # Its own process group, so a timeout can take the whole tree down.
    #
    # subprocess.run kills only the direct child, which is make -- and make's
    # emulator keeps running, holding its images and its ports. The next gate
    # in the list then fails for reasons that have nothing to do with it, and
    # the report blames it. That is exactly what happened when the storage
    # crash gate grew a second volume format and overran its budget: two gates
    # went red and only one of them was slow.
    process = subprocess.Popen(
        list(cmd),
        cwd=ROOT,
        env=merged_env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    try:
        output, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        output, _ = process.communicate()
        raise subprocess.TimeoutExpired(cmd, timeout, output=output)
    return subprocess.CompletedProcess(list(cmd), process.returncode, output,
                                       None)


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


# --------------------------------------------------------------- architecture
#
# Three machines, three runners, and three sets of names for the same knobs:
# aarch64 reads XAIOS_QEMU_* and XAIOS_PERSISTENT_IMAGE, x86_64 mixes
# XAIOS_QEMU_* with XAIOS_QEMU_X86_* and XAIOS_X86_PERSISTENT_IMAGE, and
# riscv64 reads XAIOS_RISCV64_* throughout and keeps its disks in a state
# directory rather than naming an image. Renaming any of that would break
# every existing caller for no gain, so the difference lives here instead:
# one place that a gate asks "boot this architecture" and gets the right
# names. A gate that hardcodes a runner can reach exactly one machine, which
# is how a third architecture ends up with six gates against seventy.

QEMU_ARCHES = ("aarch64", "x86_64", "riscv64")

_MAKE_TARGETS = {
    "aarch64": "qemu-aarch64",
    "x86_64": "qemu-x86_64",
    "riscv64": "qemu-riscv64",
}


def arch_from_argv(argv: Sequence[str], default: str = "aarch64") -> str:
    """--arch NAME or --arch=NAME, validated. Gates take it the same way."""
    arch = default
    for index, argument in enumerate(argv):
        if argument == "--arch" and index + 1 < len(argv):
            arch = argv[index + 1]
        elif argument.startswith("--arch="):
            arch = argument.split("=", 1)[1]
    if arch not in QEMU_ARCHES:
        raise SystemExit(f"unsupported --arch {arch!r}; expected one of "
                         f"{', '.join(QEMU_ARCHES)}")
    return arch


def qemu_make_target(arch: str) -> str:
    return _MAKE_TARGETS[arch]


def qemu_boot_environment(arch: str, env: Dict[str, str], *,
                          persistent: Any = None,
                          persistent_sectors: Any = None,
                          storage_admin: Any = None,
                          system_volume: Any = None,
                          state_dir: Any = None,
                          hostfwd_port: Any = None,
                          smp: Any = None,
                          boot_mode: Any = None,
                          extra_args: Any = None,
                          qmp_socket: Any = None,
                          keyboard: Any = None,
                          accel: Any = None,
                          serial_to_stdout: bool = False) -> Dict[str, str]:
    """The knobs for one boot, under the names this architecture's runner reads.

    Three of them -- the durable volume's file and size, and the signed A/B
    system volume -- happen to share a name across all three runners, so they
    are set unconditionally. The rest differ, and that is what this exists for.

    `serial_to_stdout` matters only on RISC-V, whose runner writes the console
    to a file by default. A gate that reads the boot from the runner's stdout,
    as the smoke helper does, needs it; one that reads the log file does not.

    `boot_mode` also matters only on RISC-V, which is the one architecture
    here that can start either way: "kernel" hands the ELF to QEMU, "uefi"
    boots the medium through EDK2. A gate about the A/B system volume needs
    uefi, because with -kernel nothing has chosen a slot.
    """
    env = dict(env)
    if extra_args is not None:
        env["XAIOS_QEMU_EXTRA_ARGS" if arch != "riscv64"
            else "XAIOS_RISCV64_EXTRA_ARGS"] = str(extra_args)
    if qmp_socket is not None:
        env["XAIOS_QEMU_QMP_SOCKET" if arch != "riscv64"
            else "XAIOS_RISCV64_QMP_SOCKET"] = str(qmp_socket)
    if keyboard is not None:
        env["XAIOS_QEMU_KEYBOARD" if arch != "riscv64"
            else "XAIOS_RISCV64_KEYBOARD"] = str(keyboard)
    if persistent is not None:
        env["XAIOS_PERSISTENT_IMAGE"] = str(persistent)
    if persistent_sectors is not None:
        env["XAIOS_PERSISTENT_SECTORS"] = str(persistent_sectors)
    if system_volume is not None:
        env["XAIOS_SYSTEM_VOLUME_IMAGE"] = str(system_volume)
    if arch == "aarch64":
        if accel is not None:
            env["XAIOS_QEMU_ACCEL"] = str(accel)
        if storage_admin is not None:
            env["XAIOS_STORAGE_ADMIN_IMAGE"] = str(storage_admin)
        if hostfwd_port is not None:
            env["XAIOS_QEMU_HOSTFWD_PORT"] = str(hostfwd_port)
        if smp is not None:
            env["XAIOS_QEMU_SMP"] = str(smp)
    elif arch == "x86_64":
        if accel is not None:
            env["XAIOS_QEMU_X86_ACCEL"] = str(accel)
        if persistent is not None:
            # Both names, deliberately: a gate that sets only the shared one
            # for an x86_64 boot falls through to the shared image, whose
            # /state holds whichever run created it. That cost a day once.
            env["XAIOS_X86_PERSISTENT_IMAGE"] = str(persistent)
        if storage_admin is not None:
            env["XAIOS_X86_STORAGE_ADMIN_IMAGE"] = str(storage_admin)
        if hostfwd_port is not None:
            env["XAIOS_QEMU_HOSTFWD_PORT"] = str(hostfwd_port)
        if smp is not None:
            env["XAIOS_QEMU_X86_SMP"] = str(smp)
    else:
        if state_dir is not None:
            env["XAIOS_RISCV64_STATE"] = str(state_dir)
        if hostfwd_port is not None:
            # "none" reaches the runner intact: it understands it, and a gate
            # that wants no host port must be able to say so rather than get
            # the default.
            env["XAIOS_RISCV64_SSH_PORT"] = str(hostfwd_port)
        if smp is not None:
            env["XAIOS_RISCV64_CPUS"] = str(smp)
        if storage_admin is not None:
            env["XAIOS_STORAGE_ADMIN_IMAGE"] = str(storage_admin)
        if boot_mode is not None:
            env["XAIOS_RISCV64_BOOT"] = str(boot_mode)
        # accel has no RISC-V spelling: there is no hypervisor for this
        # architecture on any host this runs on, so it is always TCG. A gate
        # that asks for TCG gets it; one that asked for anything else would be
        # asking for something that does not exist.
        if serial_to_stdout:
            env["XAIOS_RISCV64_SERIAL"] = "stdio"
    return env


def smoke_command(arch: str) -> List[str]:
    """The boot-closure helper, for this architecture.

    Gates that need a full boot before they assert anything run the smoke
    helper rather than a runner, which is what lets them follow the machine
    rather than name it.
    """
    command = ["python3", "./tests/scripts/qemu-smoke.py"]
    if arch != "aarch64":
        command += ["--arch", arch]
    return command


def smoke_timeout(arch: str, base: int) -> int:
    """A budget scaled to the machine rather than to the fastest one.

    RISC-V runs the same closure through an interpreter with no host
    acceleration available for it. Gates were written with AArch64's numbers,
    and reusing them would report a slower machine as a broken one.
    """
    return base * 4 if arch == "riscv64" else base


def qemu_runner(arch: str) -> str:
    """The script that starts this machine.

    Gates that drive the boot themselves -- reading the console, cutting
    power, rebooting -- cannot go through make, so they need the runner. They
    should still not name one.
    """
    return f"./platform/qemu/run-qemu-{arch}.sh"
