#!/usr/bin/env python3
# Annotations are strings, so the ones written in the syntax of a newer Python
# than the one running this are not evaluated at import time. Apple's system
# python3 is 3.9, and `Optional[Dict[str, str]]` in a signature is evaluated --
# and raises TypeError -- on it. Every gate that imports this module failed at
# import on such a machine, which is why the library carries the future import
# and the Optional spellings below rather than a minimum version nobody
# installs.
from __future__ import annotations

import json
import os
import signal
import re
import select
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------- re-exports
#
# The architecture/QEMU-runner helpers and the terminal replay moved to sibling
# modules so that this shared helper keeps its size down. Every gate imports
# them from this module, so they are imported here under their original names
# and the split is invisible to a caller.
from qemu_gate_arch import (  # noqa: E402
    QEMU_ARCHES,
    _MAKE_TARGETS,
    _QEMU_ENV_ALIASES,
    arch_from_argv,
    qemu_boot_environment,
    qemu_make_target,
    qemu_runner,
    smoke_command,
    smoke_timeout,
    timeout_scale,
    translate_qemu_env,
)
from qemu_gate_terminal import (  # noqa: E402
    _replay,
    render_terminal,
    render_terminal_frames,
)


ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
CONTRACT_PATH = ROOT / "contracts/qemu-rc-v1.json"


def run(cmd: Sequence[str], timeout: int = 180,
        env: Optional[Dict[str, str]] = None) -> subprocess.CompletedProcess[str]:
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


def dropped_line_note(text: str) -> str:
    """A note for a gate's failure output when the guest reported lost lines.

    A missing marker and a dropped line look the same from a gate's side, and
    the kernel says when it has dropped one (`klog: N log lines dropped`).
    Printed with the failure so the reader does not have to know to look for it:
    under load this is the difference between "the machine did not do it" and
    "the machine did it and the console lost the sentence" (B-117). It lives
    here because the fix for that row reached one gate, and the same failure
    then cost a session in another -- every gate that asserts console markers
    should print this rather than leaving the reader to guess.
    """
    total = sum(
        int(count)
        for count in re.findall(r"klog: (\d+) log lines dropped", text)
    )
    if total == 0:
        return ""
    # Which context lost them, when the kernel says so (B-119, second
    # sighting): a drop inside a handler is the short wait working as
    # designed, and a drop outside one is the budget still being wrong. A
    # reader deciding whether to chase the loss needs that difference.
    in_handler = sum(
        int(count)
        for count in re.findall(r"in_handler=(\d+)", text)
    )
    masked = sum(int(count) for count in re.findall(r"masked=(\d+)", text))
    where = ""
    if in_handler or masked:
        where = (f" ({in_handler} from inside a handler, {masked} with "
                 f"interrupts masked)")
    return (f"note: the kernel reported {total} log line(s) dropped while its "
            f"console lock was held{where}, so a missing marker above may be a "
            f"line that was lost rather than work that did not happen")


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


# Where EDK2's RISC-V firmware lives, in the order to look.
#
# B-67: the RISC-V runner defaulted to the Homebrew path alone, so every UEFI
# boot on Linux failed before QEMU started and the release gate reported three
# absent markers -- which reads like a kernel that did not boot, when nothing
# had booted at all. The gates that drive QEMU themselves had the same gap in
# a milder form: they listed /usr/share/qemu/edk2-riscv-code.fd, which is not
# where Debian puts it either, so on the distribution CI runs on they skipped.
# A gate that skips is not a gate that passed.
#
# The names genuinely differ per platform: Homebrew ships edk2-riscv-*.fd,
# Debian's qemu-efi-riscv64 ships RISCV_VIRT_CODE.fd and RISCV_VIRT_VARS.fd.
# platform/qemu/run-qemu-riscv64.sh carries the same list in shell, and
# tests/repository/check-riscv-firmware-paths.py keeps the two in step.
RISCV_FIRMWARE_CODE = (
    "/opt/homebrew/share/qemu/edk2-riscv-code.fd",
    "/usr/local/share/qemu/edk2-riscv-code.fd",
    "/usr/share/qemu-efi-riscv64/RISCV_VIRT_CODE.fd",
    "/usr/share/qemu/edk2-riscv-code.fd",
    "/usr/share/edk2/riscv/RISCV_VIRT_CODE.fd",
)
RISCV_FIRMWARE_VARS = (
    "/opt/homebrew/share/qemu/edk2-riscv-vars.fd",
    "/usr/local/share/qemu/edk2-riscv-vars.fd",
    "/usr/share/qemu-efi-riscv64/RISCV_VIRT_VARS.fd",
    "/usr/share/qemu/edk2-riscv-vars.fd",
    "/usr/share/edk2/riscv/RISCV_VIRT_VARS.fd",
)


def riscv_firmware(kind: str) -> Optional[str]:
    """The first RISC-V firmware file of `kind` ("code" or "vars") that exists.

    An explicit XAIOS_RISCV64_FIRMWARE_CODE / _VARS wins, as it does in the
    runner, so firmware in an unusual place is a variable and not a patch.
    """
    variable = f"XAIOS_RISCV64_FIRMWARE_{kind.upper()}"
    override = os.environ.get(variable)
    if override:
        return override if os.path.isfile(override) else None
    candidates = {"code": RISCV_FIRMWARE_CODE,
                  "vars": RISCV_FIRMWARE_VARS}[kind]
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    return None


class Console:
    """The guest's console, read continuously and timestamped as it arrives.

    B-50 asked for the host's opens timestamped against the guest's poll gaps,
    so the order of the two is a measurement rather than an inference. Two
    things had to change for that to be possible.

    The first is that nothing read this pipe while the probes ran. Every chunk
    the guest printed during the run therefore arrived, as far as the host
    could tell, at the moment the drain afterwards collected it -- so there
    were no arrival times to compare anything against.

    The second matters more than the timestamps. A pipe nobody reads fills,
    and QEMU's write to it then blocks, and a guest whose console write is
    blocked stops doing everything else. The gap this row is about is
    `network: stack was not polled for ms=30839`, and a gate that stops
    reading the console for the length of its probe loop is a candidate cause
    of exactly that. It had to be removed before the measurement could mean
    anything, whichever way the answer goes.
    """

    def __init__(self, process) -> None:
        self._process = process
        self._chunks: list[tuple[float, str]] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        descriptor = self._process.stdout.fileno()
        while not self._stop.is_set():
            ready, _, _ = select.select([descriptor], [], [], 0.2)
            if not ready:
                if self._process.poll() is not None:
                    return
                continue
            try:
                chunk = os.read(descriptor, 65536).decode("utf-8",
                                                          errors="replace")
            except OSError:
                return
            if not chunk:
                return
            with self._lock:
                self._chunks.append((time.monotonic(), chunk))

    def text(self) -> str:
        with self._lock:
            return "".join(chunk for _, chunk in self._chunks)

    def arrivals(self) -> list[tuple[float, str]]:
        with self._lock:
            return list(self._chunks)

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
