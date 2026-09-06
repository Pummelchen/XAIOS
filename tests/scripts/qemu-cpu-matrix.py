#!/usr/bin/env python3
import json
import os
import select
import shutil
import signal
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


CONTRACT_PATH = "contracts/qemu-rc-v1.json"
REPORT_PATH = os.environ.get(
    "XAIOS_QEMU_CPU_MATRIX_REPORT", "build/qemu-cpu-matrix-report.json"
)
SCHEMA = "xaios.qemu.cpu_matrix.v1"
BOOT_PROBE_MARKERS = [
    "kernel starting",  # "XAIOS <version> kernel starting"
    "smp: per-core registry self-test passed",
    "VMM map/unmap self-test passed",
    "VMM translation test passed",
    "virtio-blk: read/write/error/reset self-test passed",
    "persistence: disk reload/rollback self-test passed",
]


def find_qemu(binary: str) -> Optional[str]:
    candidates = [
        shutil.which(binary),
        f"/opt/homebrew/opt/qemu/bin/{binary}",
        f"/opt/homebrew/bin/{binary}",
        f"/usr/local/bin/{binary}",
    ]
    for candidate in candidates:
        if candidate and os.path.exists(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def cpu_help_set(qemu: str) -> Set[str]:
    proc = subprocess.run(
        [qemu, "-cpu", "help"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    supported: Set[str] = set()
    for line in proc.stdout.splitlines():
        parts = line.strip().split()
        if not parts:
            continue
        supported.add(parts[0])
    return supported


def run(cmd: List[str], env: Dict[str, str], timeout: int) -> subprocess.CompletedProcess:
    print(f"qemu-cpu-matrix: running {' '.join(cmd)}", flush=True)
    return subprocess.run(
        cmd,
        check=False,
        env=env,
        timeout=timeout,
        stdout=None,
        stderr=None,
        text=True,
    )


def run_until_markers(cmd: List[str], env: Dict[str, str], timeout: int,
                      markers: List[str]) -> Dict[str, Any]:
    print(f"qemu-cpu-matrix: probing {' '.join(cmd)}", flush=True)
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=False,
        bufsize=0,
        env=env,
    )
    seen: List[str] = []
    deadline = time.time() + timeout
    matched = False
    try:
        assert proc.stdout is not None
        fd = proc.stdout.fileno()
        while time.time() < deadline:
            ready, _, _ = select.select([fd], [], [], 0.2)
            if ready:
                chunk = os.read(fd, 4096).decode("utf-8", errors="replace")
                if not chunk:
                    break
                seen.append(chunk)
                text = "".join(seen)
                if all(marker in text for marker in markers):
                    matched = True
                    break
            elif proc.poll() is not None:
                break
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)

    text = "".join(seen)
    missing = [marker for marker in markers if marker not in text]
    if not matched:
        tail = text[-4000:]
        if tail:
            print("qemu-cpu-matrix: boot probe tail follows")
            print(tail)
    return {
        "exit_code": 0 if matched else (proc.returncode if proc.returncode is not None else 1),
        "matched": matched,
        "missing_markers": missing,
    }


def run_arm_boot_tier(tier: Dict[str, Any], supported: Set[str],
                      base_env: Dict[str, str]) -> Dict[str, Any]:
    cpu = tier["cpu"]
    accelerator = tier["accelerator"]
    name = tier["name"]
    required = tier.get("required", True)
    if (not required and accelerator == "hvf" and
            base_env.get("XAIOS_QEMU_RUN_OPTIONAL_HVF") != "1"):
        return {
            "name": name,
            "architecture": "aarch64",
            "cpu": cpu,
            "accelerator": accelerator,
            "validation": tier["validation"],
            "required": False,
            "supported": None,
            "exit_code": None,
            "status": "skipped",
            "reason": "set XAIOS_QEMU_RUN_OPTIONAL_HVF=1 to run experimental HVF",
        }
    if cpu != "host" and cpu not in supported:
        return {
            "name": name,
            "architecture": "aarch64",
            "cpu": cpu,
            "accelerator": accelerator,
            "validation": tier["validation"],
            "required": required,
            "supported": False,
            "exit_code": 1 if required else None,
            "status": "fail" if required else "skipped",
            "error": "cpu model not listed by qemu-system-aarch64 -cpu help",
        }

    if tier["validation"] == "qemu-smoke-default":
        env = base_env.copy()
        env["XAIOS_QEMU_ACCEL"] = accelerator
        env["XAIOS_QEMU_CPU"] = cpu
        proc = run(["python3", "./tests/scripts/qemu-smoke.py"], env, 140)
        return {
            "name": name,
            "architecture": "aarch64",
            "cpu": cpu,
            "accelerator": accelerator,
            "validation": tier["validation"],
            "required": required,
            "supported": True,
            "exit_code": proc.returncode,
            "status": "pass" if proc.returncode == 0 else "fail",
        }

    env = base_env.copy()
    env["XAIOS_QEMU_ACCEL"] = accelerator
    env["XAIOS_QEMU_CPU"] = cpu
    env["XAIOS_QEMU_HOSTFWD_PORT"] = "none"
    env.setdefault("XAIOS_QEMU_SMOKE_TIMEOUT", "90")
    probe = run_until_markers(["make", "qemu-aarch64"], env, 100,
                              BOOT_PROBE_MARKERS)
    return {
        "name": name,
        "architecture": "aarch64",
        "cpu": cpu,
        "accelerator": accelerator,
        "validation": tier["validation"],
        "required": required,
        "supported": True,
        "exit_code": probe["exit_code"],
        "missing_markers": probe["missing_markers"],
        "status": "pass" if probe["matched"] else "fail",
    }


# What a hart that cannot run this kernel has to say.
#
# The kernel needs Sv48, because that is where its address-space layout puts
# userspace, and it refuses rather than falling back -- Sv39 cannot address
# 511 GiB, so a fallback would boot and then fail somewhere far less
# obvious. Several real harts offer only Sv39, including the two standard
# RISC-V application profiles, so "refuses in one line" is a property worth
# holding the kernel to rather than a case to leave untested.
RISCV_REFUSAL = "Sv48 refused by this hart"

# What a booting RISC-V hart has to say, in its own words.
#
# The shared list above is AArch64's wording, and two of its lines have no
# RISC-V equivalent by design: this port has no per-core registry self-test
# under that name, and its MMU reports one line covering map, translate,
# write and unmap rather than two. The project's rule is that every
# architecture describes its own interrupt controller, page tables and timer
# in its own words, so matching AArch64's strings here would either fail
# forever or force this port to imitate another. What is shared is the claim:
# the kernel started, the harts came up, paging works, the disk works, and
# durable state reloaded.
RISCV_BOOT_MARKERS = [
    "kernel starting",
    "smp: riscv64 self-test passed",
    "vmm: self-test passed (map, translate, write, unmap)",
    "virtio-blk: read/write/error/reset self-test passed",
    "persistence: disk reload/rollback self-test passed",
]


def run_until_markers_in_file(cmd: List[str], env: Dict[str, str],
                              log: str, timeout: int,
                              markers: List[str]) -> Dict[str, Any]:
    """Watch a console the emulator writes to a file, rather than a pipe.

    The RISC-V runner writes its console to a file by default and can be told
    to use stdio instead. stdio is the wrong choice for a matrix: `-serial
    stdio` makes the guest's console the process's standard input as well, and
    a run of a dozen emulators started one after another inherits a standard
    input that has already reached end of file -- at which point QEMU quits
    immediately and the tier reports a hart that produced no output at all.
    That happened, on the fourth tier, to a hart that boots perfectly when
    started on its own.
    """
    print(f"qemu-cpu-matrix: probing {' '.join(cmd)}", flush=True)
    path = Path(log)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.unlink(missing_ok=True)
    # The emulator's own complaints go beside the console, not to /dev/null.
    # A tier whose emulator refused to start -- a volume still locked by a
    # previous tier's process, a machine type this build does not have --
    # otherwise reports an empty console and a hart that said nothing, which
    # reads as a broken kernel and is a broken bench.
    errors = path.with_name("qemu-stderr.log")
    with errors.open("wb") as sink:
        proc = subprocess.Popen(cmd, env=env, stdin=subprocess.DEVNULL,
                                stdout=sink, stderr=subprocess.STDOUT,
                                start_new_session=True)
    deadline = time.time() + timeout
    text = ""
    matched = False
    try:
        while time.time() < deadline:
            time.sleep(1.0)
            if path.is_file():
                text = path.read_text(errors="replace")
                if all(marker in text for marker in markers):
                    matched = True
                    break
            if proc.poll() is not None:
                break
    finally:
        if proc.poll() is None:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                proc.wait(timeout=10)
    if path.is_file():
        text = path.read_text(errors="replace")
    missing = [marker for marker in markers if marker not in text]
    complaint = errors.read_text(errors="replace").strip() \
        if errors.is_file() else ""
    if not matched:
        print("qemu-cpu-matrix: boot probe tail follows")
        print(text[-4000:] if text else "  (the console was empty)")
        if complaint:
            print("qemu-cpu-matrix: the emulator said:")
            print(complaint[-2000:])
    return {"exit_code": 0 if matched else 1, "matched": matched,
            "missing_markers": missing,
            "emulator_stderr": complaint[-500:] if complaint else None}


def run_riscv_tier(tier: Dict[str, Any], supported: Set[str],
                   base_env: Dict[str, str]) -> Dict[str, Any]:
    cpu = tier["cpu"]
    validation = tier["validation"]
    required = tier.get("required", True)
    result: Dict[str, Any] = {
        "name": tier["name"],
        "architecture": "riscv64",
        "cpu": cpu,
        "accelerator": tier["accelerator"],
        "validation": validation,
        "required": required,
    }
    if cpu not in supported:
        result.update({
            "supported": False,
            "exit_code": 1 if required else None,
            "status": "fail" if required else "skipped",
            "error": "cpu model not listed by qemu-system-riscv64 -cpu help",
        })
        return result

    env = base_env.copy()
    env["XAIOS_RISCV64_CPU"] = cpu
    env["XAIOS_RISCV64_SSH_PORT"] = "none"
    # A state directory and a console per hart. Two tiers sharing either would
    # have the second boot whatever the first left behind, or read the first's
    # log and pass on it.
    env["XAIOS_RISCV64_STATE"] = f"build/cpu-matrix-riscv64/{cpu}"
    log = f"build/cpu-matrix-riscv64/{cpu}/console.log"
    env["XAIOS_RISCV64_LOG"] = log
    os.makedirs(env["XAIOS_RISCV64_STATE"], exist_ok=True)
    command = ["./platform/qemu/run-qemu-riscv64.sh"]
    if validation == "qemu-boot-refusal":
        # Watched for the refusal, not for the markers. This tier passes when
        # the machine says it cannot run this kernel and stops, and fails if
        # it says nothing -- a hart that halted silently, or worse booted part
        # of the way, is the failure this exists to catch.
        probe = run_until_markers_in_file(command, env, log, 240,
                                          [RISCV_REFUSAL])
        result.update({
            "supported": True,
            "exit_code": probe["exit_code"],
            "missing_markers": probe["missing_markers"],
            "status": "pass" if probe["matched"] else "fail",
            "expected": "a refusal naming Sv48",
        })
        return result

    # RISC-V has no host acceleration here, so the budget is the machine's
    # rather than AArch64's; this is a deadline, not a delay.
    probe = run_until_markers_in_file(command, env, log, 400,
                                      RISCV_BOOT_MARKERS)
    matched = probe["matched"]
    result.update({
        "supported": True,
        "exit_code": probe["exit_code"],
        "missing_markers": probe["missing_markers"],
        "status": "pass" if matched else "fail",
    })
    return result


def run_x86_tier(tier: Dict[str, Any], supported: Set[str],
                 base_env: Dict[str, str]) -> Dict[str, Any]:
    cpu = tier["cpu"]
    env = base_env.copy()
    env["XAIOS_QEMU_X86_CPU"] = cpu
    validation = tier["validation"]
    required = tier.get("required", True)
    supported_by_qemu = cpu == "max" or cpu in supported
    if not supported_by_qemu:
        return {
            "name": tier["name"],
            "architecture": "x86_64",
            "cpu": cpu,
            "validation": validation,
            "required": required,
            "supported": False,
            "exit_code": 1 if required else None,
            "status": "fail" if required else "skipped",
            "error": "cpu model not listed by qemu-system-x86_64 -cpu help",
        }

    if validation == "qemu-smoke":
        env.setdefault("XAIOS_QEMU_SMOKE_TIMEOUT", "90")
        proc = run(["python3", "./tests/scripts/qemu-x86_64-smoke.py"], env, 140)
    else:
        proc = run(["./platform/qemu/run-qemu-x86_64.sh", "--dry-run"], env, 20)
    return {
        "name": tier["name"],
        "architecture": "x86_64",
        "cpu": cpu,
        "validation": validation,
        "required": required,
        "supported": supported_by_qemu,
        "exit_code": proc.returncode,
        "status": "pass" if supported_by_qemu and proc.returncode == 0 else "fail",
    }


def main() -> int:
    os.makedirs("build", exist_ok=True)
    architecture_filter = os.environ.get("XAIOS_QEMU_CPU_MATRIX_ARCH", "all")
    if architecture_filter not in {"all", "aarch64", "x86_64", "riscv64"}:
        print("qemu-cpu-matrix: XAIOS_QEMU_CPU_MATRIX_ARCH must be "
              "all, aarch64, x86_64, or riscv64")
        return 2
    run_aarch64 = architecture_filter in {"all", "aarch64"}
    run_x86_64 = architecture_filter in {"all", "x86_64"}
    run_riscv64 = architecture_filter in {"all", "riscv64"}

    with open(CONTRACT_PATH, "r", encoding="utf-8") as handle:
        contract = json.load(handle)

    qemu_aarch64 = find_qemu("qemu-system-aarch64") if run_aarch64 else None
    qemu_x86_64 = find_qemu("qemu-system-x86_64") if run_x86_64 else None
    qemu_riscv64 = find_qemu("qemu-system-riscv64") if run_riscv64 else None
    failures: List[str] = []
    if run_aarch64 and qemu_aarch64 is None:
        failures.append("qemu-system-aarch64 not found")
    if run_x86_64 and qemu_x86_64 is None:
        failures.append("qemu-system-x86_64 not found")
    if run_riscv64 and qemu_riscv64 is None:
        failures.append("qemu-system-riscv64 not found")

    arm_supported = cpu_help_set(qemu_aarch64) if qemu_aarch64 else set()
    x86_supported = cpu_help_set(qemu_x86_64) if qemu_x86_64 else set()
    riscv_supported = cpu_help_set(qemu_riscv64) if qemu_riscv64 else set()
    base_env = os.environ.copy()
    base_env.setdefault("XAIOS_QEMU_SMOKE_TIMEOUT", "90")

    tiers: List[Dict[str, Any]] = []
    if qemu_aarch64:
        arm_tiers = sorted(
            contract["cpu_matrix"]["arm64_boot_tiers"],
            key=lambda tier: not tier.get("required", True),
        )
        for tier in arm_tiers:
            result = run_arm_boot_tier(tier, arm_supported, base_env)
            tiers.append(result)
            if result["status"] != "pass" and result["required"]:
                failures.append(f"arm64 tier failed: {tier['name']}")
    if qemu_x86_64:
        if any(tier.get("validation") == "qemu-smoke"
               for tier in contract["cpu_matrix"]["x86_64_command_tiers"]):
            image_proc = run(["make", "image-x86_64-qemu-test"], base_env,
                             120)
            if image_proc.returncode != 0:
                failures.append("x86_64 image build failed for CPU matrix")
        for tier in contract["cpu_matrix"]["x86_64_command_tiers"]:
            result = run_x86_tier(tier, x86_supported, base_env)
            tiers.append(result)
            if result["status"] != "pass" and result["required"]:
                failures.append(f"x86_64 tier failed: {tier['name']}")

    if qemu_riscv64:
        # Built once for the whole architecture. Every tier boots the same
        # kernel on a different hart, so rebuilding per tier would be
        # measuring the compiler twelve times.
        build = run(["./scripts/build-riscv64.sh"],
                    {**base_env, "XAIOS_BOOT_TEST_APPS": "1"}, 600)
        if build.returncode != 0:
            failures.append("riscv64 kernel build failed for CPU matrix")
        else:
            for tier in contract["cpu_matrix"]["riscv64_boot_tiers"]:
                result = run_riscv_tier(tier, riscv_supported, base_env)
                tiers.append(result)
                if result["status"] != "pass" and result["required"]:
                    failures.append(f"riscv64 tier failed: {tier['name']}")

    report = {
        "schema": SCHEMA,
        "created_unix": int(time.time()),
        "status": "fail" if failures else "pass",
        "contract": CONTRACT_PATH,
        "architecture_filter": architecture_filter,
        "qemu": {
            "aarch64": qemu_aarch64,
            "x86_64": qemu_x86_64,
            "riscv64": qemu_riscv64,
        },
        "tiers": tiers,
        "optional_failures": [
            tier["name"] for tier in tiers
            if not tier["required"] and tier["status"] == "fail"
        ],
        "optional_skipped": [
            tier["name"] for tier in tiers
            if not tier["required"] and tier["status"] == "skipped"
        ],
        "failures": failures,
    }

    with open(REPORT_PATH, "w", encoding="utf-8") as handle:
        json.dump(report, handle, sort_keys=True, indent=2)
    print(f"qemu-cpu-matrix: report written to {REPORT_PATH}")

    if failures:
        print("qemu-cpu-matrix: failed")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("qemu-cpu-matrix: all CPU tiers passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
