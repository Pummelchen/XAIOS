#!/usr/bin/env python3
"""Exercise the complete supported XAIOS VMware Fusion ARM64 guest path."""

from __future__ import annotations

import json
import os
import platform
import plistlib
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
FUSION_BUILD = BUILD / "vmware-fusion"
VM_BUNDLE = FUSION_BUILD / "XAIOS.vmwarevm"
VMX = VM_BUNDLE / "XAIOS.vmx"
SERIAL = VM_BUNDLE / "fusion-serial.log"
EVIDENCE = FUSION_BUILD / "fusion-smoke-evidence.json"
TEST_KEY = BUILD / "fusion-closure-key"
TEST_KEY_PUBLIC = TEST_KEY.with_suffix(".pub")
SFTP_UPLOAD = BUILD / "fusion-closure-upload.txt"
SFTP_DOWNLOAD = BUILD / "fusion-closure-download.txt"
VMRUN = Path(os.environ.get(
    "XAIOS_VMRUN",
    "/Applications/VMware Fusion.app/Contents/Library/vmrun",
))
TIMEOUT_SECONDS = int(os.environ.get("XAIOS_FUSION_TIMEOUT", "240"))
READY_MARKER = "SSH server: up and running (tcp/22)"
BOOT_MARKERS = [
    "e1000e: ready pci=",
    "ahci: ready pci=",
    "mutable-fs: persistent mounted v5",
    "kernel: persistent network stack enabled device=e1000e",
    "telemetry: boot_summary cpu_online=1",
    "kernel: starting persistent /bin/sshd service",
    READY_MARKER,
]
FATAL_MARKERS = ["System halted", "assertion failed", "CYAN SCREEN OF DEATH"]
IPV4_PATTERN = re.compile(r"^IPv4: ([0-9]{1,3}(?:\.[0-9]{1,3}){3})$", re.MULTILINE)


def run(command: list[str], *, env: dict[str, str] | None = None,
        timeout: int = 300, check: bool = True) -> subprocess.CompletedProcess[str]:
    print("+", " ".join(command), flush=True)
    return subprocess.run(command, cwd=ROOT, env=env, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          timeout=timeout, check=check)


def fusion_version() -> str:
    info = Path("/Applications/VMware Fusion.app/Contents/Info.plist")
    with info.open("rb") as handle:
        values = plistlib.load(handle)
    return str(values.get("CFBundleShortVersionString", "unknown"))


def git_revision() -> str:
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()


def ensure_test_key() -> None:
    if TEST_KEY.is_file() and TEST_KEY_PUBLIC.is_file():
        return
    TEST_KEY.unlink(missing_ok=True)
    TEST_KEY_PUBLIC.unlink(missing_ok=True)
    generated = run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(TEST_KEY)]
    )
    print(generated.stdout, end="")
    TEST_KEY.chmod(0o600)


def build_guest() -> None:
    ensure_test_key()
    environment = os.environ.copy()
    environment.update({
        "XAIOS_BOOT_VERBOSE": "1",
        "XAIOS_AUTHORIZED_KEYS_FILE": str(TEST_KEY_PUBLIC),
    })
    build = run(["./scripts/build-image.sh"], env=environment, timeout=600)
    print(build.stdout, end="")
    package = run(["./platform/vmware-fusion/build-vmware-fusion.sh"], env=environment, timeout=600)
    print(package.stdout, end="")


def vmrun(arguments: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return run([str(VMRUN), "-T", "fusion", *arguments], timeout=90, check=check)


def vm_running() -> bool:
    result = vmrun(["list"], check=False)
    return str(VMX.resolve()) in result.stdout


def serial_text() -> str:
    return SERIAL.read_text(encoding="utf-8", errors="replace") if SERIAL.exists() else ""


def serial_tail() -> str:
    return "\n".join(serial_text().splitlines()[-80:])


def wait_for_boot(after_ready_count: int) -> tuple[str, str]:
    deadline = time.monotonic() + TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        output = serial_text()
        fatal = [marker for marker in FATAL_MARKERS if marker in output]
        if fatal:
            raise RuntimeError(f"Fusion guest reported fatal markers {fatal!r}\n{serial_tail()}")
        if output.count(READY_MARKER) > after_ready_count:
            missing = [marker for marker in BOOT_MARKERS if marker not in output]
            addresses = IPV4_PATTERN.findall(output)
            if not missing and addresses:
                return addresses[-1], output
        if not vm_running():
            raise RuntimeError(f"Fusion VM stopped before guest became ready\n{serial_tail()}")
        time.sleep(0.5)
    raise TimeoutError(f"Fusion guest did not become ready\n{serial_tail()}")


def start_vm(after_ready_count: int) -> tuple[str, str]:
    if vm_running():
        raise RuntimeError("Fusion VM is already running")
    if after_ready_count == 0:
        SERIAL.unlink(missing_ok=True)
    started = vmrun(["start", str(VMX), "nogui"])
    if started.stdout:
        print(started.stdout, end="")
    return wait_for_boot(after_ready_count)


def wait_for_stopped() -> None:
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        if not vm_running():
            return
        time.sleep(0.5)
    raise TimeoutError("Fusion VM did not power off after XAIOS shutdown")


def stop_hard() -> None:
    if vm_running():
        vmrun(["stop", str(VMX), "hard"], check=False)
    wait_for_stopped()


def ssh_base(address: str) -> list[str]:
    return [
        "ssh", "-F", "/dev/null", "-i", str(TEST_KEY),
        "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
        "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
        "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=5",
        f"admin@{address}",
    ]


def ssh(address: str, command: str, *, timeout: int = 30) -> str:
    deadline = time.monotonic() + 60.0
    last = ""
    while time.monotonic() < deadline:
        result = subprocess.run(ssh_base(address) + [command], cwd=ROOT,
                                text=True, capture_output=True, timeout=timeout)
        if result.returncode == 0:
            return result.stdout
        last = f"rc={result.returncode} stdout={result.stdout} stderr={result.stderr}"
        time.sleep(0.5)
    raise RuntimeError(f"Fusion SSH command failed: {command}\n{last}")


def sftp_round_trip(address: str) -> None:
    SFTP_UPLOAD.write_text("fusion-sftp-round-trip\n", encoding="utf-8")
    SFTP_DOWNLOAD.unlink(missing_ok=True)
    batch = (
        f'put "{SFTP_UPLOAD}" /tmp/fusion-sftp.txt\n'
        f'get /tmp/fusion-sftp.txt "{SFTP_DOWNLOAD}"\n'
    )
    result = subprocess.run(
        ["sftp", "-F", "/dev/null", "-i", str(TEST_KEY),
         "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
         "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
         "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
         "-o", "LogLevel=ERROR", "-b", "-", f"admin@{address}"],
        cwd=ROOT, input=batch, text=True, capture_output=True, timeout=60,
    )
    if result.returncode != 0 or not SFTP_DOWNLOAD.is_file() or \
            SFTP_DOWNLOAD.read_text(encoding="utf-8") != "fusion-sftp-round-trip\n":
        raise RuntimeError(
            f"Fusion SFTP round trip failed rc={result.returncode}\n"
            f"stdout={result.stdout}\nstderr={result.stderr}"
        )


def require(value: str, marker: str) -> None:
    if marker not in value:
        raise RuntimeError(f"missing {marker!r} in {value!r}")


def main() -> int:
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise SystemExit("VMware Fusion smoke requires Apple Silicon macOS")
    if not VMRUN.is_file() or not os.access(VMRUN, os.X_OK):
        raise SystemExit(f"vmrun is unavailable: {VMRUN}")
    if fusion_version() != "26.0.0":
        raise SystemExit(f"VMware Fusion 26H1 requires 26.0.0, got {fusion_version()!r}")
    for tool in ("ssh", "sftp", "ssh-keygen"):
        if not shutil.which(tool):
            raise SystemExit(f"required macOS client tool unavailable: {tool}")

    started = time.monotonic()
    result = "failed"
    failures: list[str] = []
    guest_addresses: list[str] = []
    checks: dict[str, str] = {}
    try:
        stop_hard()
        build_guest()

        first_address, _ = start_vm(0)
        guest_addresses.append(first_address)
        require(ssh(first_address, "echo fusion-ssh-ready"), "fusion-ssh-ready")
        ssh(first_address, "write /state/fusion-closure.txt fusion-persistent")
        require(ssh(first_address, "cat /state/fusion-closure.txt"), "fusion-persistent")
        sftp_round_trip(first_address)
        checks["boot_network_ssh_sftp"] = "pass"
        stop_hard()

        second_address, _ = start_vm(0)
        guest_addresses.append(second_address)
        require(ssh(second_address, "recovery status"), "unclean_boots=1")
        require(ssh(second_address, "cat /state/fusion-closure.txt"), "fusion-persistent")
        checks["crash_recovery_persistence"] = "pass"

        ready_before_reboot = serial_text().count(READY_MARKER)
        ssh(second_address, "reboot")
        rebooted_address, _ = wait_for_boot(ready_before_reboot)
        guest_addresses.append(rebooted_address)
        require(ssh(rebooted_address, "echo fusion-reboot-ready"), "fusion-reboot-ready")
        checks["guest_reboot"] = "pass"

        ssh(rebooted_address, "shutdown")
        wait_for_stopped()
        require(serial_text(), "operations: storage quiesced")
        checks["orderly_shutdown"] = "pass"

        final_address, _ = start_vm(0)
        guest_addresses.append(final_address)
        require(ssh(final_address, "recovery status"), "unclean_boots=0")
        require(ssh(final_address, "cat /state/fusion-closure.txt"), "fusion-persistent")
        checks["repeat_boot_clean_persistence"] = "pass"
        ssh(final_address, "shutdown")
        wait_for_stopped()
        result = "passed"
    except (OSError, RuntimeError, subprocess.SubprocessError, TimeoutError) as error:
        failures.append(str(error))
    finally:
        try:
            stop_hard()
        except (OSError, RuntimeError, subprocess.SubprocessError, TimeoutError) as error:
            failures.append(f"cleanup: {error}")

    evidence = {
        "schema_version": 2,
        "result": result,
        "host": {"system": platform.system(), "machine": platform.machine()},
        "vmware_fusion_version": fusion_version(),
        "source_commit": git_revision(),
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "guest_addresses": guest_addresses,
        "checks": checks,
        "failures": failures,
        "scope": (
            "Fusion 26H1 ARM64 UEFI boot, ACPI/PCI E1000E DHCP, AHCI MutableFS, "
            "Mac-local public-key SSH/SFTP, crash recovery, guest reboot, orderly "
            "shutdown, and repeat-boot persistence; not physical-performance evidence"
        ),
        "cpu_capability": "qualified single-vCPU profile; Fusion firmware does not advertise PSCI CPU_ON",
        "performance_evidence": False,
    }
    FUSION_BUILD.mkdir(parents=True, exist_ok=True)
    EVIDENCE.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if result != "passed":
        print("Fusion guest closure failed:\n" + "\n".join(failures) + "\n" + serial_tail(), file=sys.stderr)
        return 1
    print(
        "VMware Fusion guest closure passed: "
        f"version={evidence['vmware_fusion_version']} elapsed={evidence['elapsed_seconds']}s"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
