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
# What the guest must say, split into the part that is true of every profile
# and the part that names the NIC this bundle was built with.
#
# These two lists were one list with "e1000e" written into it twice, which
# made every Fusion gate unrunnable against the VMXNET3 profile: the guest
# booted perfectly, took a real lease over the card and started sshd, and the
# gate timed out because two markers named a device that was deliberately not
# present. The NIC is read from the VMX that is about to be booted, the same
# way `configured_vcpus` reads the CPU count, so the markers describe the
# machine under test rather than the one the file was written for.
NIC_MARKERS = {
    "e1000e": [
        "e1000e: ready pci=",
        "network-device: selected e1000e",
        "kernel: persistent network stack enabled device=e1000e",
    ],
    "vmxnet3": [
        "vmxnet3: self-test passed",
        "vmxnet3: activated",
        "network-device: selected vmxnet3",
        "kernel: persistent network stack enabled device=vmxnet3",
    ],
}
BOOT_MARKERS = [
    "ahci: ready pci=",
    "xaibootfs: persistent mounted v5",
    "kernel: starting persistent /bin/sshd service",
    # The other side of F-05's boundary, asserted rather than observed. This
    # profile has no firmware RNG and no architectural one, so what seeds the
    # pool is a file carried in the image -- identical on every copy -- and
    # the machine has to say so. A build that quietly reported hardware
    # entropy here would be indistinguishable from a real one in the record,
    # which is worse than having no record.
    "entropy: DEVELOPMENT seed file accepted",
    "entropy: source=development-seed-file",
    # B-19: the loader rounds firmware's address up to the strongest alignment
    # the segments ask for, and this is the one number that says it did.
    # Fusion is where it matters most -- firmware placed the kernel at
    # 0xfd480000 on one boot today and 0xff680000 on another, so the placement
    # this guards changes underneath every run.
    "offset_in_64k 0",
    READY_MARKER,
]
# The userspace applications, which until now ran only under QEMU. Fusion and
# Virtualization.framework booted the same image but built it without the test
# applications, so everything above the shell's own command surface -- the
# syscall suite, the network and SMP tests, the agent protocol, the pipe and
# redirect surface, the control tool -- had never executed on either. A gate
# that checks a kernel reached a login prompt does not tell you the programs a
# person will actually run still work there.
APP_MARKERS = [
    "/bin/xaios-shell: command surface passed",
    "/bin/systest: syscall and filesystem suite passed",
    "/bin/hello: C toolchain and EL0 runtime integration passed",
    "/bin/sysinfo: complete",
    "/bin/nettest: complete",
    "/bin/smptest: complete",
    "/bin/agenttest: agent protocol dispatch passed",
    "/bin/posix-shell: pipe and redirect surface passed",
]
BOOT_MARKERS.extend(APP_MARKERS)
FATAL_MARKERS = ["System halted", "assertion failed", "CYAN SCREEN OF DEATH",
                 # See the note in vz-gate.py: a guest in rescue mode reaches a
                 # login prompt and refuses the commands a person would type.
                 "rescue=1"]
# The boot summary used to be matched as the literal "cpu_online=1", which was
# true only while Fusion was restricted to one vCPU and silently stopped
# matching anything the moment that restriction lifted -- the guest booted
# perfectly and the gate reported it never became ready. Read the number the
# profile actually asks for and require the guest to report that many.
CPU_ONLINE_PATTERN = re.compile(r"telemetry: boot_summary cpu_online=(\d+)")


def configured_nic() -> str:
    """Which NIC the bundle about to be booted presents.

    Read rather than assumed: `XAIOS_FUSION_NIC` selects it at build time and
    a gate run without that variable in its environment would otherwise expect
    e1000e markers from a bundle built for vmxnet3.
    """
    for line in VMX.read_text(encoding="utf-8").splitlines():
        if line.strip().startswith("ethernet0.virtualDev"):
            return line.split("=", 1)[1].strip().strip('"')
    return "e1000e"


def boot_markers() -> list[str]:
    nic = configured_nic()
    if nic not in NIC_MARKERS:
        raise RuntimeError(
            f"the VM bundle presents ethernet0.virtualDev={nic!r}, which this "
            f"gate has no markers for; add them to NIC_MARKERS rather than "
            f"letting the boot be checked against another card's log lines")
    return BOOT_MARKERS + NIC_MARKERS[nic]


def configured_vcpus() -> int:
    for line in VMX.read_text(encoding="utf-8").splitlines():
        if line.strip().startswith("numvcpus"):
            return int(line.split("=", 1)[1].strip().strip('"'))
    return 1
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
        "XAIOS_BOOT_TEST_APPS": "1",
        "XAIOS_AUTHORIZED_KEYS_FILE": str(TEST_KEY_PUBLIC),
    })
    build = run(["./scripts/build-image.sh"], env=environment, timeout=600)
    print(build.stdout, end="")
    # Measured at roughly 200s on an eight-core host, and variable: the build
    # probes a registry it may not reach before falling back to the cached
    # chainloader image. 600 was tight enough that a slow probe failed the gate
    # rather than the guest.
    package = run(["./platform/vmware-fusion/build-vmware-fusion.sh"],
                  env=environment, timeout=900)
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


def cpu_capability() -> dict[str, object]:
    """Report the vCPU result this run produced, rather than a fixed sentence.

    This field used to read "qualified single-vCPU profile; Fusion firmware
    does not advertise PSCI CPU_ON". It was written when Fusion secondaries
    did not start, and it stayed behind when they did: F-01 was a defect of
    ours, not a platform limit, and the guest has been coming up on four vCPUs
    since. The gate was publishing evidence that understated the machine it
    had just booted, which is worse than publishing nothing -- a reader has no
    way to tell a stale claim from a measured one.

    The second half was never wrong, only irrelevant. Firmware does not
    advertise PSCI, and answers it anyway; the guest says so itself. So that
    is read from the log too rather than asserted here.
    """
    text = serial_text()
    configured = None
    if VMX.exists():
        match = re.search(
            r'^\s*numvcpus\s*=\s*"(\d+)"',
            VMX.read_text(encoding="utf-8", errors="replace"),
            re.MULTILINE,
        )
        configured = int(match.group(1)) if match else None
    online = re.search(r"cpu_online=(\d+)", text)
    admitted = re.search(r"smp: PSCI admitted=(\d+) rejected=(\d+)", text)
    return {
        "vcpus_configured": configured,
        "vcpus_online": int(online.group(1)) if online else None,
        "psci_admitted": int(admitted.group(1)) if admitted else None,
        "psci_rejected": int(admitted.group(2)) if admitted else None,
        "psci_advertised": "firmware answers PSCI" not in text,
        "note": (
            "Read from this run's serial log and .vmx. Fusion firmware does "
            "not advertise PSCI and answers it regardless, so secondaries "
            "start; a run that brings up fewer vCPUs than are configured is "
            "the signal, not this sentence."
        ),
    }


def wait_for_boot(after_ready_count: int) -> tuple[str, str]:
    deadline = time.monotonic() + TIMEOUT_SECONDS
    last_missing: list[str] = ["the ready marker itself"]
    while time.monotonic() < deadline:
        output = serial_text()
        fatal = [marker for marker in FATAL_MARKERS if marker in output]
        if fatal:
            raise RuntimeError(f"Fusion guest reported fatal markers {fatal!r}\n{serial_tail()}")
        if output.count(READY_MARKER) > after_ready_count:
            missing = [marker for marker in boot_markers()
                       if marker not in output]
            expected_cpus = configured_vcpus()
            reported = [int(count) for count in CPU_ONLINE_PATTERN.findall(output)]
            if not reported:
                missing.append("telemetry: boot_summary cpu_online=")
            elif reported[-1] != expected_cpus:
                missing.append(
                    f"boot summary reported cpu_online={reported[-1]}, "
                    f"but the profile asks for {expected_cpus}")
            addresses = IPV4_PATTERN.findall(output)
            if not missing and addresses:
                return addresses[-1], output
            # Kept for the timeout below. Without it the deadline expired
            # with "did not become ready" and eighty lines of a console
            # showing a machine that had booted, logged in and started sshd,
            # and nothing said which marker was absent.
            last_missing = missing if missing else ["an IPv4 address"]
        if not vm_running():
            raise RuntimeError(f"Fusion VM stopped before guest became ready\n{serial_tail()}")
        time.sleep(0.5)
    raise TimeoutError(
        f"Fusion guest did not become ready; still missing {last_missing}\n"
        f"{serial_tail()}")


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

    # Discard the previous run's console before anything else can fail.
    #
    # This was cleared inside start_vm, which happens after the image build.
    # So a build that failed -- a missing tool, a broken submodule, anything
    # before the guest exists -- reported the *previous* run's boot underneath
    # its error, and that boot ends at a healthy login prompt. A missing
    # docker on PATH read as a guest fault for exactly this reason. Clearing
    # it here means the console shown beside a failure is either this run's or
    # visibly absent.
    SERIAL.unlink(missing_ok=True)

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
            "Fusion 26H1 ARM64 UEFI boot, ACPI/PCI E1000E DHCP, AHCI xaibootFS, "
            "Mac-local public-key SSH/SFTP, crash recovery, guest reboot, orderly "
            "shutdown, and repeat-boot persistence; not physical-performance evidence"
        ),
        "cpu_capability": cpu_capability(),
        "performance_evidence": False,
    }
    FUSION_BUILD.mkdir(parents=True, exist_ok=True)
    EVIDENCE.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if result != "passed":
        console = serial_tail()
        print(
            "Fusion guest closure failed:\n" + "\n".join(failures) + "\n"
            + ("guest console (last 80 lines of this run):\n" + console
               if console.strip()
               else "no guest console: the failure is before the guest booted, "
                    "so this is a host-side or build problem, not a guest one"),
            file=sys.stderr,
        )
        return 1
    print(
        "VMware Fusion guest closure passed: "
        f"version={evidence['vmware_fusion_version']} elapsed={evidence['elapsed_seconds']}s"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
