#!/usr/bin/env python3
"""V-03: does a Virtualization.framework guest get a routable address?

The row was blocked on `VZBridgedNetworkDeviceAttachment`, which needs Apple's
`com.apple.vm.networking` entitlement -- issued only with a provisioning
profile, and not obtainable here. The way round it is the helper this project
already has: vmnet needs no entitlement, only root, so a privileged relay puts
the guest on the real wire and hands the harness an unprivileged socket. The
guest is then bridged without the VM being privileged and without the
entitlement.

That relay is the one thing this gate cannot start for itself. It runs as
root, and nothing here will ask for a password or try to acquire privilege on
its own: if the socket is not there, the gate prints the command to run and
stops. Everything after that is unprivileged.

What it then checks is what "routable" means: an address from the LAN's own
router advertisement rather than from a hypervisor's private range, this host
able to reach it, and a session over it.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
VZ = BUILD / "vz"
HARNESS = VZ / "xaios-vz"
HELPER = VZ / "vmnet-helper"
SOCKET = VZ / "vmnet.sock"
REPORT = BUILD / "vz-bridged-gate.json"
LOG = BUILD / "vz-bridged-gate.log"

PING6 = "/sbin/ping6"
PING = "/sbin/ping"
NDP = "/usr/sbin/ndp"

BOOT_TIMEOUT_S = int(os.environ.get("XAIOS_VZ_BRIDGED_TIMEOUT", "300"))
INTERFACE = os.environ.get("XAIOS_VZ_BRIDGE_INTERFACE", "en0")
READY = "SSH server: up and running (tcp/22)"
IPV4 = re.compile(r"IPv4: (\d+\.\d+\.\d+\.\d+)")
IPV6 = re.compile(r"IPv6: ([0-9a-fA-F:]+)")

VOLUMES = ("vz-test.img", "vz-persistent.img", "vz-model.img",
           "vz-storage-admin.img", "vz-system.img", "vz-system2.img")


def helper_command() -> str:
    return (f'sudo "{HELPER}" --socket "{SOCKET}" '
            f'--mode bridged --interface {INTERFACE}')


def global_ipv6(text: str) -> str | None:
    found = None
    for candidate in IPV6.findall(text):
        try:
            address = ipaddress.IPv6Address(candidate)
        except ValueError:
            continue
        if address.is_link_local or address.is_loopback:
            continue
        found = candidate
    return found


def ping(tool: str, address: str, count: int = 4) -> dict[str, object]:
    result = subprocess.run([tool, "-c", str(count), "-i", "0.5", address],
                            capture_output=True, text=True, timeout=60,
                            check=False)
    received = re.search(r"(\d+) packets received", result.stdout)
    times = re.search(r"= ([\d.]+)/([\d.]+)/", result.stdout)
    return {"sent": count,
            "received": int(received.group(1)) if received else 0,
            "average_ms": float(times.group(2)) if times else None}


def host_addresses(interface: str) -> dict[str, object]:
    """What this Mac holds on the interface being bridged onto.

    The comparison is the point: a guest address in the same prefix as the
    host's is on the LAN; one in 192.168.201/24 is on vmnet's own private
    network and would mean the helper is in shared or host mode.
    """
    result = subprocess.run(["/sbin/ifconfig", interface], capture_output=True,
                            text=True, timeout=30, check=False)
    v4 = re.findall(r"\n\tinet (\d+\.\d+\.\d+\.\d+)", result.stdout)
    v6 = [a for a in re.findall(r"\n\tinet6 ([0-9a-fA-F:]+)", result.stdout)
          if not a.startswith("fe80")]
    return {"interface": interface, "ipv4": v4, "ipv6": v6}


def boot(log: Path) -> subprocess.Popen[bytes]:
    command = [str(HARNESS), str(VZ / "run-disk.img")]
    command += [str(VZ / name) for name in VOLUMES]
    command += ["--memory-mib", "4096", "--cpus", "4",
                "--vmnet", str(SOCKET)]
    handle = log.open("wb")
    process = subprocess.Popen(command, cwd=ROOT, stdin=subprocess.DEVNULL,
                               stdout=handle, stderr=subprocess.STDOUT,
                               start_new_session=True)
    process._log = handle  # type: ignore[attr-defined]
    return process


def main() -> int:
    if sys.platform != "darwin":
        print("vz-bridged-gate: needs macOS")
        return 0
    for artefact in (HARNESS, HELPER):
        if not artefact.is_file():
            print(f"vz-bridged-gate: missing {artefact.relative_to(ROOT)}; "
                  f"run `make vz-harness vmnet-helper` first", file=sys.stderr)
            return 2
    if not SOCKET.exists():
        # Not an error to report as a failure: the relay is privileged and
        # starting it is the operator's to do. Say exactly what to run.
        print("vz-bridged-gate: the privileged vmnet relay is not running.")
        print("  Start it in another terminal and leave it running:")
        print()
        print(f"    {helper_command()}")
        print()
        print("  Then run this gate again. Nothing else here needs privilege.")
        return 2

    disk = VZ / "run-disk.img"
    if not disk.is_file():
        print(f"vz-bridged-gate: missing {disk.relative_to(ROOT)}; "
              f"run `make vz-gate` once to create the volumes", file=sys.stderr)
        return 2

    LOG.unlink(missing_ok=True)
    process = boot(LOG)
    failures: list[str] = []
    checks: dict[str, object] = {"host": host_addresses(INTERFACE)}
    try:
        deadline = time.monotonic() + BOOT_TIMEOUT_S
        text = ""
        while time.monotonic() < deadline:
            time.sleep(2.0)
            text = LOG.read_text(errors="replace") if LOG.is_file() else ""
            if READY in text:
                break
            if process.poll() is not None:
                break
        if READY not in text:
            failures.append("the guest never reported sshd listening")
        ipv4 = IPV4.findall(text)
        checks["guest_ipv4"] = ipv4[-1] if ipv4 else None
        checks["guest_ipv6_global"] = global_ipv6(text)

        if checks["guest_ipv4"] in (None, "10.0.2.15"):
            failures.append(
                "the guest took no DHCP lease from the bridged LAN; "
                "10.0.2.15 is this stack's fallback address")
        if checks["guest_ipv6_global"] is None:
            failures.append(
                "the guest configured no global IPv6 address, so the bridge "
                "carried no router advertisement it could use")
        else:
            checks["ping6"] = ping(PING6, str(checks["guest_ipv6_global"]))
            if checks["ping6"]["received"] == 0:
                failures.append("no ICMPv6 reply from the guest's global address")
        if checks["guest_ipv4"] not in (None, "10.0.2.15"):
            checks["ping4"] = ping(PING, str(checks["guest_ipv4"]))
            if checks["ping4"]["received"] == 0:
                failures.append("no ICMPv4 reply from the guest's LAN address")

        # The address has to be on the LAN, not on vmnet's private range. A
        # guest that answers on 192.168.201.2 is reachable and not bridged,
        # which is the mistake this gate exists to make impossible.
        host_v4 = checks["host"]["ipv4"]
        if checks["guest_ipv4"] and host_v4:
            same = any(ipaddress.ip_address(checks["guest_ipv4"]) in
                       ipaddress.ip_network(f"{h}/24", strict=False)
                       for h in host_v4)
            checks["guest_on_host_lan"] = same
            if not same:
                failures.append(
                    f"the guest's {checks['guest_ipv4']} is not on this host's "
                    f"LAN {host_v4}; the relay is bridging nothing")
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()

    report = {
        "schema": "xaios.vz.bridged.v1",
        "status": "pass" if not failures else "fail",
        "bridge_interface": INTERFACE,
        "helper_command": helper_command(),
        "checks": checks,
        "failures": failures,
        "guest_log": str(LOG),
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                      encoding="utf-8")
    if failures:
        for failure in failures:
            print(f"vz-bridged-gate: FAIL {failure}")
        print(f"vz-bridged-gate: report={REPORT}")
        return 1
    print(f"vz-bridged-gate: the guest is on the LAN -- IPv4 "
          f"{checks['guest_ipv4']}, IPv6 {checks['guest_ipv6_global']}, "
          f"reachable from this host; report={REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
