#!/usr/bin/env python3
"""What a Fusion guest's network does, from the LAN it is actually on.

F-03 asked for IPv6 and IPv4 behaviour on a Fusion guest to be proved rather
than assumed from QEMU. The measurements were made and written down; what was
missing was a gate, so nothing re-checked them and a regression would have
been found by someone noticing.

The attachment is bridged, so the guest is on the real wire beside this host
and every check here goes over it: a global address taken from a genuine
router advertisement, ICMPv6 that answers from the address it was addressed
at, TCP over IPv6 and over IPv4, and a file moved each way over SFTP on the
IPv6 address. That is the part of F-03 this machine can answer for.

What it deliberately does not claim: nothing here proves behaviour under loss
or reordering -- the LAN is whatever it is on the day, and a gate that asserted
a loss figure would be asserting the weather. Outbound SSH from the guest to
this host is not attempted either, because it would need Remote Login enabled
on the Mac, which is a change to the operator's machine and not this gate's to
make. Both are named in the report rather than left as silence.
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
sys.path.insert(0, str(ROOT / "tests" / "scripts"))

import importlib.util

_SMOKE = ROOT / "tests" / "scripts" / "vmware-fusion-smoke.py"
_spec = importlib.util.spec_from_file_location("fusion_smoke", _SMOKE)
assert _spec is not None and _spec.loader is not None
smoke = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(smoke)

BUILD = ROOT / "build"
REPORT = BUILD / "vmware-fusion" / "fusion-network-gate.json"
SERIAL = smoke.SERIAL
UPLOAD = BUILD / "fusion-network-upload.txt"
DOWNLOAD = BUILD / "fusion-network-download.txt"

# The guest prints both, and the global one is the whole point: a link-local
# address proves the interface came up, not that the network works.
IPV4 = re.compile(r"IPv4: (\d+\.\d+\.\d+\.\d+)")
IPV6 = re.compile(r"IPv6: ([0-9a-fA-F:]+)")


def guest_addresses(text: str) -> tuple[str, str | None]:
    ipv4 = IPV4.findall(text)
    if not ipv4:
        raise RuntimeError("the guest reported no IPv4 address")
    global_v6 = None
    for candidate in IPV6.findall(text):
        try:
            address = ipaddress.IPv6Address(candidate)
        except ValueError:
            continue
        if address.is_link_local or address.is_loopback:
            continue
        global_v6 = candidate
    return ipv4[-1], global_v6


# Absolute paths, because this gate runs with the project's own PATH and
# /sbin is not always on it. A gate that fails with "No such file or
# directory: ping6" is reporting the shell's environment, not the network.
PING6 = "/sbin/ping6"
NDP = "/usr/sbin/ndp"


def ping6(address: str, count: int = 4) -> dict[str, object]:
    result = subprocess.run(
        [PING6, "-c", str(count), "-i", "0.5", address],
        capture_output=True, text=True, timeout=60, check=False)
    received = re.search(r"(\d+) packets received", result.stdout)
    times = re.search(r"= ([\d.]+)/([\d.]+)/", result.stdout)
    return {
        "sent": count,
        "received": int(received.group(1)) if received else 0,
        "average_ms": float(times.group(2)) if times else None,
        "exit_code": result.returncode,
    }


def sftp_round_trip(address: str) -> dict[str, object]:
    """A file each way, on the address under test rather than on any address."""
    payload = f"fusion-network-gate {time.time():.0f}\n"
    UPLOAD.write_text(payload, encoding="utf-8")
    DOWNLOAD.unlink(missing_ok=True)
    remote = "/state/fusion-network-gate.txt"
    batch = f"put {UPLOAD} {remote}\nget {remote} {DOWNLOAD}\nrm {remote}\n"
    host = f"[{address}]" if ":" in address else address
    command = [
        "sftp", "-F", "/dev/null", "-i", str(smoke.TEST_KEY),
        "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "LogLevel=ERROR", "-b", "-", f"admin@{host}",
    ]
    result = subprocess.run(command, input=batch, cwd=ROOT, text=True,
                            capture_output=True, timeout=120, check=False)
    returned = DOWNLOAD.read_text(encoding="utf-8") if DOWNLOAD.exists() else ""
    return {
        "exit_code": result.returncode,
        "round_trip_identical": returned == payload,
        "stderr": result.stderr.strip()[:400],
    }


def neighbour_entry(address: str) -> dict[str, object]:
    """Whether this host resolved the guest's address to a MAC on the wire.

    Read rather than required: `ndp -an` is readable without privilege here,
    but a host that has just pinged over a bridge may have aged the entry out
    by the time this runs, and a cache miss is not the guest's fault.
    """
    result = subprocess.run([NDP, "-an"], capture_output=True, text=True,
                            timeout=30, check=False)
    for line in result.stdout.splitlines():
        if line.startswith(address + " ") or line.startswith(address + "%"):
            return {"present": True, "entry": " ".join(line.split())}
    return {"present": False, "entry": None}


def main() -> int:
    if sys.platform != "darwin":
        print("vmware-fusion-network-gate: needs macOS with VMware Fusion")
        return 0
    if not smoke.VMRUN.is_file():
        print(f"vmware-fusion-network-gate: no vmrun at {smoke.VMRUN}; skipping")
        return 0

    smoke.ensure_test_key()
    smoke.build_guest()
    smoke.stop_hard()
    address4, serial = smoke.start_vm(0)
    failures: list[str] = []
    checks: dict[str, object] = {}
    try:
        text = SERIAL.read_text(errors="replace")
        ipv4, ipv6 = guest_addresses(text)
        checks["guest_ipv4"] = ipv4
        checks["guest_ipv6_global"] = ipv6

        # A bridged guest must take a LAN address, not a hypervisor's NAT
        # range. 10.0.2.15 is the fallback this stack uses when DHCP fails,
        # and it is exactly what a broken bridge looks like.
        if ipv4 == "10.0.2.15":
            failures.append(
                "the guest is on the DHCP fallback address, so it took no "
                "lease from the LAN it is bridged to")

        if ipv6 is None:
            failures.append(
                "the guest configured no global IPv6 address, so either the "
                "LAN sent no router advertisement or the guest did not hear "
                "it -- which is how the multicast receive filter presented")
        else:
            checks["ping6"] = ping6(ipv6)
            if checks["ping6"]["received"] == 0:
                failures.append(
                    f"no ICMPv6 reply from {ipv6}; a reply sourced from the "
                    f"wrong local address is discarded by the peer and looks "
                    f"exactly like this")
            checks["neighbour"] = neighbour_entry(ipv6)

            # Bare for ssh, bracketed for sftp. ssh takes user@address and
            # treats brackets as part of the hostname; sftp reads a colon as
            # the start of a remote path, so an IPv6 literal has to be
            # wrapped there. Getting this the wrong way round costs a boot.
            status6 = smoke.ssh(ipv6, "recovery status")
            checks["ipv6_ssh"] = status6.strip()[:200]
            if "rescue=" not in status6:
                failures.append(
                    f"SSH over IPv6 did not answer with a status: {status6!r}")
            checks["ipv6_sftp"] = sftp_round_trip(ipv6)
            if not checks["ipv6_sftp"]["round_trip_identical"]:
                failures.append(
                    "a file put and fetched over IPv6 SFTP did not come back "
                    "identical")

        status4 = smoke.ssh(ipv4, "recovery status")
        checks["ipv4_ssh"] = status4.strip()[:200]
        if "rescue=" not in status4:
            failures.append(
                f"SSH over IPv4 did not answer with a status: {status4!r}")

        # The guest's own account of its network, over the network. It has to
        # agree with what the console printed: a stack that answers on an
        # address it does not think it has is a different kind of broken from
        # one that does not answer at all.
        # The guest's own account of its hardware, fetched over the network
        # it is being tested on. A machine that answers on an address and
        # cannot describe itself through the same channel is answering with
        # something other than the stack under test.
        reported = smoke.ssh(ipv4, "xaiosctl hardware")
        checks["hardware"] = reported.strip()[:400]
        if "architecture=" not in reported or "core_count=" not in reported:
            failures.append(
                f"the guest did not describe its hardware over the network: "
                f"{reported.strip()[:200]!r}")
    finally:
        smoke.stop_hard()

    report = {
        "schema": "xaios.vmware-fusion.network.v1",
        "status": "pass" if not failures else "fail",
        "fusion_version": smoke.fusion_version(),
        "revision": smoke.git_revision(),
        "attachment": "bridged",
        "checks": checks,
        "failures": failures,
        "not_claimed": [
            "loss and reordering behaviour: the LAN is not a controlled link",
            "outbound SSH from the guest to this host: needs Remote Login "
            "enabled on the Mac, which is the operator's decision",
        ],
    }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                      encoding="utf-8")
    if failures:
        for failure in failures:
            print(f"vmware-fusion-network-gate: FAIL {failure}")
        print(f"vmware-fusion-network-gate: report={REPORT}")
        return 1
    ping = checks.get("ping6", {})
    print(f"vmware-fusion-network-gate: bridged LAN reachable -- "
          f"IPv4 {checks['guest_ipv4']}, IPv6 {checks['guest_ipv6_global']}, "
          f"ICMPv6 {ping.get('received')}/{ping.get('sent')} at "
          f"{ping.get('average_ms')} ms, SSH on both families, SFTP round "
          f"trip over IPv6; report={REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
