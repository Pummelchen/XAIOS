#!/usr/bin/env python3
"""Give the guest a network that is not a /24, and read back what it says.

B-18 was a log line that lied: `routing: initialized` printed "/24"
unconditionally, so a guest handed 255.255.248.0 by DHCP reported a prefix it
was not using. The routing table had the real mask throughout -- this was the
log being wrong about the one thing a person reading it is checking, and it
cost a detour into a routing bug that did not exist.

The fix was three lines. Proving it was the hard part, and for a long time
nothing did: every environment here hands the guest a /24, so a line that says
"/24" whatever the mask is looks correct in all of them. A defect that only
appears outside the range of every test is not caught by running more tests
inside it.

QEMU's user networking will hand out any range asked for, so this asks for a
/21 and requires the guest to say /21. The prefix is the whole assertion: the
address it is attached to is free to change, and pinning it would make this
fail for reasons that have nothing to do with the bug.

Two details cost a run each when this was written, and both are the sort that
make a gate quietly test nothing. The range has to be given to net1: that is
the interface the persistent network stack configures and routes through, and
net0 is a second, unrouted one, so setting it there leaves the guest on
10.0.2.15 and the gate measuring the default. And `routing: initialized` is
only logged by the verbose build, so this needs `image-qemu-test`; against a
plain image the line never appears and the gate cannot see its own subject.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
sys.path.insert(0, str(ROOT / "tests" / "scripts"))
from qemu_gate_lib import (arch_from_argv, qemu_boot_environment, qemu_runner,
                           smoke_timeout)

ARCH = arch_from_argv(sys.argv)
REPORT = BUILD / (f"qemu-routing-prefix-gate-{ARCH}.json" if ARCH != "aarch64"
                  else "qemu-routing-prefix-gate.json")

# Deliberately neither a /24 nor a /16, so a hard-coded prefix of either shape
# fails rather than passing by coincidence. The assertion is not against this
# number though: it is against the mask the guest was actually leased, read
# from its own DHCP log. What SLIRP offers is between SLIRP and the guest, and
# a gate that assumed the offer was accepted verbatim would fail the day that
# changed for a reason having nothing to do with the routing log.
NETWORK = os.environ.get("XAIOS_ROUTING_PREFIX_NET", "10.0.5.0/21")
EXPECTED_PREFIX = int(NETWORK.split("/")[1])
DEADLINE = smoke_timeout(
    ARCH, int(os.environ.get("XAIOS_ROUTING_PREFIX_TIMEOUT", "420")))

ROUTING = re.compile(r"routing: initialized \(local=([0-9a-f]{8})/(\d+) ")
LEASE = re.compile(r"network: DHCP lease ip=([0-9a-f]{8}) mask=([0-9a-f]{8})")


def prefix_of(mask_hex: str) -> int:
    """Leading one-bits of a netmask, which is what a prefix length is."""
    mask = int(mask_hex, 16)
    length = 0
    for bit in range(31, -1, -1):
        if not mask & (1 << bit):
            break
        length += 1
    return length


def boot() -> tuple[str, str]:
    """Boot with the requested range and return everything the guest said."""
    environment = qemu_boot_environment(
        ARCH, dict(os.environ), user_net_cidr=NETWORK,
        # The routing line is read out of the runner's stdout, and RISC-V's
        # runner writes the console to a file unless told otherwise.
        serial_to_stdout=True)
    process = subprocess.Popen(
        [qemu_runner(ARCH)],
        cwd=str(ROOT), env=environment, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    collected: list[str] = []

    def drain() -> None:
        assert process.stdout is not None
        while True:
            chunk = process.stdout.read(1)
            if not chunk:
                return
            collected.append(chunk)

    threading.Thread(target=drain, daemon=True).start()
    try:
        end = time.monotonic() + DEADLINE
        while time.monotonic() < end:
            time.sleep(2)
            text = "".join(collected)
            # The routing line is printed long before the prompt, but waiting
            # for the prompt as well proves the guest is usable on this
            # network rather than merely having logged something about it.
            if ROUTING.search(text) and "xaios login:" in text:
                return text, ""
        return "".join(collected), "the guest never reached a login prompt"
    finally:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()


def main() -> int:
    prerequisite = {"aarch64": ("xaios-aarch64.img", "make image-qemu-test"),
                    "x86_64": ("xaios-x86_64.img", "make image-x86_64"),
                    "riscv64": ("kernel-riscv64/kernel.elf",
                                "make riscv64")}[ARCH]
    if not (BUILD / prerequisite[0]).is_file():
        print(f"qemu-routing-prefix-gate: build it first ({prerequisite[1]})",
              file=sys.stderr)
        return 2
    text, why = boot()
    failures: list[str] = []
    # Routing is initialised twice: once from the built-in defaults before a
    # lease exists, and again once DHCP has applied one. The first is a /24 on
    # any network, so reading it would measure the default and call it a pass
    # -- take the last, which is the one describing the lease in force.
    routes = ROUTING.findall(text)
    reported = int(routes[-1][1]) if routes else None
    leases = LEASE.findall(text)
    leased_mask = leases[-1][1] if leases else None
    leased_prefix = prefix_of(leased_mask) if leased_mask else None
    address = None
    match = re.search(r"^IPv4: ([0-9.]+)$", text, re.MULTILINE)
    if match:
        address = match.group(1)
    if why:
        failures.append(why)
    if not leases:
        failures.append("the guest never took a DHCP lease, so there is no "
                        "mask for the log to be right or wrong about")
    elif leased_prefix == 24:
        # The whole point is to be somewhere a /24 assumption breaks. If the
        # server handed one out anyway, this run proves nothing and must not
        # report success.
        failures.append(
            f"the guest was leased a /24 despite being offered {NETWORK}; "
            f"this run cannot distinguish a correct log from a hardcoded one")
    if not routes:
        failures.append("the guest never logged a routing prefix at all")
    elif leased_prefix is not None and reported != leased_prefix:
        failures.append(
            f"the guest was leased a /{leased_prefix} (mask {leased_mask}) "
            f"and its routing log says /{reported}; the log is not reading "
            f"the mask it was handed")
    report = {
        "schema": "xaios.routing-prefix.v1",
        "arch": ARCH,
        "network_offered": NETWORK,
        "lease_mask": leased_mask,
        "prefix_leased": leased_prefix,
        "prefix_reported": reported,
        "prefixes_logged": [int(p) for _, p in routes],
        "guest_address": address,
        "failures": failures,
        "passed": not failures,
    }
    BUILD.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if failures:
        for failure in failures:
            print(f"qemu-routing-prefix-gate: {failure}", file=sys.stderr)
        return 1
    print(f"qemu-routing-prefix-gate: offered {NETWORK}, guest was leased "
          f"mask {leased_mask} (/{leased_prefix}) and its routing log says "
          f"/{reported}")
    print(f"qemu-routing-prefix-gate: report written to {REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
