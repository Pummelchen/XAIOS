#!/usr/bin/env python3
"""F-02: the paravirtual NIC VMware offers, on a machine that boots in a loop.

This driver was written for VMware Fusion and could only ever be tried there
-- by hand, on one laptop, one boot at a time. QEMU implements the same
device, so it can be held to the same standard as every other driver here:
booted, given a network, and required to carry traffic.

Running it that way is what found the defect. The doorbell window and the
SATA controller's registers had been given the same hand-chosen virtual
address, so every store meant for the device landed on the disk controller's
read-only capability register. The device was never told a descriptor was
ready, and from inside it looked exactly like a protocol fault -- which is
where months of measurement had gone.

What this asserts is the whole path rather than any part of it: the driver is
chosen, the machine takes a real DHCP lease rather than the address the stack
falls back to, and an SSH key exchange completes over the card. The lease is
the load-bearing one: an offer alone does not need the receive ring to work
twice, and the acknowledgement does.
"""

from __future__ import annotations

import json
import os
import re
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
REPORT = BUILD / "qemu-vmxnet3-gate.json"
LOG = BUILD / "qemu-vmxnet3-gate.log"
READY = "SSH server: up and running (tcp/22)"
TIMEOUT_S = int(os.environ.get("XAIOS_VMXNET3_TIMEOUT", "240"))

REQUIRED = (
    ("the driver was chosen for this machine",
     re.compile(r"network-device: selected vmxnet3")),
    ("the device activated with rings of the size it was given",
     re.compile(r"vmxnet3: activated tx_ring=\d+ rx_ring=\d+ mtu=1500")),
    # The window this driver is given, and the proof that no other driver was
    # given the same one. Both matter: the second is the defect this gate
    # exists for, and it is checked on every boot rather than here alone.
    ("the doorbell has a window of its own",
     re.compile(r"device-window: vmxnet3-doorbell phys=0x[0-9a-f]+ bytes=\d+ "
                r"at 0x[0-9a-f]+")),
    ("no two drivers were given the same window",
     re.compile(r"device-window: self-test passed windows=\d+ .* none "
                r"overlapping")),
    # A lease, not an offer. The address that follows an offer looks the same
    # as the one the stack falls back to, so the address proves nothing on its
    # own; the lease line is the receive ring working more than once.
    ("the machine took a real DHCP lease",
     re.compile(r"network: DHCP lease ip=[0-9a-f]{8} mask=[0-9a-f]{8} "
                r"gw=[0-9a-f]{8}")),
    ("the SSH service came up on it", re.compile(re.escape(READY))),
)

FORBIDDEN = (
    ("a transmit timed out", re.compile(r"vmxnet3: transmit timed out")),
    ("the receive path stopped", re.compile(r"vmxnet3: receive idle at comp "
                                            r"slot=\d+ .* frames=[01]\b")),
    ("kernel panic", re.compile(r"CYAN SCREEN OF DEATH")),
)


def reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def main() -> int:
    build = subprocess.run(["./scripts/build-image.sh"], cwd=ROOT,
                           env={**os.environ, "XAIOS_TARGET_ARCH": "x86_64",
                                "XAIOS_BOOT_TEST_APPS": "1"},
                           stdout=subprocess.DEVNULL, check=False)
    if build.returncode != 0:
        print("vmxnet3-gate: could not build the x86-64 image")
        return 1

    port = reserve_port()
    LOG.unlink(missing_ok=True)
    handle = LOG.open("wb")
    environment = dict(os.environ)
    environment["XAIOS_QEMU_X86_NIC"] = "vmxnet3"
    environment["XAIOS_QEMU_HOSTFWD_PORT"] = str(port)
    process = subprocess.Popen(
        [str(ROOT / "platform" / "qemu" / "run-qemu-x86_64.sh")], cwd=ROOT,
        env=environment, stdin=subprocess.DEVNULL, stdout=handle,
        stderr=subprocess.STDOUT, start_new_session=True)

    keyscan = ""
    try:
        deadline = time.monotonic() + TIMEOUT_S
        while time.monotonic() < deadline:
            time.sleep(2.0)
            if LOG.is_file() and READY in LOG.read_text(errors="replace"):
                break
            if process.poll() is not None:
                break
        # The far end of the wire, not the guest's own opinion of it. A guest
        # that says sshd is up while nothing can reach it is exactly the state
        # this driver was in for months.
        result = subprocess.run(
            ["ssh-keyscan", "-T", "15", "-p", str(port), "127.0.0.1"],
            capture_output=True, text=True, timeout=30, check=False)
        keyscan = result.stdout
    finally:
        if process.poll() is None:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        handle.close()

    text = LOG.read_text(errors="replace") if LOG.is_file() else ""
    checks = [{"name": name, "passed": bool(pattern.search(text))}
              for name, pattern in REQUIRED]
    checks.append({"name": "a key exchange completed over the card",
                   "passed": "ssh-ed25519" in keyscan})
    faults = [{"name": name, "seen": bool(pattern.search(text))}
              for name, pattern in FORBIDDEN]
    passed = all(c["passed"] for c in checks) and not any(f["seen"]
                                                          for f in faults)

    REPORT.write_text(json.dumps(
        {"schema": "xaios.qemu.vmxnet3.v1", "architecture": "x86_64",
         "checks": checks, "faults": faults, "passed": passed,
         "console": str(LOG)}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    for check in checks:
        print(f"  {'ok  ' if check['passed'] else 'MISS'} {check['name']}")
    for fault in faults:
        if fault["seen"]:
            print(f"  FAULT {fault['name']}")
    if not passed:
        print(f"vmxnet3-gate: the card did not carry traffic; console at {LOG}")
        return 1
    print(f"vmxnet3-gate: VMXNET3 selected, leased, and reachable; "
          f"report={REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
