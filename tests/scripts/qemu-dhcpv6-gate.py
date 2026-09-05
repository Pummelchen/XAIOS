#!/usr/bin/env python3
"""Prove the DHCPv6 client obtains and configures a leased address.

Runs the guest twice against tests/network/qemu-dhcpv6-server.py, once for each
path RFC 8415 allows a server to take:

  rapid  the server honours Rapid Commit and answers SOLICIT with REPLY
  full   the server ignores it, sends ADVERTISE, and waits for the REQUEST

Both have to work, because a client does not get to choose which one it meets,
and the four-message path is the one that would otherwise never run: every
SOLICIT this client sends asks for rapid commit, so a server that grants it
would hide any defect in the longer exchange indefinitely.

The server checks what the client sent -- Client Identifier present, Elapsed
Time present, no Server Identifier in a SOLICIT, the right one echoed in a
REQUEST, the offered address named back, the transaction id unchanged across
the exchange -- and this checks what the guest did with the answer. Neither
half is sufficient alone: a client can send correct messages and fail to
configure the result, or configure something it was never given.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
sys.path.insert(0, str(ROOT / "tests" / "scripts"))
from qemu_gate_lib import (arch_from_argv, qemu_boot_environment, qemu_runner,
                           smoke_timeout)

ARCH = arch_from_argv(sys.argv)
SUFFIX = "" if ARCH == "aarch64" else f"-{ARCH}"
REPORT = BUILD / f"qemu-dhcpv6-gate{SUFFIX}.json"
RUNNER = ROOT / qemu_runner(ARCH)
SERVER = ROOT / "tests" / "network" / "qemu-dhcpv6-server.py"

BOOT_TIMEOUT_S = float(smoke_timeout(
    ARCH, int(os.environ.get("XAIOS_DHCPV6_BOOT_TIMEOUT", "180"))))
LEASE_MARKER = "network: IPv6 address configured by DHCPv6"
# 2001:db8::42, the address the server hands out, as the kernel prints it.
LEASED_ADDRESS_MARKER = "dhcpv6: lease by"
FATAL_MARKERS = ("CYAN SCREEN OF DEATH", "System halted", "assertion failed")


def reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for_listener(port: int, deadline: float) -> bool:
    """QEMU's stream netdev listens; the server connects. Do not race it."""
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1.0):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def run_case(mode: str) -> dict:
    port = reserve_port()
    log_path = BUILD / f"qemu-dhcpv6{SUFFIX}-{mode}.log"
    environment = dict(os.environ, XAIOS_BOOT_VERBOSE="1")
    environment = qemu_boot_environment(
        ARCH, environment, net_socket_port=port,
        # The guest console is redirected into log_path below; RISC-V's
        # runner writes it to a file of its own unless told otherwise.
        serial_to_stdout=True)

    result = {"mode": mode, "server_exit": None, "markers": {}, "passed": False}
    with log_path.open("wb") as handle:
        guest = subprocess.Popen([str(RUNNER)], cwd=ROOT, env=environment,
                                 stdout=handle, stderr=subprocess.STDOUT,
                                 stdin=subprocess.DEVNULL)
        server = None
        try:
            deadline = time.monotonic() + BOOT_TIMEOUT_S
            if not wait_for_listener(port, deadline):
                result["error"] = "QEMU never accepted a connection on the frame socket"
                return result
            server = subprocess.Popen(
                [sys.executable, str(SERVER), "--port", str(port),
                 "--mode", mode, "--timeout", str(BOOT_TIMEOUT_S)],
                cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True)

            while time.monotonic() < deadline:
                text = log_path.read_bytes().decode("utf-8", "replace")
                if any(marker in text for marker in FATAL_MARKERS):
                    result["error"] = "guest faulted"
                    break
                if LEASE_MARKER in text:
                    break
                if guest.poll() is not None:
                    result["error"] = "guest exited before configuring an address"
                    break
                time.sleep(1.0)
        finally:
            if server is not None:
                try:
                    output, _ = server.communicate(timeout=20)
                except subprocess.TimeoutExpired:
                    server.kill()
                    output, _ = server.communicate()
                result["server_exit"] = server.returncode
                result["server_output"] = (output or "").strip()
            guest.terminate()
            try:
                guest.wait(timeout=20)
            except subprocess.TimeoutExpired:
                guest.kill()

    text = log_path.read_bytes().decode("utf-8", "replace")
    expected_exchange = ("rapid commit" if mode == "rapid"
                         else "four-message exchange")
    result["markers"] = {
        "guest logged a lease": LEASE_MARKER in text,
        "guest logged the exchange it took": f"{LEASED_ADDRESS_MARKER} {expected_exchange}" in text,
        "guest did not fault": not any(m in text for m in FATAL_MARKERS),
    }
    result["passed"] = (result["server_exit"] == 0
                        and all(result["markers"].values()))
    return result


def main() -> int:
    if not RUNNER.is_file():
        print(f"qemu-dhcpv6-gate: missing {RUNNER}")
        return 1
    cases = [run_case("rapid"), run_case("full")]
    REPORT.write_text(json.dumps({
        "target": "qemu-aarch64",
        "qualification_evidence": False,
        "cases": cases,
        "passed": all(case["passed"] for case in cases),
    }, indent=2) + "\n", encoding="utf-8")

    for case in cases:
        state = "ok  " if case["passed"] else "FAIL"
        detail = case.get("error", "")
        missing = [name for name, ok in case["markers"].items() if not ok]
        if missing:
            detail += f" missing={','.join(missing)}"
        if case["server_exit"] not in (0, None):
            detail += f" server={case.get('server_output', '')}"
        print(f"  {state} {case['mode']} exchange {detail}".rstrip())

    print(f"qemu-dhcpv6-gate: report written to {REPORT}")
    if not all(case["passed"] for case in cases):
        print("qemu-dhcpv6-gate: failed")
        return 1
    print("qemu-dhcpv6-gate: both the two-message and four-message exchanges "
          "configure a leased address")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
