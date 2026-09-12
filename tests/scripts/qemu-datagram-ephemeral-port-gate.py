#!/usr/bin/env python3
"""Ask the kernel for two datagram sockets it names, and read the answer.

WT-35. A QUIC client's first act is to send an Initial from a local port it
does not yet have. XAIOS could bind a port it was told (``xaios_net_listen``
with the UDP protocol, or ``xaios_net_bind_udp``) and could send from one
(``xaios_net_sendto``), but there was no call that would *choose* a port and
report it, and ``xaios_net_listen`` refuses port zero outright. A client with
no port is a client whose peer has nowhere to reply.

``xaios_net_open_udp`` is that call: port zero asks the kernel to choose, and
the port comes back in the request structure. The kernel logs every one it
hands out, which is what this gate reads, together with ``/bin/netsocktest``'s
summary of what the *caller* was told. Both sides are needed, because the
whole subject of the row is that the two agree: a kernel that allocated a port
and reported zero to the caller would pass a gate that read only the log.

The properties checked, in the order the app establishes them:

  1. the port that comes back is not the zero that was asked for;
  2. it is in the dynamic range, RFC 6335's 49152 and up;
  3. two opens get different ports -- a reply is looked up by port, so two
     descriptors holding one port leave whichever is listed second
     unreachable;
  4. a port asked for by number comes back as that number;
  5. a datagram leaves from the socket that was given the port, so the port is
     a source and not merely a record;
  6. every descriptor closes.

None of this is visible in a release image: the app is part of the boot-test
profile and the summary is one line of its console output, so this needs
``image-qemu-test``. The app asserts nothing, on purpose -- a measurement that
returned non-zero on a bad number would fail a boot for a reason belonging to
the test. The judgement is here.
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
REPORT = BUILD / (f"qemu-datagram-ephemeral-port-gate-{ARCH}.json"
                  if ARCH != "aarch64"
                  else "qemu-datagram-ephemeral-port-gate.json")
DEADLINE = smoke_timeout(
    ARCH, int(os.environ.get("XAIOS_EPHEMERAL_UDP_TIMEOUT", "420")))

# The app's own report, printed after every count it keeps, whatever the
# numbers are.
SUMMARY = re.compile(
    r"/bin/netsocktest: summary opens=(\d+) opens_failed=(\d+) "
    r"port_zero=(\d+) out_of_range=(\d+) duplicated=(\d+) "
    r"explicit_mismatch=(\d+) sends=(\d+) sends_failed=(\d+) "
    r"closes_failed=(\d+) first_port=(\d+) second_port=(\d+) "
    r"explicit_port=(\d+)")
COMPLETE = "/bin/netsocktest: complete"
# The kernel's side of the same events.
KERNEL_OPEN = re.compile(r"syscall: net_open_udp port=(\d+) sockfd=(\d+)")
PROMPT = "xaios login:"

EPHEMERAL_MIN = 49152
EPHEMERAL_MAX = 65535
OPENS = 3


def boot() -> tuple[str, str]:
    """Boot the verbose build and return everything the guest said."""
    environment = qemu_boot_environment(
        ARCH, dict(os.environ),
        # The lines are read from the runner's stdout, and RISC-V's runner
        # writes the console to a file unless told otherwise.
        serial_to_stdout=True)
    process = subprocess.Popen(
        [qemu_runner(ARCH)],
        cwd=str(ROOT), env=environment, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    collected: list[str] = []

    # Drained on a thread throughout: the guest keeps writing to the serial
    # pipe while this waits, and a full pipe stalls the vCPU.
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
            if SUMMARY.search(text) and PROMPT in text:
                return text, ""
        return "".join(collected), (
            "the guest never reached a login prompt with /bin/netsocktest "
            "having reported")
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
        print(f"qemu-datagram-ephemeral-port-gate: build it first "
              f"({prerequisite[1]})", file=sys.stderr)
        return 2

    text, why = boot()
    failures: list[str] = []
    if why:
        failures.append(why)

    summary = SUMMARY.search(text)
    kernel_opens = [int(m.group(1)) for m in KERNEL_OPEN.finditer(text)]

    opens = opens_failed = port_zero = out_of_range = None
    duplicated = explicit_mismatch = sends = sends_failed = None
    closes_failed = first_port = second_port = explicit_port = None

    if summary is None:
        failures.append(
            "the app never reported its summary; /bin/netsocktest either did "
            "not run in this image or did not reach the end of itself")
    else:
        (opens, opens_failed, port_zero, out_of_range, duplicated,
         explicit_mismatch, sends, sends_failed, closes_failed, first_port,
         second_port, explicit_port) = (int(g) for g in summary.groups())

        if opens != OPENS:
            failures.append(
                f"the app reported {opens} open attempts, not the {OPENS} it "
                f"makes; the summary row does not describe this program")
        if opens_failed != 0:
            failures.append(
                f"{opens_failed} of {OPENS} opens were refused; the kernel "
                f"declined to name a datagram socket")
        if port_zero != 0:
            failures.append(
                f"{port_zero} ephemeral opens came back with port zero, so "
                f"the caller was handed a socket with no reachable address")
        if out_of_range != 0:
            failures.append(
                f"{out_of_range} of the ports that came back were outside "
                f"{EPHEMERAL_MIN}..{EPHEMERAL_MAX}; the counter is not "
                f"confined to the dynamic range")
        if duplicated != 0:
            failures.append(
                f"{duplicated} pairs of ephemeral opens were handed the same "
                f"port; a reply is looked up by port and only the first "
                f"descriptor holding it can be reached")
        if explicit_mismatch != 0:
            failures.append(
                f"{explicit_mismatch} explicit opens reported a port other "
                f"than the one that was asked for")
        if sends != 1 or sends_failed != 0:
            failures.append(
                f"the datagram from the kernel-named socket "
                f"{'was never attempted' if sends != 1 else 'failed'}; the "
                f"port is a record rather than a source")
        if closes_failed != 0:
            failures.append(f"{closes_failed} descriptors failed to close")

        for name, value in (("first_port", first_port),
                            ("second_port", second_port)):
            if value == 0:
                failures.append(f"{name} is zero in the summary")
            elif not EPHEMERAL_MIN <= value <= EPHEMERAL_MAX:
                failures.append(
                    f"{name} is {value}, outside "
                    f"{EPHEMERAL_MIN}..{EPHEMERAL_MAX}")
        if first_port is not None and first_port == second_port:
            failures.append(
                f"both ephemeral opens reported port {first_port}")

    # The kernel's side. Fewer lines than opens means an open that the kernel
    # never logged, which is the failure B-47 was: a syscall that reported
    # success for work that did not happen.
    if len(kernel_opens) < OPENS:
        failures.append(
            f"the kernel logged {len(kernel_opens)} net_open_udp allocations "
            f"and the app attempted {OPENS}; the descriptor and the log "
            f"disagree about what happened")
    for port in kernel_opens:
        if not EPHEMERAL_MIN <= port <= EPHEMERAL_MAX:
            failures.append(
                f"the kernel logged an allocated port of {port}, outside "
                f"{EPHEMERAL_MIN}..{EPHEMERAL_MAX}")

    # The two sides have to agree. This is the check the row exists for: the
    # caller must be told the port the kernel actually bound, because that is
    # the address it is about to hand a peer.
    if summary is not None and kernel_opens:
        if first_port is not None and first_port != 0 and \
                first_port not in kernel_opens:
            failures.append(
                f"the app was told first_port={first_port} and the kernel "
                f"never logged allocating it (it logged {kernel_opens})")
        if second_port is not None and second_port != 0 and \
                second_port not in kernel_opens:
            failures.append(
                f"the app was told second_port={second_port} and the kernel "
                f"never logged allocating it (it logged {kernel_opens})")
        if explicit_port is not None and explicit_port != 0 and \
                explicit_port not in kernel_opens:
            failures.append(
                f"the app was told explicit_port={explicit_port} and the "
                f"kernel never logged allocating it (it logged {kernel_opens})")

    if COMPLETE not in text:
        failures.append(
            "/bin/netsocktest never printed its completion line, so it did "
            "not walk the whole path it reports on")
    if PROMPT not in text:
        failures.append(
            "the guest never reached a login prompt after the opens, so the "
            "allocations did not leave the socket table intact")

    report = {
        "schema": "xaios.datagram-ephemeral-port.v1",
        "arch": ARCH,
        "opens_attempted": opens,
        "opens_failed": opens_failed,
        "port_zero_returned": port_zero,
        "ports_out_of_range": out_of_range,
        "ports_duplicated": duplicated,
        "explicit_port_mismatched": explicit_mismatch,
        "sends_attempted": sends,
        "sends_failed": sends_failed,
        "closes_failed": closes_failed,
        "first_port": first_port,
        "second_port": second_port,
        "explicit_port": explicit_port,
        "kernel_allocations": kernel_opens,
        "reached_login_prompt": PROMPT in text,
        "failures": failures,
        "passed": not failures,
    }
    BUILD.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if failures:
        for failure in failures:
            print(f"qemu-datagram-ephemeral-port-gate: {failure}",
                  file=sys.stderr)
        print(f"qemu-datagram-ephemeral-port-gate: report written to {REPORT}",
              file=sys.stderr)
        return 1
    print(f"qemu-datagram-ephemeral-port-gate: the kernel named "
          f"{len(kernel_opens)} datagram sockets, the caller was told "
          f"{first_port} and {second_port} for the two it did not name and "
          f"{explicit_port} for the one it did, a datagram left from the "
          f"first, and the guest booted through")
    print(f"qemu-datagram-ephemeral-port-gate: report written to {REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
