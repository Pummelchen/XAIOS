#!/usr/bin/env python3
"""Fill the socket-to-flow map and require the kernel to say so.

B-47. `network_stack_map_socket_unlocked` returned void and fell off the end
when the table was full. The accept that called it carried on regardless: it
allocated the descriptor, wrote the peer address back to userspace, logged
`syscall: net_accept` and returned success -- handing out a socket with no
flow behind it, so every later send and recv on that descriptor looked up
nothing and did nothing. A connection accepted and then never progressed,
with not one line anywhere saying why.

The table is `NETWORK_TCP_CONNECTIONS + NETWORK_UDP_FLOWS` rows, which reads
like "one row per flow, so it cannot run out before flows do". That is not
what bounds it: a row is keyed by descriptor and cleared on close, and for TCP
`release_tcp_flow` leaves the row standing when the flow dies. Occupancy is
therefore open mapped descriptors, and the kernel socket table holds at least
256 of those against 160 rows here. Sizing was never the protection.

Nothing in a boot fills the table, and nothing in the syscall paths could see
it full while the failure was a void return, so there is no way to reach this
from outside: the gate has to fill the table itself. It does, in the kernel's
own network self-test, which runs on every architecture before the persistent
stack is initialised -- every row, then one more request, then the rows given
back. This gate reads the two lines that produces and checks the arithmetic in
them, then requires the guest to boot through to a login prompt afterwards,
which is what says the fill did not damage the stack it borrowed.

Remove the refusal and this goes red twice over: the self-test's assertion on
the returned status fails, which halts the kernel, so neither line appears and
no prompt arrives.

Both lines are `klog`, so this needs the verbose build (`image-qemu-test` and
its siblings); against a release image the boot UI owns the console and the
gate cannot see its own subject.
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
REPORT = BUILD / (f"qemu-socket-flow-map-gate-{ARCH}.json" if ARCH != "aarch64"
                  else "qemu-socket-flow-map-gate.json")
DEADLINE = smoke_timeout(
    ARCH, int(os.environ.get("XAIOS_SOCKET_FLOW_MAP_TIMEOUT", "420")))

# The refusal itself, from inside the stack. `refusals` is cumulative, so the
# first one says 1; the self-test asks for exactly one mapping too many.
REFUSAL = re.compile(
    r"network: socket-to-flow map exhausted size=(\d+) sockfd=(\d+) "
    r"flow=(\d+) protocol=(\d+) refusals=(\d+)")
# The self-test's own summary, which is only printed after its assertions on
# the status, the counter and the absent mapping have all held.
SUMMARY = re.compile(
    r"network: socket-flow map exhaustion self-test passed capacity=(\d+) "
    r"filled=(\d+) refused=(\d+)")
PROMPT = "xaios login:"


def boot() -> tuple[str, str]:
    """Boot the verbose build and return everything the guest said."""
    environment = qemu_boot_environment(
        ARCH, dict(os.environ),
        # Both lines are read from the runner's stdout, and RISC-V's runner
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
            "the guest never reached a login prompt with the exhaustion "
            "self-test having run")
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
        print(f"qemu-socket-flow-map-gate: build it first ({prerequisite[1]})",
              file=sys.stderr)
        return 2

    text, why = boot()
    failures: list[str] = []
    if why:
        failures.append(why)

    summary = SUMMARY.search(text)
    refusal = REFUSAL.search(text)

    capacity = filled = refused = None
    refusal_size = refusal_refusals = None
    if summary is None:
        failures.append(
            "the kernel never reported the socket-flow map exhaustion "
            "self-test; either it did not run or one of its assertions "
            "halted the machine, which is what removing the refusal does")
    else:
        capacity = int(summary.group(1))
        filled = int(summary.group(2))
        refused = int(summary.group(3))
        if capacity <= 0:
            failures.append(f"the map reports a capacity of {capacity}")
        if filled <= 0:
            failures.append(
                f"the self-test filled {filled} rows, so it never reached a "
                f"full table and the refusal it claims to have seen cannot "
                f"have come from one")
        if filled > capacity:
            failures.append(
                f"the self-test filled {filled} rows into a table of "
                f"{capacity}")
        if refused != 1:
            failures.append(
                f"the self-test expected exactly one refusal and counted "
                f"{refused}; more than one means a mapping that should have "
                f"been admitted was turned away, none means the full table "
                f"accepted it")

    if refusal is None:
        failures.append(
            "the stack refused a mapping without logging it; the exhaustion "
            "has to be visible in the log, because that is the whole of what "
            "B-47 is about")
    else:
        refusal_size = int(refusal.group(1))
        refusal_refusals = int(refusal.group(5))
        if capacity is not None and refusal_size != capacity:
            failures.append(
                f"the refusal line names a table of {refusal_size} and the "
                f"self-test a capacity of {capacity}")
        if refusal_refusals != 1:
            failures.append(
                f"the first refusal logged says refusals={refusal_refusals}, "
                f"so something refused a mapping before the self-test did")
        if int(refusal.group(4)) != 6:
            failures.append(
                f"the refused mapping was protocol {refusal.group(4)}, not "
                f"the TCP one the self-test asked for")

    if PROMPT not in text:
        failures.append(
            "the guest never reached a login prompt after filling and "
            "emptying the map")

    report = {
        "schema": "xaios.socket-flow-map.v1",
        "arch": ARCH,
        "capacity": capacity,
        "rows_filled": filled,
        "refusals_counted": refused,
        "refusal_line_size": refusal_size,
        "refusal_line_count": refusal_refusals,
        "reached_login_prompt": PROMPT in text,
        "failures": failures,
        "passed": not failures,
    }
    BUILD.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    if failures:
        for failure in failures:
            print(f"qemu-socket-flow-map-gate: {failure}", file=sys.stderr)
        print(f"qemu-socket-flow-map-gate: report written to {REPORT}",
              file=sys.stderr)
        return 1
    print(f"qemu-socket-flow-map-gate: filled all {capacity} rows of the "
          f"socket-to-flow map ({filled} from this boot), the next mapping "
          f"was refused and logged, and the guest booted through")
    print(f"qemu-socket-flow-map-gate: report written to {REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
