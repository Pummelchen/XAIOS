#!/usr/bin/env python3
"""One RISC-V kernel on two boards, held to opposite answers about interrupts.

QEMU's `virt` machine can be started two ways. The default publishes a PLIC,
which carries wires and no messages: every device queue on it is serviced by
polling, and that is a supported mode rather than a degraded one. Adding
`aia=aplic-imsic` publishes an APLIC and an IMSIC instead, which is the
RISC-V way to deliver a message-signalled interrupt at all.

This gate boots the same kernel image on both and requires each to say the
right thing about itself, because either half alone can be passed by a broken
build. A kernel that lost its AIA driver would still pass a PLIC-only gate. A
kernel that claimed message-signalled interrupts unconditionally would still
pass an AIA-only gate, and would then be lying on every existing RISC-V gate
in this tree, all of which run the default board.

What is asserted on the AIA board is delivery, not configuration, and the
distinction is the entire subject. Every driver here can also poll, so a
machine on which no interrupt is ever delivered boots and passes exactly like
one where they all are: "an MSI-X vector was programmed" is a statement about
this kernel and "a completion arrived without anybody polling for it" is a
statement about the machine. So the markers required below are the ones that
can only be printed after something actually arrived --

  * the IMSIC self-test, which writes this hart's own interrupt file and
    requires the message back through the trap handler;
  * the APLIC self-test, which asserts a source at the wire controller and
    requires it forwarded as a message to this hart -- proving the target
    register's hart index and identity fields, not just that they were
    written;
  * at least one real wired device delivering its first message, which is a
    virtio-mmio transport and not a test fixture;
  * the NVMe MSI-X canary, which submits a read with the queue unmasked and
    requires the completion to be delivered by interrupt.

-- and on the default board, the positive statements that none of that
happened and that the PLIC is what is serving.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from qemu_gate_lib import qemu_boot_environment, qemu_runner, smoke_timeout


BUILD = Path("build")
REPORT = BUILD / "qemu-riscv64-aia-gate-report.json"

# Markers every boot must carry regardless of board, so that a machine which
# died early cannot pass by having none of the forbidden lines either.
COMMON = [
    "irq: riscv64 ",
    "nvme: async self-test passed namespaces=1",
]

AIA_REQUIRED = [
    # Discovery, and specifically of the supervisor-level pair. The addresses
    # are QEMU's and are not asserted; what is asserted is that both were
    # found and that the wire controller was put into message delivery mode.
    "aia: supervisor imsic base=",
    "aia: supervisor aplic base=",
    "delivery=msi",
    "irq: riscv64 aia aplic+imsic serving the interrupt-controller interface",
    # Delivery, three ways.
    "aia: self-test passed identity=",
    "aia: wired self-test passed source=",
    # A device that was given a vector and used it.
    "virtio-rng: MSI-X queue=0 vector=",
    "nvme: MSI-X interrupt self-test passed queues=1 all_queues=1",
    "controller=aia-imsic",
]

AIA_FORBIDDEN = [
    "exception: no plic in the device tree",
    "irq: riscv64 plic serving the interrupt-controller interface",
    "nvme: no message-signalled interrupts on this machine",
    "virtio-rng: MSI-X unavailable",
    "aia: self-test FAILED",
    "aia: wired self-test FAILED",
]

# At least one wired device -- not the self-test's own synthetic source --
# whose first message actually arrived. wired_source=0 is a message from a PCI
# device or from the self-test, so the pattern requires a non-zero one.
AIA_PATTERNS = [
    re.compile(r"aia: identity=\d+ first message delivered hart=\d+ "
               r"wired_source=[1-9]\d*"),
]

PLIC_REQUIRED = [
    "exception: plic at ",
    "irq: riscv64 plic serving the interrupt-controller interface",
    "irq: riscv64 plic interface present (no LPI, no message-signalled "
    "translation)",
    "nvme: no message-signalled interrupts on this machine",
    "virtio-rng: MSI-X unavailable; queue=0 uses bounded polling",
    "nvme: MSI-X interrupt self-test skipped; queues=1 are polled",
]

PLIC_FORBIDDEN = [
    "aia: supervisor imsic base=",
    "irq: riscv64 aia",
    "nvme: MSI-X interrupt self-test passed",
]

FATAL = ["CYAN SCREEN OF DEATH", "assertion failed", "EXCEPTION: class="]


def stop_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def run_board(name: str, machine: str | None) -> dict[str, object]:
    image = BUILD / f"xaios-aia-gate-{name}.img"
    persistent = BUILD / f"xaios-aia-gate-{name}-persistent.img"
    log_path = BUILD / f"qemu-riscv64-aia-gate-{name}.log"
    subprocess.run(["truncate", "-s", "64M", str(image)], check=True)
    persistent.unlink(missing_ok=True)

    environment = qemu_boot_environment(
        "riscv64", os.environ.copy(), persistent=persistent,
        hostfwd_port="none", accel="tcg", smp=4,
        # A state directory per board. Sharing one would have the second boot
        # start from the first boot's disks, which is a run that measured a
        # machine nobody configured.
        state_dir=BUILD / f"qemu-riscv64-aia-gate-{name}-state",
        serial_to_stdout=True)
    environment["XAIOS_NVME_IMAGE"] = str(image)
    # Both directions set explicitly: the default-board half of this gate is
    # only meaningful if it really ran on the default board, and inheriting a
    # board from whoever invoked the gate would silently make both halves the
    # same machine.
    if machine is None:
        environment.pop("XAIOS_RISCV64_MACHINE", None)
    else:
        environment["XAIOS_RISCV64_MACHINE"] = machine

    required = list(COMMON)
    forbidden: list[str] = list(FATAL)
    patterns: list[re.Pattern] = []
    if machine is None:
        required += PLIC_REQUIRED
        forbidden += PLIC_FORBIDDEN
    else:
        required += AIA_REQUIRED
        forbidden += AIA_FORBIDDEN
        patterns += AIA_PATTERNS

    chunks: list[str] = []
    with log_path.open("wb") as log:
        process = subprocess.Popen(
            [qemu_runner("riscv64")],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=environment,
            start_new_session=True,
        )
        deadline = time.time() + smoke_timeout(
            "riscv64", int(environment.get("XAIOS_QEMU_AIA_TIMEOUT", "180")))
        try:
            assert process.stdout is not None
            descriptor = process.stdout.fileno()
            while time.time() < deadline:
                ready, _, _ = select.select([descriptor], [], [], 0.2)
                if ready:
                    data = os.read(descriptor, 4096)
                    if not data:
                        break
                    text = data.decode("utf-8", errors="replace")
                    log.write(data)
                    log.flush()
                    sys.stdout.write(text)
                    sys.stdout.flush()
                    chunks.append(text)
                    output = "".join(chunks)
                    if (all(marker in output for marker in required) and
                            all(pattern.search(output)
                                for pattern in patterns)):
                        break
                elif process.poll() is not None:
                    break
        finally:
            stop_process(process)

    output = "".join(chunks)
    missing = [marker for marker in required if marker not in output]
    missing += [pattern.pattern for pattern in patterns
                if pattern.search(output) is None]
    present = [marker for marker in forbidden if marker in output]
    return {
        "status": "pass" if not missing and not present else "fail",
        "machine": machine or "virt",
        "missing_markers": missing,
        "forbidden_markers": present,
        "guest_log": str(log_path),
    }


def main() -> int:
    BUILD.mkdir(parents=True, exist_ok=True)
    boards = (("plic", None), ("aia", "virt,aia=aplic-imsic"))
    results: dict[str, dict[str, object]] = {}
    for name, machine in boards:
        print(f"qemu-riscv64-aia-gate: booting {name} "
              f"({machine or 'virt'})", flush=True)
        results[name] = run_board(name, machine)
    passed = all(result["status"] == "pass" for result in results.values())
    REPORT.write_text(
        json.dumps(
            {
                "schema": "xaios.qemu.riscv64.aia.v1",
                "status": "pass" if passed else "fail",
                "boards": results,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    if not passed:
        print(f"qemu-riscv64-aia-gate: failed report={REPORT}",
              file=sys.stderr)
        return 1
    print("qemu-riscv64-aia-gate: the same kernel polled on the PLIC board "
          "and was delivered messages by the APLIC/IMSIC pair -- imsic "
          "loopback, aplic forwarding, a wired virtio transport and an NVMe "
          f"completion; report={REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
