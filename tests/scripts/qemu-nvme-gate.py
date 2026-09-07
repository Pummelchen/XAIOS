#!/usr/bin/env python3
"""Validate asynchronous NVMe behaviour on every QEMU machine this builds for.

Two of the three deliver completions by message-signalled interrupt and are
held to that. The third cannot: the PLIC takes wires, not messages, so the
driver runs its queues on polled completion -- which is a supported mode, not
a degraded one, and the driver's own wait path has always polled while
waiting. What must not differ is everything else: the controller comes ready,
identify answers, the async round trip completes, a cancellation is honoured,
scatter-gather and direct transfers both work, four malformed commands are
refused, and the bytes the guest wrote are the bytes on the host's disk.

The number of IO queues differs too, and for a reason worth naming rather
than papering over: the driver asks for one queue per online CPU, and on
RISC-V the secondary harts are not online yet when NVMe initialises. One
queue here, four elsewhere.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time
import re

sys.path.insert(0, str(Path(__file__).resolve().parent))
from qemu_gate_lib import qemu_boot_environment, qemu_runner, smoke_timeout


BUILD = Path("build")
REPORT = BUILD / "qemu-nvme-gate-report.json"
MARKERS = [
    "nvme: controller ready version=",
    "nvme: identify controller serial='XAIOSNVME",
    "nvme: async self-test passed namespaces=1",
]

# What each machine is held to beyond the shared markers: how many IO queues
# the driver ended up with, and how many of them carry a message-signalled
# interrupt. Stated per architecture rather than accepted from the log, so a
# machine that quietly lost its interrupts fails here.
# `min_async` scales with the queue count for the same reason: the stress
# rounds submit per queue, so a one-queue machine legitimately completes fewer
# operations. It is a floor, not an expectation -- 11 were observed on RISC-V
# and 38 is the long-standing floor for the four-queue machines.
# `machine` selects the board a row runs on, and only RISC-V has more than
# one. `arch` is which runner and which build the row uses, which is the row's
# own name unless it is a second configuration of one that is already listed.
#
# The two RISC-V rows are the same kernel image on two boards, and they must
# disagree. QEMU's default `virt` publishes a PLIC, which carries wires and no
# messages, so every queue there is polled -- that is not a defect and the row
# says so positively, with `msix: 0` and the skipped-self-test marker, so that
# a build which quietly stopped configuring interrupts everywhere cannot pass
# by looking like it. `virt,aia=aplic-imsic` publishes an APLIC and an IMSIC,
# and there the same kernel must find them, program an MSI-X vector per queue
# and be handed its completions by interrupt. Asserting only one of the two
# would let a regression in either direction through: a kernel that lost AIA
# support, or one that started claiming messages on a board with none.
#
# The queue count is one on both, and stays one for a reason that has nothing
# to do with interrupts: the driver asks for one queue per online CPU, and on
# RISC-V the secondary harts are still held at the scheduler rendezvous when
# NVMe initialises. Four queues here would be a change to SMP bring-up order,
# not to this driver.
PROFILE = {
    "aarch64": {"io_queues": 4, "msix": 4, "min_async": 38,
                "controller": "controller=gicv3-its"},
    "x86_64": {"io_queues": 4, "msix": 4, "min_async": 38,
               "controller": "controller=x86-apic"},
    "riscv64": {"io_queues": 1, "msix": 0, "min_async": 10,
                "controller": None},
    "riscv64-aia": {"arch": "riscv64", "machine": "virt,aia=aplic-imsic",
                    "io_queues": 1, "msix": 1, "min_async": 10,
                    "controller": "controller=aia-imsic"},
}

RESULT_PATTERN = re.compile(
    r"rounds=(?P<rounds>\d+) async=(?P<async_ops>\d+) "
    r"cancelled=(?P<cancelled>\d+) sgl=(?P<sgl>\d+) "
    r"direct=(?P<direct>\d+) malformed=(?P<malformed>\d+) "
    r"affinity=cpu msix=(?P<msix>\d+)"
)


def stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def selected_architectures() -> tuple[str, ...]:
    requested = os.environ.get("XAIOS_QEMU_NVME_ARCH", "all")
    for index, argument in enumerate(sys.argv):
        if argument == "--arch" and index + 1 < len(sys.argv):
            requested = sys.argv[index + 1]
        elif argument.startswith("--arch="):
            requested = argument.split("=", 1)[1]
    if requested == "all":
        return tuple(PROFILE)
    if requested in PROFILE:
        # Naming an architecture selects every board this gate knows for it,
        # not only the row that shares its name. `--arch riscv64` therefore
        # runs the PLIC board and the AIA board, which is the only way the two
        # halves of the claim -- polled where there are no messages, MSI-X
        # where there are -- get made in the same run.
        rows = tuple(
            name for name in PROFILE
            if name == requested or PROFILE[name].get("arch") == requested
        )
        return rows
    raise ValueError(
        f"architecture must be all or one of {', '.join(PROFILE)}; "
        f"got {requested!r}"
    )


def run_architecture(row: str) -> dict[str, object]:
    # The row's name identifies the configuration and names its files; the
    # architecture underneath it decides which runner and which build. They
    # differ only for a second board of an architecture already listed.
    profile = PROFILE[row]
    architecture = str(profile.get("arch", row))
    image = BUILD / f"xaios-nvme-gate-{row}.img"
    persistent = BUILD / f"xaios-nvme-gate-{row}-persistent.img"
    log_path = BUILD / f"qemu-nvme-gate-{row}.log"
    subprocess.run(["truncate", "-s", "64M", str(image)], check=True)
    persistent.unlink(missing_ok=True)

    environment = qemu_boot_environment(
        architecture, os.environ.copy(),
        persistent=persistent, hostfwd_port="none", accel="tcg", smp=4,
        # Per row, not per architecture: two boards of one architecture that
        # shared a state directory would each boot from the other's leftovers,
        # and a run whose second half booted the first half's disks is a run
        # that measured the wrong machine.
        state_dir=BUILD / f"qemu-nvme-gate-{row}-state",
        # The boot is read from the runner's stdout; the RISC-V runner would
        # otherwise write it to a file of its own.
        serial_to_stdout=True)
    if architecture == "aarch64":
        environment["XAIOS_QEMU_MSI_CONTROLLER"] = "its"
        environment["XAIOS_NVME_IMAGE"] = str(image)
    elif architecture == "x86_64":
        environment["XAIOS_QEMU_X86_NVME_IMAGE"] = str(image)
    else:
        environment["XAIOS_NVME_IMAGE"] = str(image)
    # The board, for the one architecture here that has a choice of them. Set
    # explicitly both ways rather than left to the runner's default: the whole
    # point of a row is which board it is, and a row that inherited a board
    # from whoever invoked the gate would report a result about a machine
    # nobody asked for -- with the default-board row, which must find no
    # message-signalled interrupts, the one most likely to be quietly wrong.
    if profile.get("machine") is not None:
        environment["XAIOS_RISCV64_MACHINE"] = str(profile["machine"])
    else:
        environment.pop("XAIOS_RISCV64_MACHINE", None)
    runner = qemu_runner(architecture)
    required_markers = list(MARKERS)
    required_markers.append(
        f"queue_depth=16 io_queues={profile['io_queues']} prp_pages=4 "
        f"transfer_bytes=16384 rounds=8")
    required_markers.append(
        f"affinity=cpu msix={profile['msix']} write_read_flush=1")
    if profile["msix"] != 0:
        required_markers.append(
            f"nvme: MSI-X interrupt self-test passed "
            f"queues={profile['msix']} all_queues=1")
        required_markers.append(profile["controller"])
    else:
        # The positive statement that this machine polls, so a build that
        # silently stopped configuring interrupts elsewhere cannot pass by
        # looking like this one.
        required_markers.append(
            "nvme: no message-signalled interrupts on this machine")
        required_markers.append(
            f"nvme: MSI-X interrupt self-test skipped; "
            f"queues={profile['io_queues']} are polled")

    with log_path.open("wb") as log:
        process = subprocess.Popen(
            [runner],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=environment,
            start_new_session=True,
        )
        chunks: list[str] = []
        deadline = time.time() + smoke_timeout(
            architecture,
            int(environment.get("XAIOS_QEMU_NVME_TIMEOUT", "120")))
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
                    if all(marker in output for marker in required_markers):
                        break
                elif process.poll() is not None:
                    break
        finally:
            stop_process(process)

    output = "".join(chunks)
    missing = [marker for marker in required_markers if marker not in output]
    forbidden = [
        marker
        for marker in ("CYAN SCREEN OF DEATH", "nvme: self-test failed")
        if marker in output
    ]
    match = RESULT_PATTERN.search(output)
    metrics = (
        {key: int(value) for key, value in match.groupdict().items()}
        if match is not None
        else {}
    )
    with image.open("rb") as stream:
        first_transfer = stream.read(16384)
    expected = bytes((index ^ 0xA5) & 0xFF for index in range(16384))
    host_verified = first_transfer == expected
    behavior_verified = bool(
        metrics
        and metrics["rounds"] >= 8
        and metrics["async_ops"] >= profile["min_async"]
        and metrics["cancelled"] >= 1
        and metrics["sgl"] >= 1
        and metrics["direct"] == metrics["async_ops"]
        and metrics["malformed"] >= 4
        and metrics["msix"] == profile["msix"]
    )
    passed = not missing and not forbidden and host_verified and behavior_verified
    return {
        "status": "pass" if passed else "fail",
        "controller": "QEMU NVMe",
        "queue_depth": 16,
        "io_queues": profile["io_queues"],
        "prp_pages": 4,
        "transfer_bytes": 16384,
        "guest_write_read_flush": not missing and not forbidden,
        "host_backing_image_verified": host_verified,
        "async_behavior_verified": behavior_verified,
        "msix_delivery_verified": not any(
            "MSI-X interrupt self-test" in marker for marker in missing
        ),
        "metrics": metrics,
        "missing_markers": missing,
        "forbidden_markers": forbidden,
        "guest_log": str(log_path),
    }


def main() -> int:
    BUILD.mkdir(parents=True, exist_ok=True)
    try:
        architectures = selected_architectures()
    except ValueError as error:
        print(f"qemu-nvme-gate: {error}", file=sys.stderr)
        return 2
    results: dict[str, dict[str, object]] = {}
    for architecture in architectures:
        print(f"qemu-nvme-gate: testing {architecture}", flush=True)
        results[architecture] = run_architecture(architecture)
    passed = all(result["status"] == "pass" for result in results.values())
    REPORT.write_text(
        json.dumps(
            {
                "schema": "xaios.qemu.nvme.v4",
                "status": "pass" if passed else "fail",
                "qemu_correctness_only": True,
                "requested_architectures": list(architectures),
                "architectures": results,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    if not passed:
        print(f"qemu-nvme-gate: failed report={REPORT}", file=sys.stderr)
        return 1
    queues = ", ".join(
        f"{arch} {PROFILE[arch]['io_queues']} "
        f"{'msix' if PROFILE[arch]['msix'] else 'polled'}"
        for arch in architectures)
    print(
        f"qemu-nvme-gate: async PRP/SGL direct I/O, cancellation, malformed "
        f"completion and stress passed on {queues}; report={REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
