#!/usr/bin/env python3
"""Boot XAIOS under Apple Virtualization.framework and check what came up.

This is a local gate. It needs macOS on Apple Silicon, a signed harness and the
framework itself, none of which exist on the CI runners, so it is not part of
the CI workflow and its result is not qualification evidence.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
VZ = BUILD / "vz"
REPORT = BUILD / "vz-gate.json"
BOOT_TIMEOUT_S = int(os.environ.get("XAIOS_VZ_TIMEOUT", "240"))

# Every volume the kernel expects, in the order it identifies them on the bus.
VOLUMES = (
    ("vz-test.img", "xaios-virtio-test.img"),
    ("vz-persistent.img", "xaios-persistent.img"),
    ("vz-model.img", "xaios-xaifs.img"),
    ("vz-storage-admin.img", None),
    ("vz-system.img", "xaios-system.img"),
    ("vz-system2.img", "xaios-system.img"),
)

# What a healthy boot says. Each is required.
EXPECTED = (
    ("kernel started", re.compile(r"XAIOS Build \d+ kernel starting")),
    ("virtio console attached", re.compile(r"virtio-console: kernel log attached")),
    ("durable volume mounted", re.compile(r"xaibootfs: persistent mounted")),
    ("filesystem checked", re.compile(r"persistent fsck valid=1")),
    ("IPv4 configured by DHCP", re.compile(r"network: DHCP lease ip=")),
    ("IPv6 address configured", re.compile(r"IPv6 address configured from advertised")),
    ("SSH server listening", re.compile(r"SSH server: up and running")),
    ("all four vCPUs online", re.compile(r"smp: online cpus=4/4")),
    ("shell command surface",
     re.compile(r"/bin/xaios-shell: command surface passed")),
    ("syscall and filesystem suite",
     re.compile(r"/bin/systest: syscall and filesystem suite passed")),
    ("C toolchain and EL0 runtime",
     re.compile(r"/bin/hello: C toolchain and EL0 runtime integration passed")),
    ("system information tool", re.compile(r"/bin/sysinfo: complete")),
    ("network test application", re.compile(r"/bin/nettest: complete")),
    ("multi-core test application", re.compile(r"/bin/smptest: complete")),
    ("agent protocol dispatch",
     re.compile(r"/bin/agenttest: agent protocol dispatch passed")),
    ("pipe and redirect surface",
     re.compile(r"/bin/posix-shell: pipe and redirect surface passed")),
)

# What it must never say.
FORBIDDEN = (
    ("kernel panic", re.compile(r"CYAN SCREEN OF DEATH")),
    ("assertion failure", re.compile(r"ERROR: assertion failed")),
    # Rescue mode is a healthy response to a damaged system and a wrong state
    # to declare a boot good in: it refuses ordinary commands while still
    # reaching a login prompt, so every kernel-level marker above can pass
    # while the applications a person would run do not work.
    ("booted into rescue mode", re.compile(r"lifecycle initialized[^\n]*rescue=1")),
)


def fail(message: str) -> int:
    print(f"vz-gate: {message}")
    return 1


def prepare() -> str | None:
    harness = VZ / "xaios-vz"
    if not harness.is_file():
        return "harness missing; build and sign platform/virtualization-framework/xaios_vz.swift first"
    subprocess.run([str(ROOT / "platform/virtualization-framework/build-vz-disk.sh")], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    shutil.copy(VZ / "xaios-vz-disk.img", VZ / "run-disk.img")
    # A fresh durable volume, not a copy of the shared one. The lifecycle
    # record lives on it -- boot counts, and the marker that puts the system
    # into rescue mode -- and build/xaios-persistent.img is written by every
    # QEMU boot as well. Enough hard power-offs across any of those gates and
    # the marker is set, after which the guest still boots, mounts, gets a
    # lease and runs sshd, but refuses ordinary commands. Copying that state in
    # made this gate depend on how many times unrelated gates had run.
    # The generator declines to overwrite, so remove it first: leaving the old
    # file in place is exactly the accumulation this is meant to end.
    (VZ / "vz-persistent.img").unlink(missing_ok=True)
    subprocess.run([str(ROOT / "scripts/create-persistent-image.sh")],
                   env={**os.environ,
                        "XAIOS_PERSISTENT_IMAGE": str(VZ / "vz-persistent.img")},
                   check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL)

    for target, source in VOLUMES:
        destination = VZ / target
        if target == "vz-persistent.img":
            continue
        if source is None:
            if not destination.is_file():
                destination.write_bytes(b"\0" * (16384 * 512))
            continue
        # Refresh every volume: the loader prefers the kernel on the A/B system
        # volume over the one on the ESP, so a stale copy boots a stale kernel
        # and the run proves nothing about the build under test.
        shutil.copy(BUILD / source, destination)
    return None


def run() -> tuple[str, bool]:
    log = VZ / "vz-gate.log"
    command = [str(VZ / "xaios-vz"), str(VZ / "run-disk.img")]
    command += [str(VZ / target) for target, _ in VOLUMES]
    # Four vCPUs, not one: secondaries start with translation off, and every
    # defect that state causes is invisible on a single-CPU boot.
    command += ["--memory-mib", "2048", "--cpus", "4"]
    with log.open("wb") as handle:
        process = subprocess.Popen(command, stdout=handle,
                                   stderr=subprocess.STDOUT,
                                   stdin=subprocess.DEVNULL)
        deadline = time.monotonic() + BOOT_TIMEOUT_S
        settled = False
        try:
            while time.monotonic() < deadline:
                time.sleep(5)
                text = log.read_bytes().decode("utf-8", "replace")
                if any(pattern.search(text) for _, pattern in FORBIDDEN):
                    break
                if all(pattern.search(text) for _, pattern in EXPECTED):
                    settled = True
                    break
        finally:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
    return log.read_bytes().decode("utf-8", "replace"), settled


def main() -> int:
    if sys.platform != "darwin":
        return fail("this gate runs only on macOS")
    problem = prepare()
    if problem is not None:
        return fail(problem)
    text, settled = run()

    checks = [{"name": name, "passed": bool(pattern.search(text))}
              for name, pattern in EXPECTED]
    faults = [{"name": name, "seen": bool(pattern.search(text))}
              for name, pattern in FORBIDDEN]
    passed = all(check["passed"] for check in checks) and \
        not any(fault["seen"] for fault in faults)

    REPORT.write_text(json.dumps({
        "target": "apple-virtualization-framework-aarch64",
        "qualification_evidence": False,
        "settled_before_timeout": settled,
        "checks": checks,
        "faults": faults,
        "passed": passed,
    }, indent=2) + "\n", encoding="utf-8")

    for check in checks:
        print(f"  {'ok  ' if check['passed'] else 'MISS'} {check['name']}")
    for fault in faults:
        if fault["seen"]:
            print(f"  FAULT {fault['name']}")
    print(f"vz-gate: report written to {REPORT}")
    if not passed:
        return fail("boot did not reach a healthy state")
    print("vz-gate: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
