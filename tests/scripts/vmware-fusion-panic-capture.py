#!/usr/bin/env python3
"""Prove a Fusion panic is diagnosable, by causing one and reading it back.

B-15 fired once on VMware Fusion ARM64 and left fifteen stack addresses and
nothing else -- no load base, so the addresses could not be turned into
function names, and no log, so there was no saying what the kernel had been
doing. The panic screen was then taught to print both. That fix has been
described as making the next occurrence answerable in one step, but it had
only ever been exercised under QEMU. A diagnostic that has never run on the
machine it was written for is a claim, not evidence.

So this builds a kernel with a deliberate assertion (XAIOS_PANIC_SELFTEST,
compiled out of everything else), boots it on Fusion, and requires the
serial console to carry every part a real diagnosis needs:

  the cyan screen, the assertion text with its expression, the load base,
  a backtrace, the replayed kernel log, and the halt line.

Then it does the step an operator would do next: runs the panic through
resolve-panic.py, the script the panic screen names, and requires a frame to
come back as kmain -- where the deliberate assertion is. Anything less means
the next B-15 occurrence produces the same fifteen useless addresses.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

_SPEC = importlib.util.spec_from_file_location(
    "vmware_fusion_smoke", Path(__file__).with_name("vmware-fusion-smoke.py"))
smoke = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(smoke)

EVIDENCE = smoke.FUSION_BUILD / "fusion-panic-capture.json"
KERNEL_ELF = ROOT / "build" / "kernel" / "kernel.elf"

FRAME = re.compile(r"^\s*#(\d+)\s+(0x[0-9a-f]+)\s*$", re.MULTILINE)
LOAD_BASE = re.compile(r"load base (0x[0-9a-f]+)")


def required_parts(console: str) -> list[str]:
    """What has to be present for a panic to be diagnosable at all."""
    missing = []
    for label, marker in (
        ("cyan screen banner", "CYAN SCREEN OF DEATH"),
        ("the assertion and its expression", "assertion failed: 0 == 1"),
        # Not "load base 0x": the kernel prints that on every ordinary boot
        # now, so matching it reported the load base as present on a guest
        # that had never panicked at all. The resolver line is printed only
        # by the panic path.
        ("the panic's own load base line", "resolve with: tests/scripts/resolve-panic.py"),
        ("a stack backtrace", "--- Stack Backtrace ---"),
        ("the replayed kernel log", "--- Recent Kernel Log ---"),
        ("the halt line", "System halted"),
    ):
        if marker not in console:
            missing.append(f"{label} ({marker!r})")
    return missing


def resolve_like_an_operator(console: str) -> tuple[str, str]:
    """Run the panic through the script the panic screen tells you to run.

    Deliberately shells out to resolve-panic.py rather than reimplementing
    it. A gate that resolves addresses its own way proves its own way works;
    the thing that has to work is the path an operator is sent down.
    """
    resolver = Path(__file__).with_name("resolve-panic.py")
    result = subprocess.run(
        [sys.executable, str(resolver), "--kernel", str(KERNEL_ELF)],
        input=console, text=True, capture_output=True, timeout=300)
    output = result.stdout + result.stderr
    if result.returncode != 0:
        raise RuntimeError(
            "resolve-panic.py could not name a single frame:\n" + output)
    named = [line.strip() for line in result.stdout.splitlines()
             if "->" in line and "not in kernel text" not in line]
    if not named:
        raise RuntimeError("no frame resolved to a function:\n" + output)
    # The assertion is in kmain, so kmain is what the top of a kernel-text
    # frame has to be. Without this the check would pass on any name at all,
    # including one resolved against the wrong build.
    if not any("kmain" in line for line in named):
        raise RuntimeError(
            "frames resolved, but none to kmain, where the deliberate "
            "assertion is -- so the resolution is not trustworthy:\n" + output)
    return named[0], output.strip()


def main() -> int:
    environment = os.environ.copy()
    environment["XAIOS_PANIC_SELFTEST"] = "1"
    # The kernel has to be built here, first.
    #
    # build-vmware-fusion.sh only packages what is already in build/ -- it
    # refuses outright if the artifacts are missing and tells you to run
    # `make image`. Handing it XAIOS_PANIC_SELFTEST therefore did nothing
    # whatsoever, and the first run of this gate boxed up an ordinary kernel,
    # booted it to a login prompt, and reported no panic. Which was the right
    # answer to the question it asked, and not the question intended.
    for step in (["./scripts/build-image.sh"],
                 ["./platform/vmware-fusion/build-vmware-fusion.sh"]):
        build = subprocess.run(step, cwd=ROOT, env=environment, text=True,
                               capture_output=True, timeout=1800)
        if build.returncode != 0:
            print(f"{step[0]} failed:\n"
                  + build.stdout[-2000:] + build.stderr[-2000:], file=sys.stderr)
            return 2

    if smoke.vm_running():
        smoke.vmrun(["stop", str(smoke.VMX), "hard"], check=False)
        smoke.wait_for_stopped()
    smoke.SERIAL.unlink(missing_ok=True)
    smoke.vmrun(["start", str(smoke.VMX), "nogui"])

    # The guest halts rather than booting, so waiting for a ready marker would
    # only ever time out. Wait for the halt line instead, which is the thing
    # under test arriving.
    deadline = time.monotonic() + int(os.environ.get("XAIOS_FUSION_TIMEOUT", "180"))
    console = ""
    while time.monotonic() < deadline:
        console = smoke.serial_text()
        if "System halted" in console:
            break
        time.sleep(0.5)

    kept = smoke.FUSION_BUILD / "fusion-panic-console.log"
    kept.write_text(console, encoding="utf-8")
    if smoke.vm_running():
        smoke.vmrun(["stop", str(smoke.VMX), "hard"], check=False)

    missing = required_parts(console)
    if missing:
        print(f"the panic reached the console but is not diagnosable; missing:\n  "
              + "\n  ".join(missing)
              + f"\nconsole kept at {kept.relative_to(ROOT)}", file=sys.stderr)
        return 1

    try:
        function, provenance = resolve_like_an_operator(console)
    except RuntimeError as error:
        print(f"panic printed everything but could not be resolved: {error}\n"
              f"console kept at {kept.relative_to(ROOT)}", file=sys.stderr)
        return 1

    smoke.FUSION_BUILD.mkdir(parents=True, exist_ok=True)
    EVIDENCE.write_text(json.dumps({
        "platform": "vmware-fusion-aarch64",
        "fusion_version": smoke.fusion_version(),
        "resolved_function": function,
        "resolved_from": provenance,
        "console": str(kept.relative_to(ROOT)),
        "console_lines": len(console.splitlines()),
        "claim": ("a panic on this platform carries its load base, backtrace "
                  "and kernel log, and a frame resolves to a function name"),
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print("fusion-panic-capture: the panic is diagnosable on Fusion --\n"
          f"  {function}\n"
          f"{provenance}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
