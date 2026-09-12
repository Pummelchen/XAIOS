#!/usr/bin/env python3
"""VMware Fusion and Virtualization.framework at 1, 2 and 4 GiB.

`qemu-memory-matrix` does this for the three QEMU architectures. The two
hypervisors were left out, and they are where the memory-size defects actually
bit: B-06 was "Virtualization.framework boots to nothing below ~3.5 GiB", which
turned out to be a fixed kernel link address wearing a memory size, and B-12
was a Fusion framebuffer that firmware places above RAM.

Both gates ran at exactly 2048 MiB. That is not a neutral choice:

  * B-06 is about 1024 failing and 4096 working, so 2048 is the one value
    between them.
  * On Fusion, 2048 is the *only* size of the three where the firmware
    framebuffer lands inside the kernel's identity map. At 1024 it sits at
    0xf0000000 above 895 MiB of RAM, and at 4096 at 0xff0000000 above 3967
    MiB. The mapping B-12 added is load-bearing at both ends and needed at
    neither middle.

So the size every gate used is the size at which two of these defects cannot
occur. This runs the ends as well.

What it asserts beyond "it booted" is the same thing the QEMU matrix does: the
guest has to report managed memory matching what the hypervisor was told to
give it, and the figures have to rise across the three sizes. A kernel that
silently capped itself would boot perfectly at every size and report the same
number three times.

Fusion additionally reports where firmware put the framebuffer, which is what
distinguishes a boot that exercised B-12's mapping from one that did not.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
REPORT = BUILD / "hypervisor-memory-matrix.json"

_SPEC = importlib.util.spec_from_file_location(
    "vmware_fusion_smoke", Path(__file__).with_name("vmware-fusion-smoke.py"))
smoke = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(smoke)

SIZES_MIB = (1024, 2048, 4096)
# The trailing " pmm_free=" is what proves the number ended. This gate reads a
# finished console rather than a stream, so it cannot stop mid-number the way
# qemu-memory-matrix did in B-69 -- but a capture cut short by a killed guest
# gives the same truncated digits, and a prefix of a page count is a
# plausible-looking memory size rather than an obvious error.
PMM = re.compile(
    r"telemetry: boot_summary cpu_online=\d+ pmm_total=(\d+) pmm_free=")
FRAMEBUFFER = re.compile(
    r"boot-ui: framebuffer mapped base=0x([0-9a-f]+) bytes=0x[0-9a-f]+ "
    r"ram_pages=(\d+)")
PAGE_BYTES = 4096


def fusion(mib: int) -> dict[str, object]:
    environment = os.environ.copy()
    environment["XAIOS_FUSION_MEMSIZE"] = str(mib)
    result = subprocess.run(
        [sys.executable, str(ROOT / "tests/scripts/vmware-fusion-smoke.py")],
        cwd=ROOT, env=environment, text=True, capture_output=True,
        timeout=2400, check=False)
    console = smoke.serial_text() if smoke.SERIAL.is_file() else ""
    entry: dict[str, object] = {"platform": "vmware-fusion",
                                "requested_mib": mib,
                                "exit_code": result.returncode}
    pages = PMM.findall(console)
    entry["managed_mib"] = (int(pages[-1]) * PAGE_BYTES // (1024 * 1024)
                            if pages else 0)
    frame = FRAMEBUFFER.findall(console)
    if frame:
        base, ram_pages = frame[-1]
        ram_bytes = int(ram_pages) * PAGE_BYTES
        entry["framebuffer_base"] = f"0x{base}"
        # The comparison B-12 turns on, recorded per boot rather than inferred
        # from the memory size afterwards.
        entry["framebuffer_above_ram"] = int(base, 16) >= ram_bytes
    # The console is kept per size: they overwrite each other otherwise, and
    # the boot worth reading is always the one about to be replaced.
    kept = BUILD / "hypervisor-memory-matrix" / f"fusion-{mib}.log"
    kept.parent.mkdir(parents=True, exist_ok=True)
    kept.write_text(console, encoding="utf-8")
    entry["console"] = str(kept.relative_to(ROOT))
    return entry


def virtualization_framework(mib: int) -> dict[str, object]:
    environment = os.environ.copy()
    environment["XAIOS_VZ_MEMORY_MIB"] = str(mib)
    result = subprocess.run(
        [sys.executable, str(ROOT / "tests/scripts/vz-gate.py")],
        cwd=ROOT, env=environment, text=True, capture_output=True,
        timeout=2400, check=False)
    # The guest's console, not the gate's checklist. vz-gate prints a list of
    # named checks and writes the boot itself to build/vz/vz-gate.log, so
    # parsing its stdout finds no telemetry line and reports a guest managing
    # no memory at all -- which is what the first run of this gate did.
    log = ROOT / "build" / "vz" / "vz-gate.log"
    console = log.read_text(errors="replace") if log.is_file() else ""
    console += result.stdout + result.stderr
    entry: dict[str, object] = {"platform": "virtualization-framework",
                                "requested_mib": mib,
                                "exit_code": result.returncode}
    pages = PMM.findall(console)
    entry["managed_mib"] = (int(pages[-1]) * PAGE_BYTES // (1024 * 1024)
                            if pages else 0)
    kept = BUILD / "hypervisor-memory-matrix" / f"vz-{mib}.log"
    kept.parent.mkdir(parents=True, exist_ok=True)
    kept.write_text(console, encoding="utf-8")
    entry["console"] = str(kept.relative_to(ROOT))
    return entry


def main() -> int:
    if sys.platform != "darwin":
        print("hypervisor-memory-matrix: needs macOS")
        return 0
    if not smoke.VMRUN.is_file():
        print(f"hypervisor-memory-matrix: no vmrun at {smoke.VMRUN}; skipping")
        return 0

    results: list[dict[str, object]] = []
    failures: list[str] = []
    for platform, run in (("VMware Fusion", fusion),
                          ("Virtualization.framework",
                           virtualization_framework)):
        for mib in SIZES_MIB:
            print(f"hypervisor-memory-matrix: {platform} at {mib} MiB",
                  flush=True)
            entry = run(mib)
            results.append(entry)
            if entry["exit_code"] != 0:
                failures.append(
                    f"{entry['platform']} did not complete its gate at "
                    f"{mib} MiB (exit {entry['exit_code']}); console at "
                    f"{entry['console']}")
                continue
            managed = int(entry["managed_mib"])
            if not 0.80 * mib <= managed <= 1.02 * mib:
                failures.append(
                    f"{entry['platform']} at {mib} MiB manages {managed} MiB, "
                    f"which is not the memory it was given; a kernel that "
                    f"capped itself boots perfectly and reports exactly this")

    for platform in ("vmware-fusion", "virtualization-framework"):
        managed = [int(r["managed_mib"]) for r in results
                   if r["platform"] == platform and r["exit_code"] == 0]
        if len(managed) == len(SIZES_MIB) and not all(
                b > a for a, b in zip(managed, managed[1:])):
            failures.append(
                f"{platform} reported {managed} MiB across "
                f"{list(SIZES_MIB)}: the figures do not rise, so the size "
                f"never reached the hypervisor and these are three boots of "
                f"one machine")

    report = {"schema": "xaios.hypervisor.memory_matrix.v1",
              "status": "pass" if not failures else "fail",
              "sizes_mib": list(SIZES_MIB),
              "results": results,
              "failures": failures}
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                      encoding="utf-8")
    if failures:
        for failure in failures:
            print(f"hypervisor-memory-matrix: FAIL {failure}")
        print(f"hypervisor-memory-matrix: report={REPORT}")
        return 1
    summary = ", ".join(f"{r['platform'].split('-')[0]}@{r['requested_mib']}="
                        f"{r['managed_mib']}MiB" for r in results)
    frames = [f"{r['requested_mib']}MiB:{r.get('framebuffer_base')}"
              f"{'(above RAM)' if r.get('framebuffer_above_ram') else ''}"
              for r in results if r["platform"] == "vmware-fusion"
              and r.get("framebuffer_base")]
    print(f"hypervisor-memory-matrix: Fusion and Virtualization.framework "
          f"each boot at 1024, 2048 and 4096 MiB and manage the memory they "
          f"are given -- {summary}; Fusion framebuffer placement "
          f"{', '.join(frames)}; report={REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
