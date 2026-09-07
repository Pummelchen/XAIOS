#!/usr/bin/env python3
"""Every architecture at 1, 2 and 4 GiB, and does the kernel take what it is given?

Two claims this project makes had never been tested as a matrix, and both are
about how much memory the machine has.

The first is B-11. Userspace and the kernel's identity map used to be the same
addresses, and *which machines noticed depended only on how much RAM they
had*: VMware Fusion faulted at level 1, QEMU ARM64 booted and failed a
self-test much further in, and x86_64 was unaffected because its identity map
happened to stop just below the window. Two years of 2 GiB gates never saw
it. The fix caps the identity map at `XAIOS_USER_BASE`, and the only way to
show that a cap works is to boot machines on both sides of where it used to
break -- so the size that reproduced the original defect is in the matrix
rather than assumed away.

The second is B-05 and B-06: one fixed kernel link address blocked a 1 GiB
profile, and Virtualization.framework "could not boot below ~3.5 GiB" turned
out to be the same defect wearing a memory size. A bisected number that
matches no placement model is what a fixed link address looks like from the
outside, and only a matrix says whether that is really gone.

What it asserts is stronger than "it booted", because a kernel that silently
capped itself at a gibibyte would boot perfectly at every size. Each boot has
to report managed memory that matches the memory the machine was actually
given, and the reported figures have to *rise* with the requested size. That
second requirement is also this gate's negative control on itself: the three
runners read three differently-named environment variables, and a gate that
set the wrong one would boot three identical 2 GiB machines and pass every
per-boot check. Three equal numbers fail here.
"""

from __future__ import annotations

import json
import os
import re
import select
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
sys.path.insert(0, str(ROOT / "tests" / "scripts"))
from qemu_gate_lib import (qemu_boot_environment, qemu_runner,
                           smoke_timeout)

REPORT = BUILD / "qemu-memory-matrix-report.json"
SCHEMA = "xaios.qemu.memory_matrix.v1"

# The sizes, and why these three.
#
# 1 GiB is B-05's profile, the one a fixed link address excluded. 2 GiB is
# what every gate in this tree already ran, and is here as the control: if it
# fails, the change under test broke the configuration everything else uses.
# 4 GiB is B-11's, the size at which the identity map used to reach into
# userspace -- below it the collision could not happen, which is exactly why
# it went unnoticed for so long.
SIZES_MIB = (1024, 2048, 4096)

# The memory knob is spelled differently by each runner, and there is no
# shared name for it. Getting this wrong is silent: the runner falls back to
# its default and the boot succeeds, which is why the scaling assertion below
# exists rather than trusting this table.
MEMORY_VARIABLE = {
    "aarch64": "XAIOS_QEMU_MEMORY",
    "x86_64": "XAIOS_QEMU_X86_MEMORY",
    "riscv64": "XAIOS_RISCV64_MEMORY",
}

ARCHITECTURES = ("aarch64", "x86_64", "riscv64")

# Enough of a boot to say the address space survived being resized, in each
# architecture's own words.
#
# The VMM self-tests are the point: they are what failed "further in" on QEMU
# ARM64 when the identity map and userspace overlapped, rather than at the
# first access the way Fusion did. All three run the same tests and none of
# them announce it the same way, so one shared string would silently never
# match on two of the three -- a gate reporting the wording of a log line as a
# broken address space.
# B-19 rides along here for free: this gate boots nine machines across three
# architectures and three memory sizes, and firmware picks a different load
# address for most of them -- the two QEMU AArch64 addresses seen today differ
# purely because the memory size did. That is the widest spread of placements
# anything in this tree produces, and the alignment invariant is one line.
ALIGNMENT_MARKER = "offset_in_64k 0"
BOOT_MARKERS = {
    "aarch64": ("VMM map/unmap self-test passed", "VMM translation test passed",
                ALIGNMENT_MARKER),
    "x86_64": ("VMM: x86 map/unmap self-test passed",
               "VMM: x86 self-test translated", ALIGNMENT_MARKER),
    "riscv64": ("vmm: self-test passed (map, translate, write, unmap)",
                "VMM translation test passed", ALIGNMENT_MARKER),
}
# Said by the boot UI, not the kernel. Reaching this with none of the markers
# above means a release image was booted: there the boot UI owns the console
# and the kernel log is suppressed, so the machine is perfectly healthy and
# the gate can see none of what it came to check.
RELEASE_TELL = "xaios login:"

# Built here rather than through `make`, and that is the same trap in a
# different place. The `qemu-<arch>` make targets depend on `image-<arch>`,
# which is the RELEASE configuration -- so booting through make quietly
# rebuilt the release image over the boot-test one and then booted it. The
# runner is invoked directly, against images this gate builds itself with the
# test applications switched on.
IMAGE_BUILD = {
    "aarch64": [["./scripts/build-image.sh"]],
    "x86_64": [["./scripts/build-image.sh"]],
    "riscv64": [["./scripts/build-riscv64.sh"], ["./scripts/build-riscv64-image.sh"]],
}
FATAL = ("KERNEL PANIC", "CYAN SCREEN OF DEATH", "assertion failed",
         "System halted")

TELEMETRY = re.compile(r'"pmm_total_pages":\s*(\d+)')
PAGE_BYTES = 4096


def memory_argument(arch: str, mib: int) -> str:
    """What this runner wants: a QEMU size string, or a bare count of MiB.

    riscv64's runner defaults to "1024" and passes the value straight to -m,
    where a bare number means mebibytes. The other two default to "2G". Both
    forms reach QEMU intact, but the runner's own default tells you which the
    author expected to see, and matching it keeps a `--dry-run` readable.
    """
    if arch == "riscv64":
        return str(mib)
    return f"{mib // 1024}G"


def build(arch: str) -> None:
    env = os.environ.copy()
    env["XAIOS_BOOT_TEST_APPS"] = "1"
    if arch == "x86_64":
        env["XAIOS_TARGET_ARCH"] = "x86_64"
    for command in IMAGE_BUILD[arch]:
        subprocess.run(command, cwd=ROOT, env=env, check=True,
                       stdout=subprocess.DEVNULL)


def boot(arch: str, mib: int) -> tuple[str, int]:
    env = os.environ.copy()
    env[MEMORY_VARIABLE[arch]] = memory_argument(arch, mib)
    # A durable volume per boot. Sharing one across nine boots would let a
    # volume formatted by the 4 GiB machine be mounted by the 1 GiB one, and
    # any resulting failure would be about this gate rather than about memory.
    persistent = BUILD / f"memory-matrix-{arch}-{mib}.img"
    persistent.unlink(missing_ok=True)
    state_dir = BUILD / "memory-matrix-state" / f"{arch}-{mib}"
    shutil.rmtree(state_dir, ignore_errors=True)
    state_dir.mkdir(parents=True, exist_ok=True)
    env = qemu_boot_environment(arch, env, persistent=persistent,
                                state_dir=state_dir, hostfwd_port="none",
                                serial_to_stdout=True)
    process = subprocess.Popen(
        [qemu_runner(arch)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        bufsize=1, env=env, cwd=ROOT, start_new_session=True)
    deadline = time.time() + smoke_timeout(arch, 240)
    output: list[str] = []
    try:
        descriptor = process.stdout.fileno()
        while time.time() < deadline:
            ready, _, _ = select.select([descriptor], [], [], 0.2)
            if ready:
                chunk = os.read(descriptor, 8192).decode("utf-8",
                                                         errors="replace")
                if not chunk:
                    break
                output.append(chunk)
                text = "".join(output)
                if TELEMETRY.search(text) and all(
                        marker in text for marker in BOOT_MARKERS[arch]):
                    break
            elif process.poll() is not None:
                break
    finally:
        if process.poll() is None:
            try:
                os.killpg(process.pid, 15)
                process.wait(timeout=10)
            except Exception:  # noqa: BLE001 - the boot is over either way
                try:
                    os.killpg(process.pid, 9)
                except ProcessLookupError:
                    pass
    text = "".join(output)
    pages = [int(match) for match in TELEMETRY.findall(text)]
    return text, pages[0] if pages else 0


def main() -> int:
    results: list[dict[str, object]] = []
    failures: list[str] = []
    for arch in ARCHITECTURES:
        print(f"qemu-memory-matrix: building the {arch} boot-test image",
              flush=True)
        build(arch)
        for mib in SIZES_MIB:
            print(f"qemu-memory-matrix: booting {arch} at {mib} MiB",
                  flush=True)
            text, pages = boot(arch, mib)
            managed_mib = (pages * PAGE_BYTES) // (1024 * 1024)
            fatal = [marker for marker in FATAL if marker in text]
            missing = [m for m in BOOT_MARKERS[arch] if m not in text]
            entry = {
                "architecture": arch,
                "requested_mib": mib,
                "managed_mib": managed_mib,
                "pmm_total_pages": pages,
                "fatal_markers": fatal,
                "missing_markers": missing,
            }
            log = BUILD / "memory-matrix" / f"{arch}-{mib}.log"
            log.parent.mkdir(parents=True, exist_ok=True)
            log.write_text(text, encoding="utf-8")
            entry["console"] = str(log.relative_to(ROOT))
            results.append(entry)
            if fatal:
                failures.append(f"{arch} at {mib} MiB: {fatal}")
                continue
            if missing:
                if RELEASE_TELL in text and len(missing) == len(
                        BOOT_MARKERS[arch]):
                    failures.append(
                        f"{arch} at {mib} MiB reached a login prompt with none "
                        f"of {missing} in the console: that is a release image, "
                        f"where the boot UI owns the console and the kernel log "
                        f"is suppressed -- the machine is fine and this gate "
                        f"can see nothing it came to check")
                else:
                    failures.append(
                        f"{arch} at {mib} MiB never reached {missing}; the "
                        f"address space did not survive this size")
                continue
            # Does the kernel take what the machine has? Firmware keeps some
            # of it -- reserved regions, the device tree, the framebuffer --
            # so the floor is a proportion rather than the exact figure, and
            # the ceiling catches a kernel counting memory that is not there.
            if not (0.85 * mib <= managed_mib <= 1.02 * mib):
                failures.append(
                    f"{arch} at {mib} MiB manages {managed_mib} MiB, which is "
                    f"not the memory it was given; a kernel that caps itself "
                    f"boots perfectly and reports exactly this")
    # Rising, across each architecture. This is what proves the size knob was
    # honoured at all: three identical figures mean the runner used its own
    # default three times and every check above passed on the same machine.
    for arch in ARCHITECTURES:
        managed = [r["managed_mib"] for r in results
                   if r["architecture"] == arch and not r["fatal_markers"]
                   and not r["missing_markers"]]
        if len(managed) == len(SIZES_MIB) and not all(
                b > a for a, b in zip(managed, managed[1:])):
            failures.append(
                f"{arch} reported {managed} MiB across {list(SIZES_MIB)} MiB: "
                f"the figures do not rise, so the requested size never reached "
                f"the emulator and these are three boots of one machine")
    report = {
        "schema": SCHEMA,
        "status": "pass" if not failures else "fail",
        "sizes_mib": list(SIZES_MIB),
        "results": results,
        "failures": failures,
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                      encoding="utf-8")
    if failures:
        for failure in failures:
            print(f"qemu-memory-matrix: FAIL {failure}")
        print(f"qemu-memory-matrix: report={REPORT}")
        return 1
    summary = ", ".join(
        f"{r['architecture']}@{r['requested_mib']}={r['managed_mib']}MiB"
        for r in results)
    print(f"qemu-memory-matrix: aarch64, x86_64 and riscv64 each boot at "
          f"{', '.join(str(s) for s in SIZES_MIB)} MiB and manage the memory "
          f"they are given -- {summary}; report={REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
