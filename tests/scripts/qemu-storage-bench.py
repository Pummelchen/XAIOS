#!/usr/bin/env python3
"""Boot a machine, make it measure its own storage, and record what it said.

Not a pass/fail gate on the numbers. These are QEMU/TCG figures on whatever
host happens to run them; pinning a throughput would make this a gate on the
host's mood, and a gate that fails for reasons unrelated to the change gets
disabled within a month.

What it does assert is that the measurement happened and was coherent: every
line present, no verification mismatch, and -- the one that has teeth -- that
a warm read is faster than a cold one. That is the claim the read cache
exists to make, and it is the one that would silently stop being true if the
cache were bypassed, disabled, or invalidated on every access.
"""

from __future__ import annotations

import json
import os
import re
import signal
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
REPORT = BUILD / f"qemu-storage-bench{SUFFIX}.json"
LOG = BUILD / f"qemu-storage-bench{SUFFIX}.log"
CACHE_FIXTURE = BUILD / "xaios-cache-fixture.img"
SCRATCH = BUILD / f"storage-bench-scratch{SUFFIX}.img"
SCRATCH_BYTES = 1024 * 1024 * 1024
TIMEOUT_S = smoke_timeout(
    ARCH, int(os.environ.get("XAIOS_STORAGE_BENCH_TIMEOUT", "900")))

RATE = re.compile(
    rb"storage-bench: (\S+) (?:device|bytes)=\S* ?bytes=(\d+) ms=(\d+) "
    rb"kb_per_s=(\d+)")
BLOCK = re.compile(
    rb"storage-bench: (write|read) device=(\S+) bytes=(\d+) ms=(\d+) "
    rb"kb_per_s=(\d+) requests=(\d+) bytes_per_request=(\d+)")
MODEL = re.compile(
    rb"storage-bench: model-(\S+) bytes=(\d+) ms=(\d+) kb_per_s=(\d+) "
    rb"requests=(\d+) window=(\d+)")
CACHE = re.compile(
    rb"model-cache: (\S+) hits=(\d+) misses=(\d+) rate=(\d+\.\d+)% "
    rb"resident=(\d+)MB peak=(\d+)MB budget=(\d+)MB admitted=(\d+) "
    rb"evicted=(\d+) refused=(\d+)")
RESIDENCY = re.compile(
    rb"residency: system resident=(\d+)KB reservations=(\d+) budget=(\d+)MB")
MISMATCH = re.compile(rb"storage-bench: verify mismatches=(\d+)")
# The last thing the measurement says. Everything this gate reads is above it.
DONE = re.compile(rb"model-cache: window ")
TRANSFERS = re.compile(rb"virtio-blk: transfers direct=(\d+) bounced=(\d+)")


def fail(message: str) -> int:
    print(f"storage-bench: {message}")
    return 1


def main() -> int:
    if not CACHE_FIXTURE.is_file():
        return fail(f"no cache fixture at {CACHE_FIXTURE}; run "
                    f"tests/xai_fs/create_cache_fixture.py first")
    # A scratch disk for the block half. Recreated every run: a file the host
    # has already allocated behaves differently from a sparse one, and that
    # difference is larger than most of what this measures.
    SCRATCH.unlink(missing_ok=True)
    with SCRATCH.open("wb") as sink:
        sink.truncate(SCRATCH_BYTES)

    environment = dict(os.environ)
    environment["XAIOS_XAI_FS_IMAGE"] = str(CACHE_FIXTURE)
    # No host port forwarding. This gate does not use SSH, and claiming a
    # fixed host port means one stale emulator anywhere on the machine turns
    # the run into a boot that never happened.
    #
    # serial_to_stdout because the console is being redirected into LOG here;
    # RISC-V's runner would otherwise write it to a file of its own and this
    # would read an empty log.
    environment = qemu_boot_environment(
        ARCH, environment, hostfwd_port="none", storage_admin=SCRATCH,
        serial_to_stdout=True)
    LOG.unlink(missing_ok=True)
    with LOG.open("wb") as sink:
        process = subprocess.Popen(
            [qemu_runner(ARCH)],
            cwd=ROOT, env=environment, stdout=sink,
            stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            start_new_session=True)
    # A machine that reaches a login prompt keeps running, and everything this
    # gate wants has been said by then. Waiting for the timeout instead cost a
    # quarter of an hour per run for a measurement that finished in two
    # minutes, which is how a gate ends up disabled.
    deadline = time.monotonic() + TIMEOUT_S
    try:
        while process.poll() is None and time.monotonic() < deadline:
            if DONE.search(LOG.read_bytes()):
                break
            time.sleep(0.2)
    finally:
        if process.poll() is None:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            process.wait(timeout=30)

    text = LOG.read_bytes()
    block = {}
    for match in BLOCK.finditer(text):
        block[match.group(1).decode()] = {
            "device": match.group(2).decode(),
            "bytes": int(match.group(3)),
            "milliseconds": int(match.group(4)),
            "kb_per_s": int(match.group(5)),
            "requests": int(match.group(6)),
            "bytes_per_request": int(match.group(7)),
        }
    model = {}
    for match in MODEL.finditer(text):
        model[match.group(1).decode()] = {
            "bytes": int(match.group(2)),
            "milliseconds": int(match.group(3)),
            "kb_per_s": int(match.group(4)),
            "requests": int(match.group(5)),
            "window": int(match.group(6)),
        }
    cache = {}
    for match in CACHE.finditer(text):
        cache[match.group(1).decode()] = {
            "hits": int(match.group(2)),
            "misses": int(match.group(3)),
            "hit_rate": float(match.group(4)),
            "resident_mb": int(match.group(5)),
            "peak_mb": int(match.group(6)),
            "budget_mb": int(match.group(7)),
            "admitted": int(match.group(8)),
            "evicted": int(match.group(9)),
            "refused": int(match.group(10)),
        }

    failures = []
    for phase in ("read", "write"):
        if phase not in block:
            failures.append(f"the block {phase} measurement did not happen")
    for phase in ("aligned-cold", "aligned-warm", "window-cold", "window-warm"):
        if phase not in model:
            failures.append(f"the model {phase} measurement did not happen")

    mismatch = MISMATCH.search(text)
    if mismatch is None:
        failures.append("the block benchmark never verified what it wrote")
    elif int(mismatch.group(1)) != 0:
        failures.append(
            f"the block benchmark read back {mismatch.group(1).decode()} wrong "
            f"bytes, so its rate is a rate for the wrong path")

    # The claim with teeth. A cache that has been bypassed, disabled, or
    # invalidated on every access still produces every line above; only this
    # comparison notices.
    for kind in ("aligned", "window"):
        cold = model.get(f"{kind}-cold")
        warm = model.get(f"{kind}-warm")
        if cold is None or warm is None:
            continue
        if warm["kb_per_s"] <= cold["kb_per_s"]:
            failures.append(
                f"a warm {kind} read ({warm['kb_per_s']} kB/s) was no faster "
                f"than a cold one ({cold['kb_per_s']} kB/s); the read cache is "
                f"not doing anything")
        counters = cache.get(kind)
        if counters is not None and counters["hits"] == 0:
            failures.append(f"the {kind} pass never hit the cache")

    residency = RESIDENCY.search(text)
    transfers = TRANSFERS.search(text)
    report = {
        "schema": "xaios.storage-bench.v1",
        "arch": ARCH,
        "block": block,
        "model": model,
        "cache": cache,
        "residency": None if residency is None else {
            "resident_kb": int(residency.group(1)),
            "reservations": int(residency.group(2)),
            "budget_mb": int(residency.group(3)),
        },
        "transfers": None if transfers is None else {
            "direct": int(transfers.group(1)),
            "bounced": int(transfers.group(2)),
        },
        "failures": failures,
        "passed": not failures,
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    SCRATCH.unlink(missing_ok=True)

    for phase, figures in block.items():
        print(f"storage-bench: block {phase:<5} {figures['kb_per_s']:>10} kB/s "
              f"({figures['requests']} requests of "
              f"{figures['bytes_per_request']} B)")
    for phase in ("aligned-cold", "aligned-fill", "aligned-warm",
                  "window-cold", "window-fill", "window-warm"):
        figures = model.get(phase)
        if figures is not None:
            print(f"storage-bench: model {phase:<12} "
                  f"{figures['kb_per_s']:>10} kB/s "
                  f"(window {figures['window']} B)")
    for kind, counters in cache.items():
        print(f"storage-bench: cache {kind:<7} hit_rate={counters['hit_rate']}% "
              f"resident={counters['resident_mb']}MB "
              f"admitted={counters['admitted']} "
              f"evicted={counters['evicted']} refused={counters['refused']}")

    if failures:
        for message in failures:
            print(f"storage-bench: FAIL {message}")
        return 1
    print(f"storage-bench: passed report={REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
