#!/usr/bin/env python3
"""Fusion under sustained storage and network load, rather than repeated boots.

F-04's remaining item: "long-duration storage and network load, which is a
different shape of run from repeat boot." `vmware-fusion-boot-soak` boots the
guest forty times and shuts it down cleanly each time; every one of those is a
fresh machine, so nothing it does can accumulate. The failures this is for are
the ones that need a machine to stay up: a handle that is not returned, a
buffer that grows, a filesystem that fragments, a socket table that fills.

So this boots once and keeps the machine working.

What it asserts, and why each is separate:

  * The guest answers every round. A machine that stops answering half way
    through is the plainest failure and needs no interpretation.
  * Every file put comes back byte-identical. Storage under load is worth
    nothing if the bytes change, and a round trip is the only way to know.
  * Free memory does not trend downwards across the run. This is the whole
    reason for a long run rather than a long list of short ones: a leak of a
    page per operation is invisible in a boot and obvious in a thousand
    operations. It is a trend test, not a threshold -- the figure moves around
    as caches fill, so a single low reading proves nothing and a steady
    decline over the whole run proves a great deal.
  * The console carries no fault marker at the end, including rescue mode,
    which a guest can enter while still answering SSH.

What it deliberately does not claim: any of this as a throughput or latency
figure. The bytes moved and the seconds taken are printed because a run that
reports nothing is hard to judge, but this is one laptop running one
hypervisor, and docs/BENCHMARK-CONTRACT.md is where performance claims live.
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location(
    "vmware_fusion_smoke", Path(__file__).with_name("vmware-fusion-smoke.py"))
smoke = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(smoke)

BUILD = ROOT / "build"
REPORT = BUILD / "vmware-fusion" / "fusion-load-soak.json"
WORK = BUILD / "vmware-fusion" / "load-soak"

# Ten minutes by default: long enough for a per-operation leak to show as a
# trend, short enough to sit inside a gate run. XAIOS_FUSION_LOAD_SECONDS
# raises it for a real soak.
DURATION_S = int(os.environ.get("XAIOS_FUSION_LOAD_SECONDS", "600"))
# 256 KiB per round: bigger than the filesystem's staging buffer, so each
# transfer crosses more than one block and exercises the multi-sector path
# rather than the fast case.
PAYLOAD_BYTES = int(os.environ.get("XAIOS_FUSION_LOAD_PAYLOAD", str(256 * 1024)))


def free_pages(console: str) -> int | None:
    """The guest's own account of free memory, from its last telemetry line."""
    marker = "pmm_free="
    last = None
    for line in console.splitlines():
        index = line.find(marker)
        if index < 0:
            continue
        digits = ""
        for character in line[index + len(marker):]:
            if not character.isdigit():
                break
            digits += character
        if digits:
            last = int(digits)
    return last


def round_trip(address: str, index: int, payload: bytes) -> dict[str, object]:
    """One file out and back, verified byte for byte."""
    WORK.mkdir(parents=True, exist_ok=True)
    source = WORK / f"upload-{index % 4}.bin"
    returned = WORK / f"download-{index % 4}.bin"
    source.write_bytes(payload)
    returned.unlink(missing_ok=True)
    remote = f"/state/load-soak-{index % 4}.bin"
    batch = f"put {source} {remote}\nget {remote} {returned}\nrm {remote}\n"
    started = time.monotonic()
    result = subprocess.run(
        ["sftp", "-F", "/dev/null", "-i", str(smoke.TEST_KEY),
         "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
         "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
         "-o", "LogLevel=ERROR", "-b", "-", f"admin@{address}"],
        input=batch, cwd=ROOT, text=True, capture_output=True, timeout=180,
        check=False)
    identical = (returned.is_file() and returned.read_bytes() == payload)
    return {"round": index,
            "exit_code": result.returncode,
            "identical": identical,
            "seconds": round(time.monotonic() - started, 2),
            "stderr": result.stderr.strip()[:200]}


def main() -> int:
    if sys.platform != "darwin":
        print("vmware-fusion-load-soak: needs macOS with VMware Fusion")
        return 0
    if not smoke.VMRUN.is_file():
        print(f"vmware-fusion-load-soak: no vmrun at {smoke.VMRUN}; skipping")
        return 0

    smoke.build_guest()
    smoke.stop_hard()
    address, _ = smoke.start_vm(0)

    payload = bytes((index * 31 + 7) & 0xFF for index in range(PAYLOAD_BYTES))
    rounds: list[dict[str, object]] = []
    free_samples: list[int] = []
    failures: list[str] = []
    deadline = time.monotonic() + DURATION_S
    index = 0
    try:
        while time.monotonic() < deadline:
            index += 1
            entry = round_trip(address, index, payload)
            rounds.append(entry)
            if entry["exit_code"] != 0:
                failures.append(
                    f"round {index}: sftp exited {entry['exit_code']} "
                    f"({entry['stderr']!r})")
            elif not entry["identical"]:
                failures.append(
                    f"round {index}: the file came back different from the "
                    f"one sent")
            # The guest's own view, asked over the network it is being loaded
            # through -- a machine that cannot describe itself under load is a
            # different failure from one that stops answering.
            status = smoke.ssh(address, "recovery status")
            if "rescue=" not in status:
                failures.append(
                    f"round {index}: the guest stopped answering commands: "
                    f"{status.strip()[:120]!r}")
                break
            if "rescue=1" in status:
                failures.append(
                    f"round {index}: the guest entered rescue mode under load")
                break
            sample = free_pages(smoke.serial_text())
            if sample is not None:
                free_samples.append(sample)
    finally:
        console = smoke.serial_text()
        kept = BUILD / "vmware-fusion" / "fusion-load-soak.log"
        kept.write_text(console, encoding="utf-8")
        smoke.stop_hard()

    fatal = [marker for marker in smoke.FATAL_MARKERS if marker in console]
    if fatal:
        failures.append(f"the console carries fault markers {fatal}")

    # A trend, not a threshold. Compare the first quarter of the samples with
    # the last: caches fill early and the figure wanders, so one low reading
    # says nothing, while a steady decline across a ten-minute run is a leak.
    trend: dict[str, object] = {"samples": len(free_samples)}
    if len(free_samples) >= 8:
        quarter = len(free_samples) // 4
        early = sum(free_samples[:quarter]) / quarter
        late = sum(free_samples[-quarter:]) / quarter
        trend.update({"early_mean_pages": round(early),
                      "late_mean_pages": round(late),
                      "delta_pages": round(late - early)})
        # 2% of the early mean: enough to ignore ordinary movement, small
        # enough to catch a page-per-operation leak over hundreds of rounds.
        if late < early * 0.98:
            failures.append(
                f"free memory declined across the run: {round(early)} pages "
                f"early against {round(late)} late. Over {index} rounds that "
                f"is a leak rather than a cache filling")

    report = {
        "schema": "xaios.vmware-fusion.load_soak.v1",
        "status": "pass" if not failures else "fail",
        "fusion_version": smoke.fusion_version(),
        "revision": smoke.git_revision(),
        "duration_requested_s": DURATION_S,
        "payload_bytes": PAYLOAD_BYTES,
        "rounds": len(rounds),
        "bytes_moved": len(rounds) * PAYLOAD_BYTES * 2,
        "free_page_trend": trend,
        "failures": failures,
        "not_claimed": [
            "throughput or latency: one laptop, one hypervisor, and "
            "docs/BENCHMARK-CONTRACT.md is where performance claims live",
        ],
        "round_detail": rounds[-20:],
    }
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                      encoding="utf-8")
    if failures:
        for failure in failures:
            print(f"vmware-fusion-load-soak: FAIL {failure}")
        print(f"vmware-fusion-load-soak: report={REPORT}")
        return 1
    print(f"vmware-fusion-load-soak: {len(rounds)} verified round trips of "
          f"{PAYLOAD_BYTES} bytes over {DURATION_S}s on one boot, every file "
          f"identical, the guest answering throughout, free memory "
          f"{trend.get('delta_pages', 'n/a')} pages against its early mean; "
          f"report={REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
