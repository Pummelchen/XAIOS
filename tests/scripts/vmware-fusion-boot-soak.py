#!/usr/bin/env python3
"""Boot the Fusion guest repeatedly and keep every console.

B-15 is a fatal assertion seen once on VMware Fusion ARM64 and never since.
Two things have to be true before a bug like that can be closed or dismissed,
and neither was:

  * enough boots to say something about how rare it is. `vmware-fusion-smoke`
    builds the image, boots, runs SSH and SFTP closure, reboots and shuts
    down. Most of that is not where the assertion fired, and the build
    dominates the wall clock, so running the whole gate in a loop buys very
    few boots per hour. This builds once and then boots only.

  * every console kept. The smoke gate deletes the serial log at the start of
    each boot, which is correct for one run and useless for a soak: the boot
    that fails is the one whose console is about to be overwritten by the
    next iteration. That is how the single recorded occurrence of B-15 lost
    everything except fifteen stack addresses. Here each boot's console is
    copied out before the next one starts.

Not a gate. Nothing in CI runs this; it is a reproduction harness, and it
exits non-zero only when it actually reproduces something.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
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

SOAK = smoke.FUSION_BUILD / "boot-soak"


def stop_if_running() -> None:
    if smoke.vm_running():
        smoke.vmrun(["stop", str(smoke.VMX), "hard"], check=False)
        try:
            smoke.wait_for_stopped()
        except Exception:
            pass


def one_boot(index: int) -> dict[str, object]:
    """Boot once from a clean console, then shut down cleanly.

    The shutdown has to be orderly, and that is not a detail. A hard stop
    leaves the lifecycle record saying "running", which the next boot counts
    as an unclean boot, and `operations_init` puts the guest into rescue mode
    at three consecutive ones. A soak that hard-stops therefore poisons itself
    on its third iteration and every boot after that is a guest refusing
    commands rather than a sample. The first version of this script did
    exactly that: 12 of its first 13 boots "failed", none of them for any
    reason to do with the machine.
    """
    stop_if_running()
    smoke.SERIAL.unlink(missing_ok=True)
    started = time.monotonic()
    outcome: dict[str, object] = {"iteration": index}
    try:
        smoke.vmrun(["start", str(smoke.VMX), "nogui"])
        address, _ = smoke.wait_for_boot(0)
        outcome["result"] = "booted"
        outcome["address"] = address
        # The command is sent, not required to return zero.
        #
        # A shutdown that works closes the connection under the client, so
        # ssh exits non-zero on the very command that succeeded. The smoke
        # helper treats that as a failure and retries for a minute against a
        # machine that has already gone, and the soak recorded every boot as
        # failed with "Fusion SSH command failed: shutdown" -- while the
        # guest had shut down perfectly each time. Worse, the retry loop left
        # the machine to be hard-stopped, which counted as an unclean boot,
        # so rescue mode latched on the fourth iteration and every later boot
        # was a guest refusing commands rather than a sample.
        #
        # What says the shutdown worked is the machine stopping.
        deadline = time.monotonic() + 90.0
        while time.monotonic() < deadline:
            subprocess.run(smoke.ssh_base(address) + ["shutdown"], cwd=ROOT,
                           text=True, capture_output=True, timeout=30,
                           check=False)
            if not smoke.vm_running():
                break
            time.sleep(1.0)
        smoke.wait_for_stopped()
        outcome["shutdown"] = "clean"
    except Exception as error:  # noqa: BLE001 - every failure is a result here
        outcome["result"] = "failed"
        # First line only. The smoke helpers append an eighty-line console
        # tail to their exceptions, which is right for a one-shot gate and
        # wrong here -- the whole console is kept beside this record, so
        # embedding a slice of it just makes the report unreadable.
        outcome["error"] = f"{type(error).__name__}: {str(error).splitlines()[0]}"
    outcome["seconds"] = round(time.monotonic() - started, 1)

    # The console is copied before the next boot truncates it, which is the
    # whole reason this script exists.
    console = smoke.serial_text()
    kept = SOAK / f"boot-{index:04d}.log"
    kept.write_text(console, encoding="utf-8")
    outcome["console"] = str(kept.relative_to(ROOT))
    outcome["console_lines"] = len(console.splitlines())
    outcome["fatal_markers"] = [m for m in smoke.FATAL_MARKERS if m in console]
    if smoke.vm_running():
        # Only reached when the clean shutdown above did not happen, which is
        # itself worth recording: the next boot will count as unclean.
        outcome["shutdown"] = "hard"
        stop_if_running()
    return outcome


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--boots", type=int, default=25,
                        help="how many boots to attempt (default 25)")
    parser.add_argument("--keep-going", action="store_true",
                        help="carry on after a failure instead of stopping "
                             "at the first one")
    parser.add_argument("--skip-build", action="store_true",
                        help="use the VM bundle already in build/")
    arguments = parser.parse_args()

    if not arguments.skip_build:
        # The whole guest, the way the smoke gate builds it.
        #
        # This ran only the Fusion packaging step, which repackages whatever
        # image happens to be in build/ -- so the VM booted with somebody
        # else's authorized key and every SSH command was refused. The
        # shutdown then never reached the guest, each boot was hard-stopped,
        # and rescue mode latched on the fourth: twenty consecutive failures
        # that were entirely the harness's doing. build_guest mints the key
        # and builds the image around it.
        try:
            smoke.build_guest()
        except Exception as error:  # noqa: BLE001 - report and stop
            print(f"build failed, so no boot was attempted: {error}",
                  file=sys.stderr)
            return 2
    if not smoke.VMX.is_file():
        print(f"no VM bundle at {smoke.VMX}; run without --skip-build",
              file=sys.stderr)
        return 2

    if SOAK.exists():
        shutil.rmtree(SOAK)
    SOAK.mkdir(parents=True)

    results: list[dict[str, object]] = []
    failures = 0
    for index in range(1, arguments.boots + 1):
        outcome = one_boot(index)
        results.append(outcome)
        if outcome["result"] == "booted":
            print(f"fusion-boot-soak: boot {index}/{arguments.boots} ok "
                  f"in {outcome['seconds']}s", flush=True)
        else:
            failures += 1
            print(f"fusion-boot-soak: boot {index}/{arguments.boots} FAILED "
                  f"after {outcome['seconds']}s: {outcome['error']}\n"
                  f"  console kept at {outcome['console']} "
                  f"({outcome['console_lines']} lines)"
                  + (f"\n  fatal markers: {outcome['fatal_markers']}"
                     if outcome["fatal_markers"] else ""),
                  file=sys.stderr, flush=True)
            if not arguments.keep_going:
                break

    report = {
        "boots_attempted": len(results),
        "boots_requested": arguments.boots,
        "booted": sum(1 for r in results if r["result"] == "booted"),
        "failed": failures,
        "results": results,
    }
    (SOAK / "report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"fusion-boot-soak: {report['booted']} booted, {failures} failed, "
          f"consoles under {SOAK.relative_to(ROOT)}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
