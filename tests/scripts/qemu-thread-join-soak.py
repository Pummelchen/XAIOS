#!/usr/bin/env python3
"""B-02: the create/join churn, on QEMU, with the CPU deliberately oversubscribed.

B-02 was recorded twice and explained neither time: a thread join failing under
load, once on QEMU and once during a VMware Fusion profile run. A defect with
exactly that signature has since been fixed -- `user_thread_worker` cleared the
CPU to the kernel unconditionally, so a worker entered from inside a process's
own `xaios_thread_join` left the outer syscall with no current process and the
kernel's address space. Whether that defect produced *those two sightings* is
inference, and the tracker says so.

What was missing is a way to run the path hard enough to argue about. This is
that: `/bin/smpstress` performs a create/join churn with more threads than the
machine has CPUs, so a thread is still pending when join runs, which is the
window the defect needed. `vz-stress-gate` already drives the same application
-- but only on Virtualization.framework, which this project treats as a
development target and not as evidence. Nothing exercised it under QEMU.

Oversubscription is the whole design. A process waiting in join runs pending
threads on its own CPU, and there is only a nested run to get wrong when the
threads outnumber the CPUs able to take them. Given eight stress threads, a
one- or two-CPU guest spends most of the churn in exactly that state; an
eight-CPU guest mostly does not, which is why running this at the comfortable
size would be the same mistake as `vz-gate` sitting at the one memory size
where B-06 could not occur.

Two anti-vacuity floors, because a soak that boots and asserts nothing passes
beautifully. The stress application must report that it ran and that its churn
was deterministic -- a boot where it never started must not count as a clean
one -- and the guest must report the CPU count it was actually given, so a run
that quietly came up with eight CPUs cannot be recorded as an oversubscribed
one.

The forbidden markers are the diagnostics `user_thread_worker` prints on each
of its abandonment paths. Those exist because the original sightings said only
that something went wrong; if this soak ever goes red, the log now names which
condition fired.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
sys.path.insert(0, str(ROOT / "tests" / "scripts"))
from qemu_gate_lib import qemu_boot_environment, qemu_runner, smoke_timeout

REPORT = BUILD / "qemu-thread-join-soak.json"
ARCH = os.environ.get("XAIOS_THREAD_SOAK_ARCH", "aarch64")
RUNS = int(os.environ.get("XAIOS_THREAD_SOAK_RUNS", "6"))
# Fewer CPUs than /bin/smpstress has threads. See the module docstring: this is
# the parameter the gate exists to hold, not a convenience.
CPUS = os.environ.get("XAIOS_THREAD_SOAK_CPUS", "2")
STRESS_THREADS = 8

REQUIRED = (
    ("stress app ran", re.compile(r"/bin/smpstress: sustained multi-core load")),
    ("churn deterministic",
     re.compile(r"/bin/smpstress: create/join churn deterministic")),
    ("counters exact",
     re.compile(r"/bin/smpstress: contended counter and neighbour words exact")),
    ("stress app completed", re.compile(r"/bin/smpstress: complete")),
    ("returned cleanly",
     re.compile(r"kernel: /bin/smpstress returned to kernel exit_code=0")),
)

# Every path in user_thread_worker that gives up, and the two the joiner sees.
FORBIDDEN = (
    # The detector that sits inside thread_join_owned itself, and the one that
    # names B-02 directly: the join compares the current process before and
    # after running a pending thread, and says so if the worker did not put
    # back what it borrowed. Leaving this out of the list was why the first
    # version of this soak stayed green with the fix reverted.
    "threads: join lost its process context",
    "threads: worker abandoned",
    "threads: worker returned without the exit magic",
    "threads: worker exit magic present but exited=0",
    "/bin/smpstress: contended counter lost updates",
    "/bin/smpstress: neighbouring word corrupted",
)

ONLINE = re.compile(r"telemetry: boot_summary cpu_online=(\d+)")


def build_guest() -> None:
    """Build the image this soak boots, with the stress application in it.

    /bin/smpstress is compiled in only when XAIOS_STRESS_TEST=1 -- it is a
    build flag, not a runtime one, so an image built without it boots perfectly
    and simply never runs the churn. The first version of this gate booted
    whatever was in build/ and got exactly that: a clean boot to a login prompt
    with no stress application in it, which the required-marker floor caught.
    Building here is the same rule B-31 exists for: a gate boots what it built.
    """
    environment = os.environ.copy()
    environment.update({"XAIOS_BOOT_TEST_APPS": "1", "XAIOS_STRESS_TEST": "1"})
    print("qemu-thread-join-soak: building the stress image", flush=True)
    subprocess.run(["./scripts/build-image.sh"], check=True, cwd=ROOT,
                   env=environment, stdout=subprocess.DEVNULL)


# Reading stops at whichever of these arrives first. The guest never exits on
# its own, so without this every boot costs the whole timeout.
DONE = re.compile(r"kernel: /bin/smpstress returned to kernel exit_code=\d+"
                  r"|xaios login:")


def boot(index: int) -> dict[str, object]:
    env = qemu_boot_environment(ARCH, os.environ.copy(), smp=CPUS,
                                hostfwd_port="none", serial_to_stdout=True)
    started = time.monotonic()
    process = subprocess.Popen(
        [qemu_runner(ARCH)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1, env=env, cwd=ROOT, start_new_session=True)
    import select
    chunks: list[str] = []
    deadline = time.time() + smoke_timeout(ARCH, 420)
    try:
        descriptor = process.stdout.fileno()
        while time.time() < deadline:
            ready, _, _ = select.select([descriptor], [], [], 0.5)
            if ready:
                data = os.read(descriptor, 65536).decode("utf-8",
                                                         errors="replace")
                if not data:
                    break
                chunks.append(data)
                if DONE.search("".join(chunks)):
                    break
            elif process.poll() is not None:
                break
        text = "".join(chunks)
    finally:
        if process.poll() is None:
            try:
                os.killpg(process.pid, 9)
            except ProcessLookupError:
                pass
    log = BUILD / f"qemu-thread-join-soak-{index}.log"
    log.write_text(text, encoding="utf-8")
    online = ONLINE.search(text)
    return {
        "run": index,
        "seconds": round(time.monotonic() - started, 1),
        "cpu_online": int(online.group(1)) if online else None,
        "missing": [name for name, pattern in REQUIRED
                    if not pattern.search(text)],
        "forbidden": [marker for marker in FORBIDDEN if marker in text],
        "log": str(log.relative_to(ROOT)),
    }


def main() -> int:
    BUILD.mkdir(parents=True, exist_ok=True)
    build_guest()
    failures: list[str] = []
    runs: list[dict[str, object]] = []
    requested = int(CPUS)

    for index in range(1, RUNS + 1):
        print(f"qemu-thread-join-soak: boot {index}/{RUNS} on {requested} CPUs "
              f"against {STRESS_THREADS} stress threads", flush=True)
        entry = boot(index)
        runs.append(entry)
        if entry["missing"]:
            failures.append(
                f"boot {index} did not report {entry['missing']}: the churn "
                f"this soak exists to exercise cannot be assumed to have run")
        if entry["forbidden"]:
            failures.append(
                f"boot {index} printed {entry['forbidden']} -- this is the "
                f"B-02 path failing, and the marker names which condition")
        if entry["cpu_online"] is None:
            failures.append(
                f"boot {index} never reported its CPU count, so it cannot be "
                f"recorded as an oversubscribed run")
        elif entry["cpu_online"] != requested:
            failures.append(
                f"boot {index} came up with {entry['cpu_online']} CPUs, not "
                f"the {requested} asked for. Oversubscription is what puts a "
                f"thread pending while join runs; at the comfortable size this "
                f"soak proves nothing")

    clean = sum(1 for r in runs if not r["missing"] and not r["forbidden"])
    report = {"schema": "xaios.qemu.thread_join_soak.v1",
              "status": "pass" if not failures else "fail",
              "architecture": ARCH,
              "requested_cpus": requested,
              "stress_threads": STRESS_THREADS,
              "runs": runs,
              "clean_runs": clean,
              "failures": failures}
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                      encoding="utf-8")
    if failures:
        for failure in failures:
            print(f"qemu-thread-join-soak: FAIL {failure}")
        print(f"qemu-thread-join-soak: report={REPORT}")
        return 1
    print(f"qemu-thread-join-soak: {clean}/{RUNS} boots ran the create/join "
          f"churn to completion on {requested} CPUs against {STRESS_THREADS} "
          f"threads, with none of the abandonment diagnostics and no lost "
          f"update; report={REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
