#!/usr/bin/env python3
"""B-02: a join that runs a thread inside itself, and the CPU it borrowed.

`thread_join_owned` runs pending work on the joining CPU while it waits. When
the joiner is a *user* process and the pending thread is targeted at that same
CPU, the worker is entered from inside the process's own syscall: the CPU
already has a current process bound and that process's address space active.
A worker that clears the CPU to the kernel on the way out leaves the outer
syscall with neither, and nothing in the join notices -- every later
capability check on it is refused and every user pointer resolves in the wrong
space.

`/bin/joinnest` reaches that window deliberately (a helper thread pinned to a
worker CPU, a victim pinned to the same CPU behind it, and the helper joining
the victim). This gate boots it and reads three separate kinds of evidence:

  * the workload's own report, which says at each step what it did and what
    it found afterwards;
  * the kernel's thread log, which has to show the victim dispatched and
    completed *between* the helper's dispatch and the helper's completion, on
    the same CPU and with a non-zero owner -- that interleaving is what
    "nested inside a user process's join" looks like from the kernel side, and
    it cannot be produced by two threads running side by side;
  * the kernel's own B-02 detector, `threads: join lost its process context`,
    and the unbound-syscall refusal `... refused for cpu=N pid=0`, either of
    which appearing is the defect happening.

Two floors keep a green run from being a vacuous one. The workload has to
report that it actually ran the nested join -- not that it started, and not
that it decided there was nothing to do -- and it has to report the CPU count
the guest was given, which must match the count this gate asked for. A boot
with one CPU cannot reach the window at all, and without that check it would
read as a boot that reached it and found nothing.
"""
import json
import os
import re
import select
import signal
import subprocess
import sys
import time
from pathlib import Path

from qemu_gate_lib import (BUILD, ROOT, arch_from_argv, qemu_boot_environment,
                           qemu_runner, now, result, status_from_failures,
                           write_report)


SCHEMA = "xaios.qemu.thread_join_nested_context.v1"
DEFAULT_SMP = 4
DEFAULT_REPEAT = 3

# The workload said it did the thing, in the order it had to do it in. Every
# one of these is printed on a path that has already done the work it names,
# and every one is printed by whichever CPU is the only one logging at that
# moment -- the boot has been seen to drop a console line when two CPUs write
# at once, and a required marker inside that window would make this gate red
# for console timing rather than for B-02.
APP_MARKERS = [
    "/bin/joinnest: nested thread join starting",
    "/bin/joinnest: victim thread running nested",
    "/bin/joinnest: victim ran inside the join",
    "/bin/joinnest: process context intact after nested join",
    "/bin/joinnest: nested join summary ",
    "/bin/joinnest: nested join kept its process context",
    "/bin/joinnest: complete",
    "kernel: /bin/joinnest returned to kernel exit_code=0",
]

# Any of these is B-02 happening, or the boot dying of it.
FAILURE_MARKERS = [
    "threads: join lost its process context",
    "/bin/joinnest: process context lost across nested join",
    "/bin/joinnest: victim ran before the join; not nested",
    "/bin/joinnest: single cpu, nested join window unreachable",
    "CYAN SCREEN OF DEATH",
    "System halted. Manual reset required",
]

# A syscall refused because the CPU making it has no process bound. This is
# the shape the defect wears when it is not the detector that catches it: the
# capability is present, the binding is not, and the kernel says pid=0.
UNBOUND_REFUSAL = re.compile(r"user: \w+ refused for cpu=\d+ pid=0 ")

APP_START = "/bin/joinnest: nested thread join starting"
APP_END = "kernel: /bin/joinnest returned to kernel"
APP_SUMMARY = re.compile(
    r"/bin/joinnest: nested join summary cpus=(\d+) pinned_cpu=(\d+) "
    r"helper_thread=(\d+) victim_thread=(\d+) ran_nested=(\d+)")
APP_EXIT_WARNING = re.compile(r"WARNING /bin/joinnest exited with status=(-?\d+)")
THREAD_CREATE = re.compile(
    r"threads: user create id=(\d+) owner=(\d+) target_cpu=(\d+)")
THREAD_DISPATCH = re.compile(
    r"threads: user dispatch id=(\d+) owner=(\d+) cpu=(\d+)")
THREAD_COMPLETE = re.compile(
    r"threads: user complete id=(\d+) owner=(\d+) cpu=(\d+) result=(\d+)")


# What each runner boots by default, so this gate can refuse a stale one.
BOOT_MEDIUM = {
    "aarch64": "build/xaios-aarch64.img",
    "x86_64": "build/xaios-x86_64.img",
    "riscv64": "build/xaios-riscv64.img",
}

# What the medium has to be newer than. A boot of last week's image would pass
# every check here and say nothing about the source in the tree -- which is
# how a green run comes to mean nothing.
SOURCES = [
    "userspace/apps/joinnest.c",
    "kernel/sched/thread.c",
    "kernel/core/kmain.c",
]


def stale_medium(arch: str) -> list[str]:
    medium = ROOT / BOOT_MEDIUM[arch]
    if not medium.exists():
        return [f"{BOOT_MEDIUM[arch]} does not exist; build the test-apps "
                f"image for {arch} first"]
    built = medium.stat().st_mtime
    return [f"{source} is newer than {BOOT_MEDIUM[arch]}; the boot would not "
            "contain it"
            for source in SOURCES
            if (ROOT / source).stat().st_mtime > built]


def line_complete(output: str, marker: str) -> bool:
    """Has this marker arrived, and has the line carrying it ended?"""
    index = output.find(marker)
    return index >= 0 and output.find("\n", index) >= 0


def stop_process_group(proc: "subprocess.Popen[str]") -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        proc.wait(timeout=5)


def int_argument(argv, name: str, default: int) -> int:
    for index, argument in enumerate(argv):
        if argument == name and index + 1 < len(argv):
            return int(argv[index + 1])
        if argument.startswith(f"{name}="):
            return int(argument.split("=", 1)[1])
    return default


def boot(arch: str, smp: int, timeout: int, log_path: Path) -> str:
    """One boot, stopped as soon as the workload has said all it is going to."""
    persistent = BUILD / f"xaios-thread-join-soak-{arch}.img"
    persistent.unlink(missing_ok=True)
    state_dir = BUILD / f"thread-join-soak-{arch}-state"
    env = qemu_boot_environment(arch, os.environ.copy(), smp=smp,
                                hostfwd_port="none", persistent=persistent,
                                state_dir=state_dir, serial_to_stdout=True)
    # The runner, not `make <machine>`.
    #
    # On x86_64 that make target depends on `image-x86_64`, which is the
    # ordinary image and not the one with the diagnostic applications in it.
    # A gate that went through make rebuilt the image it had just been given
    # and then booted a machine that never runs /bin/joinnest at all -- every
    # marker missing, for a reason that has nothing to do with threads. The
    # image is the caller's job (see the make target beside this gate); this
    # boots what is there.
    proc = subprocess.Popen(
        [qemu_runner(arch)],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env=env,
        start_new_session=True,
    )
    chunks = []
    deadline = time.time() + timeout
    try:
        assert proc.stdout is not None
        fd = proc.stdout.fileno()
        while time.time() < deadline:
            ready, _, _ = select.select([fd], [], [], 0.2)
            if ready:
                chunk = os.read(fd, 4096).decode("utf-8", errors="replace")
                if not chunk:
                    break
                sys.stdout.write(chunk)
                sys.stdout.flush()
                chunks.append(chunk)
                output = "".join(chunks)
                # Stop on the kernel's line rather than the app's, so a boot
                # that failed on the way out is still read in full -- and only
                # once that line is complete. Stopping at the substring cut
                # the console mid-word and lost the exit code on the end of
                # it, which this gate then reported as a missing marker: a
                # red run caused entirely by where the reader stopped.
                if line_complete(output, APP_END):
                    break
                if any(line_complete(output, marker)
                       for marker in FAILURE_MARKERS):
                    break
            elif proc.poll() is not None:
                break
    finally:
        stop_process_group(proc)
        persistent.unlink(missing_ok=True)
    output = "".join(chunks)
    log_path.write_text(output, encoding="utf-8")
    return output


def app_slice(output: str) -> str:
    """The part of the boot the workload was running, and nothing else.

    The thread log is shared with everything else that creates a thread on
    this boot -- smptest is three applications earlier and does the same
    calls. Attributing an interleaving to this workload means cutting the log
    at its own boundaries first.
    """
    start = output.find(APP_START)
    if start < 0:
        return ""
    end = output.find(APP_END, start)
    return output[start:end if end >= 0 else len(output)]


def check_nesting(section: str, helper_id: int, victim_id: int,
                  pinned_cpu: int) -> tuple[list[str], dict]:
    """The kernel's account of the same thing, where the console kept it.

    From the kernel's side, nesting is an ordering: the victim is dispatched
    and completed strictly between the helper's dispatch and the helper's
    completion, on the same CPU, both owned by a live process. Two threads
    running side by side cannot produce that, and neither can a join that
    returned because somebody else had already run the thread.

    Corroboration rather than requirement, and deliberately so. These lines
    are written by the worker CPU while the caller's CPU is writing its own,
    and this boot drops a console line when that happens -- a run has already
    been seen without the helper's create line, with the thread plainly
    created. Failing on a missing line would make the gate an assertion about
    serial timing. Failing on a *wrong* order would not, so that still fails:
    what is here has to agree.
    """
    failures: list[str] = []
    evidence: dict = {"kernel_thread_log": "complete"}

    def position(pattern: "re.Pattern[str]", thread_id: int, what: str) -> int:
        for match in pattern.finditer(section):
            if int(match.group(1)) == thread_id:
                if int(match.group(2)) == 0:
                    failures.append(
                        f"{what} for thread {thread_id} had no owning "
                        "process")
                if int(match.group(3)) != pinned_cpu:
                    failures.append(
                        f"{what} for thread {thread_id} ran on cpu "
                        f"{match.group(3)}, expected {pinned_cpu}")
                return match.start()
        return -1

    order = {
        "helper_dispatch": position(THREAD_DISPATCH, helper_id, "dispatch"),
        "victim_dispatch": position(THREAD_DISPATCH, victim_id, "dispatch"),
        "victim_complete": position(THREAD_COMPLETE, victim_id, "completion"),
        "helper_complete": position(THREAD_COMPLETE, helper_id, "completion"),
    }
    for create in THREAD_CREATE.finditer(section):
        if int(create.group(1)) in (helper_id, victim_id):
            if int(create.group(3)) != pinned_cpu:
                failures.append(
                    f"thread {create.group(1)} was created for cpu "
                    f"{create.group(3)}, expected {pinned_cpu}")
    evidence["order"] = order
    missing = [name for name, index in order.items() if index < 0]
    if missing:
        # Said out loud in the report rather than passed over: a run whose
        # kernel-side account was eaten by the console is a weaker run, even
        # though the workload's own account still stands on its own.
        evidence["kernel_thread_log"] = f"incomplete, missing {missing}"
        return failures, evidence
    if not (order["helper_dispatch"] < order["victim_dispatch"] <
            order["victim_complete"] < order["helper_complete"]):
        failures.append(
            f"the victim did not run inside the helper's join: {order}")
    return failures, evidence


def check_boot(output: str, smp: int) -> tuple[list[str], dict]:
    failures: list[str] = []

    # In order, not merely present. Each of these follows from the one before
    # it, so a run that shows them out of order is showing something other
    # than this exchange.
    cursor = 0
    for marker in APP_MARKERS:
        index = output.find(marker, cursor)
        if index < 0:
            if marker in output:
                failures.append(f"marker out of order: {marker}")
            else:
                failures.append(f"missing marker: {marker}")
            cursor = 0
        else:
            cursor = index + len(marker)

    present = [marker for marker in FAILURE_MARKERS if marker in output]
    failures.extend(f"failure marker present: {marker}" for marker in present)

    refusal = UNBOUND_REFUSAL.search(output)
    if refusal is not None:
        end = output.find("\n", refusal.start())
        line = output[refusal.start():end if end >= 0 else len(output)]
        failures.append(f"syscall refused on an unbound CPU: {line.strip()}")

    warning = APP_EXIT_WARNING.search(output)
    if warning is not None:
        failures.append(f"/bin/joinnest exited with status {warning.group(1)}")

    # The two floors, both read off the summary line.
    #
    # The first is that the workload ran the nested join rather than starting
    # and deciding there was nothing to do -- ran_nested is printed only after
    # the helper has come back holding the victim's result and its own process
    # context. The second is that the guest came up with the CPU count this
    # gate asked for: one CPU cannot reach the window at all, and a boot that
    # silently came up with one would otherwise read as a boot that reached it
    # and found nothing wrong.
    summary = APP_SUMMARY.search(output)
    if summary is None:
        failures.append("the workload never reported a nested join summary")
        return failures, {}
    cpus = int(summary.group(1))
    pinned_cpu = int(summary.group(2))
    helper_id = int(summary.group(3))
    victim_id = int(summary.group(4))
    ran_nested = int(summary.group(5))
    evidence = {
        "reported_cpus": cpus,
        "pinned_cpu": pinned_cpu,
        "helper_thread_id": helper_id,
        "victim_thread_id": victim_id,
        "ran_nested": ran_nested,
    }
    if cpus != smp:
        failures.append(
            f"guest reported cpus={cpus}, this gate asked for {smp}")
    if cpus < 2:
        failures.append("a single-CPU guest cannot reach the nested join")
    if ran_nested != 1:
        failures.append("the workload did not run a nested join")

    section = app_slice(output)
    if not section:
        failures.append("the workload never started")
        return failures, evidence

    nesting_failures, nesting = check_nesting(section, helper_id, victim_id,
                                              pinned_cpu)
    failures.extend(nesting_failures)
    evidence.update(nesting)
    return failures, evidence


def main() -> int:
    arch = arch_from_argv(sys.argv[1:])
    smp = int_argument(sys.argv[1:], "--smp", DEFAULT_SMP)
    repeat = int_argument(sys.argv[1:], "--repeat", DEFAULT_REPEAT)
    # RISC-V runs the same closure through an interpreter with no host
    # acceleration, so a shared budget would either fail that machine or stop
    # bounding the other two.
    timeout = int_argument(sys.argv[1:], "--timeout",
                           600 if arch == "riscv64" else 180)
    if smp < 2:
        print("qemu-thread-join-soak: --smp must be at least 2; the window "
              "needs a worker CPU that is not the caller's")
        return 2

    BUILD.mkdir(parents=True, exist_ok=True)
    report_path = BUILD / f"qemu-thread-join-soak-{arch}.json"
    started = time.time()
    failures: list[str] = []
    checks = []

    stale = stale_medium(arch)
    if stale:
        print("qemu-thread-join-soak: refusing to boot a stale image")
        for reason in stale:
            print(f" - {reason}")
        return 2

    for iteration in range(1, repeat + 1):
        log_path = BUILD / f"qemu-thread-join-soak-{arch}-{iteration}.log"
        print(f"qemu-thread-join-soak: boot {iteration}/{repeat} "
              f"arch={arch} smp={smp}", flush=True)
        output = boot(arch, smp, timeout, log_path)
        boot_failures, evidence = check_boot(output, smp)
        checks.append(result(f"boot_{iteration}", not boot_failures,
                             failures=boot_failures, evidence=evidence,
                             log=str(log_path.relative_to(ROOT))))
        failures.extend(f"boot {iteration}: {failure}"
                        for failure in boot_failures)

    report = {
        "schema": SCHEMA,
        "generated_at": now(),
        "status": status_from_failures(failures),
        "arch": arch,
        "cpus": smp,
        "boots": repeat,
        "elapsed_seconds": round(time.time() - started, 3),
        "tracker_item": "B-02",
        "claims": [
            "a user process's xaios_thread_join runs a pending thread of its "
            "own on its own CPU, nested inside the join syscall",
            "the CPU's current process, address space and thread slot are "
            "what they were when the nested run returns",
        ],
        "not_claimed": [
            "anything about joins whose nested run belongs to the kernel "
            "rather than to a user process",
        ],
        "checks": checks,
        "failures": failures,
    }
    write_report(report_path, report)
    if failures:
        print("qemu-thread-join-soak: failed")
        for failure in failures:
            print(f" - {failure}")
        return 1
    print(f"qemu-thread-join-soak: nested user join kept its process context "
          f"on {repeat} boots (arch={arch}, cpus={smp})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
