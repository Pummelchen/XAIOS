#!/usr/bin/env python3
"""Acknowledge writes, lose the unflushed ones for real, reboot, come back whole.

This is the half `qemu-crash-safety-gate` and `qemu-write-ordering-gate` could
not reach between them.

The crash gate kills the emulator mid-ingest and checks what survived, but the
emulator loses nothing when it is killed: a write it acknowledged has already
gone into the host's page cache through pwrite, and the host outlives the
process and writes those pages back. So the crash gate's kills only ever
produce torn or abandoned *requests*, never lost *acknowledged* ones. It
covers the second case by building the state by hand -- overwrite half a
superblock, zero the catalog a slot points at -- which proves the reader
rejects those states and does not prove any device ever produces them.

The ordering gate reads the driver's own trace and requires a flush between
the catalog and the superblock that publishes it. That is a claim about what
the kernel asked for, checked where it can rot, and it says nothing about
what a device that took the flush seriously would leave behind.

What was missing was the whole loop: a device that acknowledges writes,
genuinely drops the ones that were never flushed, and a machine that then
boots that volume. This gate is that loop.

  * The models volume is attached through QEMU's `blklogwrites` filter, which
    passes every request through to the image and records it -- header and
    full payload, writes and flushes alike, in issue order -- in the
    dm-log-writes format. The guest sees an ordinary virtio-blk device and the
    kernel knows nothing about any of this.
  * The emulator is killed mid-ingest, which cuts the recording where the
    power went.
  * `tools/xaios_write_log.py` replays that log onto the volume as it was
    before the boot, honouring the one promise a volatile write cache makes:
    everything before the last completed flush is on the platter, and each
    write since then survived or did not, independently. Nothing is invented.
    Every byte written was a byte the guest wrote.
  * The result is checked from the host, by the tool that does not share the
    writer's assumptions, and then *booted*, and the kernel's own reader has
    to agree with the host tool about which commit survived.

The requirement, in full: no error at all, a superblock that survives, and a
generation no lower than the last commit that was durable when the power went.
Losing the commit in flight is the trade the design accepts. Losing one that
had already been flushed, or coming back to a superblock pointing at a catalog
that is not there, is not.

Falsifiability, every run, not as an afterthought. The same log is replayed a
second time through a device that accepts flush commands and ignores them --
`cache=unsafe`, which is a real setting real people use -- and that must
produce a corrupt volume. If it does not, the flushes in the log are not
buying anything and every clean result above is worth nothing, so the gate
fails and says so.

And falsifiability against the writer, checked by hand rather than by this
file, because it needs a rebuild. `xaios_xai_fs_commit_staging_range` issues
two flushes before it publishes anything: one before it writes the catalog and
one between the catalog and the superblock. Deleting *both* makes this gate
fail loudly -- nine cases across five of eight epochs, every one of them a
chunk the surviving catalog called complete whose bytes were not on the
volume. Deleting either one alone does not, and that is worth knowing: each of
them separates the data writes from the superblock that publishes them, so
either on its own is sufficient on a device that loses only unflushed writes,
and the pair is redundant. `qemu-write-ordering-gate` is the one that notices
the second flush going missing, from the driver's trace, and it should stay
that way -- a redundancy nobody designed is not something to start relying on.

What this still does not settle: this is a model of a volatile write cache,
not a cache. It assumes the device is honest about when a flush completed, and
a device that lies about that -- some do -- would defeat every filesystem
here and cannot be caught from inside the machine. It also cannot speak to
what happens to a drive's own capacitor-backed buffer, to a controller that
reorders across a flush in firmware, or to the write that was physically in
the head at the moment the rails collapsed. Those need a bench, a real disk,
and a switch.
"""

from __future__ import annotations

import json
import os
import random
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
TOOLS = ROOT / "tools"
sys.path.insert(0, str(ROOT / "tests" / "scripts"))
sys.path.insert(0, str(TOOLS))
from qemu_gate_lib import (arch_from_argv, qemu_boot_environment, qemu_runner,
                           smoke_timeout)
import xaios_write_log as write_log

ARCH = arch_from_argv(sys.argv)
SUFFIX = "" if ARCH == "aarch64" else f"-{ARCH}"
REPORT = BUILD / f"qemu-power-loss-gate{SUFFIX}.json"
PRISTINE = BUILD / "xaios-crash-fixture.img"
# The volume the recorded boot writes to, the log it is recorded into, and the
# volume each replay produces. Per architecture, because two runs sharing any
# of them would each be looking at the other's answer.
RECORDING_VOLUME = BUILD / f"power-loss-recording{SUFFIX}.img"
WRITE_LOG = BUILD / f"power-loss{SUFFIX}.writelog"
RECORDING_CONSOLE = BUILD / f"power-loss-recording{SUFFIX}.log"
REPLAYED = BUILD / f"power-loss-replayed{SUFFIX}.img"
REBOOT_VOLUME = BUILD / f"power-loss-reboot{SUFFIX}.img"
REBOOT_CONSOLE = BUILD / f"power-loss-reboot{SUFFIX}.log"

# Cuts at an arbitrary instant, on top of the epoch sweep below.
TRIALS = int(os.environ.get("XAIOS_POWER_LOSS_TRIALS", "6"))
# Coin sequences per epoch. Which of the at-risk writes a cache kept is a
# draw, so one draw per epoch tests one cache rather than the class of them;
# a replay and a check together cost well under a second, so there is no
# reason to be stingy here.
EPOCH_SEEDS = int(os.environ.get("XAIOS_POWER_LOSS_EPOCH_SEEDS", "4"))
# How far into the ingest to let the guest get before the power goes. Counted
# in commits rather than seconds for the same reason the crash gate counts
# them: a wall-clock delay measures the host and lands somewhere different on
# every machine.
COMMITS = int(os.environ.get("XAIOS_POWER_LOSS_COMMITS", "8"))
BOOT_TIMEOUT_S = float(smoke_timeout(
    ARCH, int(os.environ.get("XAIOS_POWER_LOSS_BOOT_TIMEOUT", "300"))))
SEED = int(os.environ.get("XAIOS_POWER_LOSS_SEED", "20260908"))

STARTED = re.compile(rb"crash-writer: ingest started")
COMMITTED = re.compile(rb"crash-writer: committed chunk=(\d+)")
MOUNTED = re.compile(rb"xaifs: mounted \S+ device=\S+ generation=(\d+)")
MOUNT_SKIPPED = re.compile(rb"xaifs: mount skipped status=(-?\d+)")
# Both superblock slots, 4096 bytes each, at the very front of the volume. A
# write landing in either is the flip that publishes one commit, which is what
# lets the floor below be counted rather than guessed.
SUPERBLOCK_REGION_BYTES = 2 * 4096


def fail(message: str) -> int:
    print(f"power-loss-gate: {message}")
    return 1


def fsck(image: Path) -> dict:
    """The volume as something that did not write it sees it.

    The same host tool the crash gate uses, and for the same reason: a check
    written against the writer's assumptions can agree with the writer about
    something they are both wrong about.
    """
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(TOOLS) + os.pathsep + environment.get(
        "PYTHONPATH", "")
    result = subprocess.run(
        [sys.executable, str(TOOLS / "xaios_xai_fs.py"), "fsck",
         "--verify-data", str(image)],
        cwd=ROOT, env=environment, capture_output=True, text=True, check=False)
    # A nonzero exit means "this volume is not clean", which is an answer.
    # Only output that is not a report at all is the tool having failed.
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"status": "tool_failed",
                "errors": [result.stderr.strip() or result.stdout.strip()]}


def boot(volume: Path, console: Path, *, record_to: Path | None,
         stop_after_commits: int) -> bytes:
    """Boot the machine on `volume` and kill it once it has committed enough.

    No host port forwarding: this gate never uses SSH, and claiming a fixed
    port means one stale emulator anywhere on the machine turns the run into a
    boot that never happened -- reported, unhelpfully, as a guest that never
    committed anything. serial_to_stdout because the console is read out of
    the pipe this redirects; one runner writes it to a file of its own by
    default and would leave the pipe empty.
    """
    console.unlink(missing_ok=True)
    environment = dict(os.environ)
    environment["XAIOS_XAI_FS_IMAGE"] = str(volume)
    if record_to is not None:
        # QEMU's file driver opens, it does not create. An empty file is
        # enough; blklogwrites writes its superblock over the front.
        record_to.write_bytes(b"")
        environment["XAIOS_XAI_FS_WRITE_LOG"] = str(record_to)
    environment = qemu_boot_environment(ARCH, environment, hostfwd_port="none",
                                        serial_to_stdout=True)
    with console.open("wb") as sink:
        process = subprocess.Popen(
            [qemu_runner(ARCH)], cwd=ROOT, env=environment, stdout=sink,
            stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            start_new_session=True)
    try:
        deadline = time.monotonic() + BOOT_TIMEOUT_S
        # If the ingest never starts, the kernel was built without the crash
        # writer and no amount of waiting produces a commit. Say so in seconds
        # rather than burning the whole boot timeout.
        started_deadline = time.monotonic() + BOOT_TIMEOUT_S / 2.0
        while process.poll() is None:
            text = console.read_bytes()
            if len(COMMITTED.findall(text)) >= stop_after_commits:
                break
            if not STARTED.search(text) and time.monotonic() > started_deadline:
                break
            if time.monotonic() > deadline:
                break
            time.sleep(0.05)
        if process.poll() is None:
            # The whole process group, and SIGKILL: a shutdown the emulator
            # can see is not a power cut, and a graceful exit would flush the
            # log and close the image, which is the opposite of the point.
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            process.wait(timeout=30)
    finally:
        if process.poll() is None:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            process.wait(timeout=30)
    return console.read_bytes()


def commits_durable_before(entries, boundary: int) -> int:
    """How many commits had definitely reached the platter by `boundary`.

    One superblock write publishes one commit and moves the generation on by
    one, and the commit's third flush follows that write immediately. So a
    superblock write earlier in the log than the last durable point is a
    commit the device had promised to keep, and the volume must come back with
    at least that many.
    """
    return sum(1 for entry in entries
               if entry.is_write and entry.offset < SUPERBLOCK_REGION_BYTES
               and entry.index < boundary)


def main() -> int:
    if not PRISTINE.is_file():
        return fail(f"no crash fixture at {PRISTINE}; run "
                    f"tests/xai_fs/create_crash_fixture.py first")
    baseline = fsck(PRISTINE)
    if baseline.get("status") != "clean":
        return fail(f"the fixture is not clean to begin with: {baseline}")
    baseline_generation = int(baseline["generation"])

    # ------------------------------------------------------------ recording
    shutil.copyfile(PRISTINE, RECORDING_VOLUME)
    text = boot(RECORDING_VOLUME, RECORDING_CONSOLE, record_to=WRITE_LOG,
                stop_after_commits=COMMITS)
    guest_commits = len(COMMITTED.findall(text))
    if guest_commits == 0:
        # Two very different failures land here and they used to be reported
        # as one. A runner that died before starting QEMU -- a missing system
        # volume, a port already taken -- leaves a console holding one line of
        # shell error, and telling that person to check XAIOS_CRASH_WRITER
        # sends them to the wrong place entirely. So the console decides which
        # thing to say, and either way its tail goes in the message.
        tail = text[-400:].decode("utf-8", "replace").strip()
        if not STARTED.search(text) and len(text) < 4096:
            return fail(
                f"no machine ever started: the runner produced {len(text)} "
                f"bytes and no kernel output at all. Its last words were "
                f"{tail!r} (console: {RECORDING_CONSOLE})")
        return fail(
            f"the guest booted and never committed a chunk, so there is "
            f"nothing to lose; check that the kernel was built with "
            f"XAIOS_CRASH_WRITER=1, which is what the make target for this "
            f"architecture does. Console tail: {tail!r} "
            f"({RECORDING_CONSOLE})")
    try:
        entries = write_log.parse(WRITE_LOG)
    except write_log.WriteLogError as error:
        return fail(str(error))
    recorded = write_log.summarise(entries)
    print(f"power-loss-gate: recorded arch={ARCH} commits={guest_commits} "
          f"entries={recorded['entries']} writes={recorded['writes']} "
          f"flushes={recorded['flushes']} "
          f"write_bytes={recorded['write_bytes']}")
    if recorded["flushes"] == 0:
        return fail("the guest issued no flush at all, so there is no "
                    "durability boundary to respect and this gate would be "
                    "asserting nothing")
    if recorded["writes"] < 2:
        return fail(f"only {recorded['writes']} write(s) were recorded")

    failures = []
    trials = []
    rng = random.Random(SEED)
    total_dropped = 0

    # ------------------------------------------------------ where to cut
    #
    # A uniformly random instant is the obvious choice and on its own it is a
    # poor one, which cost a rebuild to learn. The dangerous moment is the
    # *last* instant of a flush epoch: the moment when the cache is holding
    # the most it has not been told to keep. Everything the guest wrote since
    # the previous flush is at risk at once, including the superblock write
    # that publishes the commit if the driver put one in that epoch. Cutting
    # anywhere earlier in the same epoch is strictly less exposed, because the
    # writes after the cut had not been issued yet.
    #
    # That instant is also rare in the log -- one or two entries out of the
    # seventy a commit takes -- so uniform sampling almost never lands on it.
    # A first version of this gate sampled uniformly, and with the flush
    # before the superblock deleted from the writer it still passed six trials
    # out of six. It was not detecting the thing it exists to detect. So every
    # epoch in the recording gets cut at its last instant, deterministically,
    # and the coin is flipped a few times over each; the random instants stay
    # because a power cut is not obliged to be adversarial and a gate that only
    # tests the worst case is not testing the ordinary one.
    cases = []
    boundaries = [entry.index for entry in entries if entry.is_flush]
    for epoch, boundary in enumerate(boundaries):
        if boundary == 0:
            continue
        for repeat in range(EPOCH_SEEDS):
            cases.append({"kind": "epoch", "group": epoch,
                          "cut": boundary - 1, "survival": 0.5,
                          "seed": SEED + epoch * 4099 + repeat})
    for index in range(TRIALS):
        # Both ends of the survival range are legal device behaviour and both
        # are here: at 0 the cache lost everything and the volume is merely
        # older, at 1 nothing was lost at all. Neither is interesting on its
        # own, and a gate that quietly tested one point would not say so.
        cases.append({"kind": "instant", "group": index,
                      "cut": rng.randrange(len(entries) // 4, len(entries)),
                      "survival": rng.choice([0.0, 0.25, 0.5, 0.75, 1.0]),
                      "seed": SEED + 7919 + index})

    controls_run = 0
    controls_corrupted = 0
    for case in cases:
        loss = write_log.replay(PRISTINE, REPLAYED, entries,
                                cut_after=case["cut"], seed=case["seed"],
                                survival=case["survival"])
        total_dropped += loss["writes_dropped"]
        floor = baseline_generation + commits_durable_before(
            entries, loss["last_durable_entry"])
        check = fsck(REPLAYED)
        generation = check.get("generation")
        name = f"{case['kind']} {case['group']}"
        record = {
            "kind": case["kind"],
            "group": case["group"],
            "cut_after_entry": case["cut"],
            "survival": case["survival"],
            "seed": case["seed"],
            "writes_dropped": loss["writes_dropped"],
            "bytes_dropped": loss["bytes_dropped"],
            "last_durable_entry": loss["last_durable_entry"],
            "generation_floor": floor,
            "status": check.get("status"),
            "generation": generation,
            "valid_superblocks": check.get("valid_superblocks"),
            "verified_chunks": check.get("verified_chunks"),
            "errors": check.get("errors", []),
        }
        trials.append(record)
        if check.get("status") == "tool_failed":
            failures.append(f"{name}: fsck could not run: {check}")
        elif check.get("errors"):
            failures.append(
                f"{name} (cut at entry {case['cut']}, seed {case['seed']}): "
                f"the volume came back with {len(check['errors'])} error(s) "
                f"after losing {loss['writes_dropped']} unflushed write(s): "
                f"{check['errors'][:3]}")
        elif not check.get("valid_superblocks"):
            failures.append(
                f"{name} (cut at entry {case['cut']}, seed {case['seed']}): "
                f"no superblock survived")
        elif generation is None or generation < floor:
            failures.append(
                f"{name} (cut at entry {case['cut']}, seed {case['seed']}): "
                f"came back at generation {generation}, but {floor} commits "
                f"had been flushed before the power went; a commit the device "
                f"promised to keep was lost")

        # --------------------------------------------------------- control
        # The same log and the same cut -- through a device that accepts flush
        # commands and does not honour them. That is `cache=unsafe`, a setting
        # people really do use, and it is the one thing every argument in this
        # file depends on not being true. If this never corrupts the volume
        # then the flushes are not what is keeping it whole, and every clean
        # result above is worth nothing.
        #
        # Even odds rather than the case's own survival: a control that lost
        # *everything* leaves a volume that is merely older and perfectly
        # consistent, and one that lost nothing is not a power cut at all.
        # Neither says anything about ordering.
        unsafe = write_log.replay(PRISTINE, REPLAYED, entries,
                                  cut_after=case["cut"],
                                  seed=case["seed"] ^ 0x5EED,
                                  survival=0.5, ignore_flushes=True)
        unsafe_check = fsck(REPLAYED)
        corrupted = bool(unsafe_check.get("errors")) or not (
            unsafe_check.get("valid_superblocks"))
        controls_run += 1
        controls_corrupted += 1 if corrupted else 0
        record["control_writes_dropped"] = unsafe["writes_dropped"]
        record["control_status"] = unsafe_check.get("status")
        record["control_errors"] = len(unsafe_check.get("errors", []))
        record["control_corrupted"] = corrupted

        if case["kind"] == "instant":
            print(f"power-loss-gate: instant {case['group']} "
                  f"cut={case['cut']} survival={case['survival']} "
                  f"dropped={loss['writes_dropped']} writes "
                  f"({loss['bytes_dropped']}B) fsck={check.get('status')} "
                  f"generation={generation} floor={floor} "
                  f"verified_chunks={check.get('verified_chunks')} "
                  f"| control fsck={unsafe_check.get('status')} "
                  f"corrupted={corrupted}")

    # One line per epoch rather than one per coin sequence: EPOCH_SEEDS lines
    # apiece would bury the instants, and what matters per epoch is the range.
    for epoch in sorted({record["group"] for record in trials
                         if record["kind"] == "epoch"}):
        group = [record for record in trials
                 if record["kind"] == "epoch" and record["group"] == epoch]
        print(f"power-loss-gate: epoch {epoch} cut={group[0]['cut_after_entry']} "
              f"seeds={len(group)} "
              f"dropped={min(r['writes_dropped'] for r in group)}"
              f"-{max(r['writes_dropped'] for r in group)} writes "
              f"fsck={sorted({r['status'] for r in group})} "
              f"generation={sorted({r['generation'] for r in group})} "
              f"floor={group[0]['generation_floor']} "
              f"| control corrupted="
              f"{sum(1 for r in group if r['control_corrupted'])}/{len(group)}")

    if total_dropped == 0:
        failures.append(
            "not one acknowledged write was dropped across every case, so "
            "nothing was actually lost and the gate asserted nothing")
    if not controls_corrupted:
        failures.append(
            f"replaying the same log through a device that ignores flushes "
            f"left all {controls_run} volumes intact; the flushes are not "
            f"what is keeping the volume whole, so this gate cannot tell a "
            f"working filesystem from a broken one and its passes are "
            f"worthless")

    # ------------------------------------------------------------- reboot
    # A volume that satisfies a host tool is not yet a volume a machine can
    # use. Boot the survivor of the case that lost the most, and require the
    # kernel's own reader to mount it, to agree with the host tool about which
    # commit survived, and to accept a fresh commit on top.
    reboot = {}
    lossiest = max(trials, key=lambda entry: entry["writes_dropped"])
    replayed_again = write_log.replay(
        PRISTINE, REPLAYED, entries, cut_after=lossiest["cut_after_entry"],
        seed=lossiest["seed"], survival=lossiest["survival"])
    shutil.copyfile(REPLAYED, REBOOT_VOLUME)
    reboot_text = boot(REBOOT_VOLUME, REBOOT_CONSOLE, record_to=None,
                       stop_after_commits=1)
    mounted = MOUNTED.search(reboot_text)
    skipped = MOUNT_SKIPPED.search(reboot_text)
    reboot_commits = len(COMMITTED.findall(reboot_text))
    reboot = {
        "from_case": f"{lossiest['kind']} {lossiest['group']}",
        "writes_dropped": replayed_again["writes_dropped"],
        "expected_generation": lossiest["generation"],
        "kernel_generation": int(mounted.group(1)) if mounted else None,
        "mount_skipped_status": int(skipped.group(1)) if skipped else None,
        "commits_after_reboot": reboot_commits,
        "console": str(REBOOT_CONSOLE),
    }
    if skipped:
        failures.append(
            f"after the power cut the kernel refused to mount the volume "
            f"(status {skipped.group(1).decode()}); the host tool called it "
            f"{lossiest['status']}, so the two readers disagree")
    elif not mounted:
        failures.append(
            f"the machine did not report mounting the recovered volume at "
            f"all; see {REBOOT_CONSOLE}")
    elif reboot["kernel_generation"] != lossiest["generation"]:
        failures.append(
            f"the kernel mounted generation {reboot['kernel_generation']} and "
            f"the host tool read {lossiest['generation']} from the same "
            f"volume; one of the two readers is wrong about which commit "
            f"survived")
    elif reboot_commits == 0:
        failures.append(
            "the recovered volume mounted but the machine could not commit "
            "anything onto it, so it came back readable and not usable")
    print(f"power-loss-gate: reboot on the {reboot['from_case']} volume "
          f"({replayed_again['writes_dropped']} writes lost) "
          f"kernel_generation={reboot['kernel_generation']} "
          f"host_generation={lossiest['generation']} "
          f"commits_after_reboot={reboot_commits}")

    report = {
        "schema": "xaios.power-loss.v1",
        "arch": ARCH,
        "baseline_generation": baseline_generation,
        "guest_commits_recorded": guest_commits,
        "recording": recorded,
        "cases": trials,
        "cases_run": len(trials),
        "controls_run": controls_run,
        "controls_that_corrupted": controls_corrupted,
        "total_writes_dropped": total_dropped,
        "reboot": reboot,
        "failures": failures,
        "passed": not failures,
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    REPLAYED.unlink(missing_ok=True)
    RECORDING_VOLUME.unlink(missing_ok=True)
    REBOOT_VOLUME.unlink(missing_ok=True)

    if failures:
        for message in failures:
            print(f"power-loss-gate: FAIL {message}")
        return 1
    print(f"power-loss-gate: passed arch={ARCH} cases={len(trials)} "
          f"writes_lost={total_dropped} "
          f"controls_that_corrupted={controls_corrupted}/{controls_run} "
          f"report={REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
