#!/usr/bin/env python3
"""Cut power to a machine mid-write and check that nothing broken survived.

The requirement is not that writes always complete. It is that an interrupted
write leaves behind either the whole thing or none of it, never a half of it:
better to lose a chunk than to keep a chunk that is quietly wrong. A model
whose weights are corrupt in one tensor and correct everywhere else is worse
than a model that is visibly missing, because the first one still loads.

xaiFS is built to give that. A commit writes an entire fresh catalog at an
unused offset, flushes, then writes the *other* superblock slot and flushes
again. The superblock carries a hash of itself and a hash of the catalog it
points at, so a slot caught half-written fails its own hash and is passed
over for the surviving slot. Every chunk marked complete in whichever catalog
wins was hashed and matched before it was ever marked.

That is an argument. This gate is the evidence, in two parts.

**Killed mid-ingest.** A guest ingests a staged package chunk by chunk,
committing each. The gate kills the emulator outright at a random moment and
then asks fsck to hash every chunk the surviving catalog still calls
complete. Requests in flight at the moment of the kill are abandoned or
applied in part, which is exactly the torn-write case that matters now that
a single request carries up to a mebibyte rather than a sector.

**Torn superblock.** A kill rarely lands inside the 4096 bytes of the
superblock itself, so the case that the whole A/B design exists for is the
one a kill test almost never reaches. So it is produced directly: take a
healthy volume, overwrite part of the slot that was written last, and require
that the volume still mounts -- from the older slot, having lost the newest
commit and nothing else.

What this does not model: a device that acknowledges a write, keeps it in a
volatile cache, and loses it on power failure. The emulator hands writes to
the host as it receives them. xaiFS defends against that case by flushing
before it flips the superblock, and the flush is a real VIRTIO_BLK_T_FLUSH,
but this gate does not prove it -- it proves the ordering-and-tearing half.
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
sys.path.insert(0, str(ROOT / "tests" / "scripts"))
from qemu_gate_lib import (arch_from_argv, qemu_boot_environment, qemu_runner,
                           smoke_timeout)

ARCH = arch_from_argv(sys.argv)
REPORT = BUILD / (f"qemu-crash-safety-gate-{ARCH}.json" if ARCH != "aarch64"
                  else "qemu-crash-safety-gate.json")
PRISTINE = BUILD / "xaios-crash-fixture.img"
# Per architecture: the pristine fixture is an input and shared, but the
# copy being wrecked is not, and two runs sharing one would each report
# the other's damage.
WORKING = BUILD / (f"crash-trial-{ARCH}.img" if ARCH != "aarch64"
                   else "crash-trial.img")
TOOLS = ROOT / "tools"

TRIALS = int(os.environ.get("XAIOS_CRASH_TRIALS", "8"))
# Where in the ingest to cut, counted in commits rather than in seconds.
#
# A wall-clock delay measures the host, not the guest. Six seconds is most of
# an ingest on a fast machine and not one commit on a loaded CI runner, and a
# trial that kills before anything has been committed proves nothing and fails
# the gate for a reason that has nothing to do with the code. Waiting for a
# given number of commits lands at the same place in the sequence whatever the
# machine is doing.
MIN_COMMITS = int(os.environ.get("XAIOS_CRASH_MIN_COMMITS", "1"))
MAX_COMMITS = int(os.environ.get("XAIOS_CRASH_MAX_COMMITS", "30"))
# And then a moment longer, so the kill lands at an arbitrary phase within the
# commit that follows rather than always just after one finished.
MIN_JITTER_S = float(os.environ.get("XAIOS_CRASH_MIN_JITTER", "0.0"))
MAX_JITTER_S = float(os.environ.get("XAIOS_CRASH_MAX_JITTER", "0.4"))
BOOT_TIMEOUT_S = float(smoke_timeout(
    ARCH, int(os.environ.get("XAIOS_CRASH_BOOT_TIMEOUT", "240"))))
SEED = int(os.environ.get("XAIOS_CRASH_SEED", "20260829"))

STARTED = re.compile(rb"crash-writer: ingest started")
COMMITTED = re.compile(rb"crash-writer: committed chunk=(\d+)")
FINISHED = re.compile(rb"crash-writer: ingest finished")
SUPERBLOCK_BYTES = 4096


def fail(message: str) -> int:
    print(f"crash-safety-gate: {message}")
    return 1


def fsck(image: Path) -> dict:
    """Ask the host tool what the volume looks like from the outside.

    Deliberately not the kernel's own reader: a check written against the same
    assumptions as the writer can agree with it about something they are both
    wrong about.
    """
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(TOOLS) + os.pathsep + environment.get(
        "PYTHONPATH", "")
    result = subprocess.run(
        [sys.executable, str(TOOLS / "xaios_xai_fs.py"), "fsck",
         "--verify-data", str(image)],
        cwd=ROOT, env=environment, capture_output=True, text=True, check=False)
    # A nonzero exit is fsck's way of saying the volume is not clean, which is
    # an answer and not a malfunction -- a volume with one torn superblock is
    # repairable, and reporting that is the tool working. Only output that is
    # not a report at all counts as the tool having failed.
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"status": "tool_failed",
                "errors": [result.stderr.strip() or result.stdout.strip()]}


def run_until_killed(log: Path, after_commits: int,
                     jitter_s: float) -> tuple[int, bool]:
    """Boot, wait for `after_commits` commits, wait `jitter_s`, then kill.

    Returns the highest chunk number the guest reported committing and whether
    the ingest was still running when the kill landed. Counting commits rather
    than seconds keeps the cut at the same point in the sequence on a fast
    machine and a slow one; the jitter afterwards is what puts it at an
    arbitrary phase inside the commit that follows, which is the case that
    matters.
    """
    log.unlink(missing_ok=True)
    environment = dict(os.environ)
    environment["XAIOS_XAI_FS_IMAGE"] = str(WORKING)
    # No host port forwarding. Neither gate uses SSH, and claiming a fixed
    # host port means one stale emulator anywhere on the machine turns every
    # trial into a boot that never happened -- reported, unhelpfully, as a
    # guest that never committed anything.
    #
    # serial_to_stdout because this reads the guest's console out of the pipe
    # it is redirecting into `log`. The RISC-V runner writes the console to a
    # file of its own by default, which would leave that pipe empty and every
    # trial looking like a guest that never started.
    environment = qemu_boot_environment(ARCH, environment, hostfwd_port="none",
                                        serial_to_stdout=True)
    with log.open("wb") as sink:
        process = subprocess.Popen(
            [qemu_runner(ARCH)],
            cwd=ROOT, env=environment, stdout=sink,
            stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
            start_new_session=True)
    try:
        deadline = time.monotonic() + BOOT_TIMEOUT_S
        # If the ingest never starts, the kernel was built without the crash
        # writer and no amount of waiting will produce a commit. Say so in
        # seconds rather than burning the boot timeout once per trial.
        started_deadline = time.monotonic() + BOOT_TIMEOUT_S / 2.0
        reached = None
        while True:
            if process.poll() is not None:
                break
            text = log.read_bytes()
            if not STARTED.search(text) and time.monotonic() > started_deadline:
                break
            committed = len(COMMITTED.findall(text))
            if reached is None and committed >= after_commits:
                reached = time.monotonic()
            if reached is not None and time.monotonic() - reached >= jitter_s:
                break
            # An ingest that has finished will never reach a higher count, so
            # stop waiting for one rather than burning the whole timeout.
            if FINISHED.search(text):
                break
            if time.monotonic() > deadline:
                break
            time.sleep(0.02)
        alive = process.poll() is None
        if alive:
            # The whole process group, and SIGKILL rather than SIGTERM: a
            # shutdown the emulator can see is not a power cut.
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            process.wait(timeout=30)
    finally:
        if process.poll() is None:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            process.wait(timeout=30)
    committed = [int(match.group(1)) for match in COMMITTED.finditer(
        log.read_bytes())]
    return (max(committed) + 1 if committed else 0), alive


def slot_generations(image: Path) -> dict[int, int]:
    """Which slot holds the newer commit, read the way the volume is read."""
    sys.path.insert(0, str(TOOLS))
    from xaios_xai_fs import _read_candidate  # noqa: PLC0415

    found = {}
    handle = os.open(image, os.O_RDONLY)
    try:
        size = os.fstat(handle).st_size
        for slot in (0, 1):
            try:
                found[slot] = _read_candidate(handle, size, slot)[0][
                    "generation"]
            except ValueError:
                pass
    finally:
        os.close(handle)
    return found


def tear_superblock(image: Path, slot: int, rng: random.Random) -> int:
    """Overwrite part of one superblock, as an interrupted write would.

    A 4096-byte write is several device writes underneath. Losing the tail of
    it is the ordinary way it fails, so that is what this does: keep a random
    prefix, replace the rest with the byte pattern a half-erased block tends
    to carry. Returns how many bytes were left intact.
    """
    keep = rng.randrange(64, SUPERBLOCK_BYTES - 64)
    with image.open("r+b") as stream:
        stream.seek(slot * SUPERBLOCK_BYTES + keep)
        stream.write(bytes([0xFF]) * (SUPERBLOCK_BYTES - keep))
    return keep


def lose_catalog_write(image: Path, slot: int) -> int:
    """Discard the catalog a slot points at, leaving the slot itself intact.

    This is the state a device with a volatile write cache produces when the
    power goes between the catalog write and the superblock that publishes it:
    the superblock reached the platter and the thing it points at did not. A
    commit writes its catalog at an unused offset, so what a lost write leaves
    behind is the region as it was -- unwritten -- which is why this zeroes it
    rather than scribbling on it.

    `qemu-write-ordering-gate` proves the flush that prevents this is issued.
    This is the other half: what the volume does if a device ignores it anyway.
    Returns how many bytes were discarded.
    """
    sys.path.insert(0, str(TOOLS))
    from xaios_xai_fs import _decode_superblock  # noqa: PLC0415

    handle = os.open(image, os.O_RDONLY)
    try:
        size = os.fstat(handle).st_size
        raw = os.pread(handle, SUPERBLOCK_BYTES, slot * SUPERBLOCK_BYTES)
        superblock = _decode_superblock(raw, size)
    finally:
        os.close(handle)
    offset = int(superblock["catalog_offset"])
    length = int(superblock["catalog_length"])
    with image.open("r+b") as stream:
        stream.seek(offset)
        stream.write(bytes(length))
    return length


def prove_the_check_can_fail(rng: random.Random) -> str | None:
    """Flip one byte inside a complete chunk and require fsck to notice.

    Without this the gate is unfalsifiable: eight trials reporting "clean"
    mean nothing if the thing reporting it would say clean about anything.
    One byte, in the middle of a chunk the catalog vouches for, is the
    smallest corruption the design claims to catch.
    """
    sys.path.insert(0, str(TOOLS))
    from xaios_xai_fs import XaiFs, CHUNK_COMPLETE  # noqa: PLC0415

    shutil.copyfile(PRISTINE, WORKING)
    target = None
    with XaiFs(WORKING, read_only=True) as volume:
        for record in volume.records:
            for chunk in volume._record_chunks(record):
                if chunk.flags & CHUNK_COMPLETE and chunk.length > 4096:
                    target = chunk.physical_offset + rng.randrange(
                        0, chunk.length)
                    break
            if target is not None:
                break
    if target is None:
        return "the fixture has no complete chunk to corrupt"
    with WORKING.open("r+b") as stream:
        stream.seek(target)
        original = stream.read(1)
        stream.seek(target)
        stream.write(bytes([original[0] ^ 0xFF]))
    check = fsck(WORKING)
    if not check.get("errors"):
        return (f"a flipped byte at {target} was not detected; fsck said "
                f"{check.get('status')}, so every clean result above is "
                f"worth nothing")
    print(f"crash-safety-gate: falsifiability byte={target} "
          f"fsck={check.get('status')} errors={len(check['errors'])}")
    return None


def main() -> int:
    if not PRISTINE.is_file():
        return fail(f"no crash fixture at {PRISTINE}; run "
                    f"tests/xai_fs/create_crash_fixture.py first")
    baseline = fsck(PRISTINE)
    if baseline.get("status") != "clean":
        return fail(f"the fixture is not clean to begin with: {baseline}")

    rng = random.Random(SEED)
    trials = []
    failures = []

    # Before anything else, show that the check being applied below is capable
    # of reporting a failure at all.
    unfalsifiable = prove_the_check_can_fail(rng)
    if unfalsifiable:
        return fail(unfalsifiable)

    for index in range(TRIALS):
        shutil.copyfile(PRISTINE, WORKING)
        after_commits = rng.randint(MIN_COMMITS, MAX_COMMITS)
        jitter = rng.uniform(MIN_JITTER_S, MAX_JITTER_S)
        log = BUILD / f"crash-trial-{ARCH}-{index}.log"
        committed, killed_while_running = run_until_killed(log, after_commits,
                                                           jitter)
        check = fsck(WORKING)
        record = {
            "trial": index,
            "kill_after_commits": after_commits,
            "kill_jitter_s": round(jitter, 3),
            "chunks_committed_by_guest": committed,
            "killed_while_running": killed_while_running,
            "status": check.get("status"),
            "generation": check.get("generation"),
            "verified_chunks": check.get("verified_chunks"),
            "errors": check.get("errors", []),
        }
        trials.append(record)
        if check.get("status") == "tool_failed" or check.get("errors"):
            failures.append(f"trial {index}: {check}")
        elif check.get("valid_superblocks", 0) < 1:
            failures.append(f"trial {index}: no superblock survived")
        elif committed == 0:
            failures.append(
                f"trial {index}: the guest never committed a chunk, so the "
                f"kill proved nothing -- check that the kernel was built with "
                f"XAIOS_CRASH_WRITER=1, which is what the make target for "
                f"this architecture does")
        print(f"crash-safety-gate: trial {index} "
              f"kill_after={after_commits} commits +{jitter:.2f}s "
              f"guest_committed={committed} fsck={check.get('status')} "
              f"generation={check.get('generation')} "
              f"verified_chunks={check.get('verified_chunks')}")

    # A run where every kill landed at the same phase would pass while proving
    # one instant safe. Different surviving generations is the evidence that
    # the kills were spread across the commit sequence.
    generations = {record["generation"] for record in trials}
    if TRIALS > 2 and len(generations) < 2:
        failures.append(
            f"every trial survived at the same generation {generations}; the "
            f"kills did not land at different points")

    # The case a kill almost never produces on its own. Tearing the newer
    # slot is the one that costs something: the volume has to fall back to the
    # older commit, which is the loss the design accepts in exchange for never
    # serving a blend of the two.
    generations_by_slot = slot_generations(PRISTINE)
    if len(generations_by_slot) != 2:
        failures.append(
            f"the fixture does not carry two readable superblocks: "
            f"{generations_by_slot}")
    torn = []
    for slot in sorted(generations_by_slot):
        shutil.copyfile(PRISTINE, WORKING)
        before = fsck(WORKING)
        kept = tear_superblock(WORKING, slot, rng)
        after = fsck(WORKING)
        rejected = [entry["slot"] for entry in after.get(
            "invalid_superblocks", [])]
        other = 1 - slot
        record = {
            "slot_torn": slot,
            "bytes_left_intact": kept,
            "status": after.get("status"),
            "generation_before": before.get("generation"),
            "generation_after": after.get("generation"),
            "expected_generation": generations_by_slot[other],
            "rejected_slots": rejected,
            "errors": after.get("errors", []),
        }
        torn.append(record)
        if after.get("status") == "tool_failed":
            failures.append(f"torn slot {slot}: fsck could not run: {after}")
        elif after.get("errors"):
            failures.append(f"torn slot {slot}: {after['errors']}")
        elif rejected != [slot]:
            failures.append(
                f"torn slot {slot}: expected exactly that slot to be "
                f"rejected, got {rejected} -- a half-written superblock was "
                f"accepted as valid, or an intact one was not")
        elif after.get("generation") != generations_by_slot[other]:
            failures.append(
                f"torn slot {slot}: fell back to generation "
                f"{after.get('generation')}, expected "
                f"{generations_by_slot[other]}")
        print(f"crash-safety-gate: torn slot={slot} kept={kept}B "
              f"fsck={after.get('status')} rejected={rejected} "
              f"generation {before.get('generation')} -> "
              f"{after.get('generation')}")

    # **A catalog write that never landed.** The case above is a superblock
    # caught half-written. This is its mirror and the one a volatile write
    # cache actually produces: the superblock is whole and on the platter, and
    # the catalog it points at is not there at all. The superblock carries a
    # hash of that catalog, so the slot must fail its own check and the volume
    # must come back from the other one -- a commit lost, which is the trade,
    # rather than a superblock followed to a catalog that was never written.
    lost = []
    for slot in sorted(generations_by_slot):
        shutil.copyfile(PRISTINE, WORKING)
        before = fsck(WORKING)
        discarded = lose_catalog_write(WORKING, slot)
        after = fsck(WORKING)
        rejected = [entry["slot"] for entry in after.get(
            "invalid_superblocks", [])]
        other = 1 - slot
        record = {
            "slot_orphaned": slot,
            "catalog_bytes_discarded": discarded,
            "status": after.get("status"),
            "generation_before": before.get("generation"),
            "generation_after": after.get("generation"),
            "expected_generation": generations_by_slot[other],
            "rejected_slots": rejected,
            "errors": after.get("errors", []),
        }
        lost.append(record)
        if after.get("status") == "tool_failed":
            failures.append(f"orphaned slot {slot}: fsck could not run: {after}")
        elif after.get("errors"):
            failures.append(f"orphaned slot {slot}: {after['errors']}")
        elif rejected != [slot]:
            failures.append(
                f"orphaned slot {slot}: expected exactly that slot to be "
                f"rejected, got {rejected} -- a superblock pointing at a "
                f"catalog that was never written was accepted")
        elif after.get("generation") != generations_by_slot[other]:
            failures.append(
                f"orphaned slot {slot}: fell back to generation "
                f"{after.get('generation')}, expected "
                f"{generations_by_slot[other]}")
        print(f"crash-safety-gate: catalog lost slot={slot} "
              f"discarded={discarded}B fsck={after.get('status')} "
              f"rejected={rejected} generation "
              f"{before.get('generation')} -> {after.get('generation')}")

    report = {
        "schema": "xaios.crash-safety.v1",
        "falsifiability_checked": True,
        "trials": trials,
        "torn_superblocks": torn,
        "lost_catalog_writes": lost,
        "failures": failures,
        "passed": not failures,
    }
    REPORT.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    WORKING.unlink(missing_ok=True)

    if failures:
        for message in failures:
            print(f"crash-safety-gate: FAIL {message}")
        return 1
    print(f"crash-safety-gate: passed arch={ARCH} trials={TRIALS} "
          f"generations={sorted(generations)} report={REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
