#!/usr/bin/env python3
"""A block device that acknowledges writes and then loses the unflushed ones.

Why this file exists at all
---------------------------

Every crash test here up to now killed the emulator and looked at the image
afterwards, which sounds like a power cut and is not one. When QEMU writes to
a raw image it calls pwrite, and pwrite hands the bytes to the host kernel's
page cache. Killing QEMU -- SIGKILL, the whole process group, no chance to
clean up -- does not take the page cache with it. The host is still running
and still writes those pages back. So every write the guest ever had
acknowledged survives the kill, and the state that a real device with a
volatile write cache would leave behind never occurs.

That is not a guess. `cache=unsafe` (equivalently `cache.no-flush=on`) is the
usual suggestion, and it is the wrong tool for this: what it does is make
flushes no-ops, which changes what a *host* power failure would cost and
changes nothing at all about what a killed process loses. Measured, with
qemu-io driving the same block layer a virtio-blk device drives -- write, wait
for the acknowledgement, SIGKILL, then read the file back from the host:

    raw   cache=writeback  survived_kill=True
    raw   cache=unsafe     survived_kill=True
    qcow2 cache=writeback  survived_kill=False
    qcow2 cache=unsafe     survived_kill=False

raw loses nothing either way. qcow2 does lose the write, but for a reason that
is no use as a model: what it loses is the L2 table entry sitting in QEMU's own
metadata cache, so it loses writes that *allocate* a cluster and keeps writes
that land in a cluster already mapped. Which acknowledged writes disappear is
then decided by the image format's allocation state rather than by where the
guest put its flushes, and an overwrite -- which is what a superblock flip is
-- always survives. A device that loses exactly the writes qcow2 finds
inconvenient is not a device.

What QEMU does have is `blklogwrites`: a filter that sits under the virtio-blk
device, passes every request through to the image, and appends what it saw --
header and full payload, writes and flushes alike, in issue order -- to a
second file, in the same dm-log-writes format the Linux kernel's own
power-failure testing uses. That log is a complete record of what the guest
actually did. Replaying it is a device.

The model
---------

A device with a volatile write cache promises exactly one thing: when a FLUSH
completes, everything acknowledged before it is durable. It promises nothing
whatever about anything acknowledged since. So:

  * pick a cut point -- the instant the power went;
  * every write before the last flush that completed at or before the cut is
    on the platter, in order;
  * every write between that flush and the cut was acknowledged to the guest
    and may or may not have reached the platter. Each one independently.

`replay` implements that and nothing else. It decides which of the at-risk
writes survived by coin flip, from a seed the caller supplies, so a failing
run can be repeated exactly. Note what it does *not* do: it never invents a
write, never writes a byte the guest did not write, and never tears a single
request in half. Tearing is the crash gate's department and it constructs it
deliberately; this file's whole point is that everything it does was provoked.

`ignore_flushes=True` is the same model on a device that accepts flush
commands and does not honour them -- which is to say `cache=unsafe`, the thing
the option is actually good for. Every write since the volume was opened is at
risk. It exists as the negative control: if replaying a log that way does not
produce a corrupt volume, then the flushes in the log are not doing anything
and the honest replay proves nothing either.

Format notes, all of them checked against a log QEMU actually wrote rather
than against the header file: the log opens with a 512-byte superblock holding
a magic, a version, an entry count and the log's own sector size. Each entry
that follows is a 32-byte header padded out to that sector size, followed by
the payload padded the same way. `sector` and `nr_sectors` are in 512-byte
units of the *device*, independent of the log's sector size. The entry count
in the superblock is rewritten periodically rather than per entry, so a log
from a killed emulator understates it; that is why entries are read until they
stop making sense rather than counted out of the header.
"""

from __future__ import annotations

import random
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Sequence

# "rhswfsj", little-endian, from the dm-log-writes on-disk format.
LOG_MAGIC = 0x6A736677736872
LOG_VERSION = 1
SECTOR_BYTES = 512
ENTRY_HEADER_BYTES = 32

FLAG_FLUSH = 1 << 0
FLAG_FUA = 1 << 1
FLAG_DISCARD = 1 << 2
FLAG_MARK = 1 << 3
FLAG_METADATA = 1 << 4


@dataclass(frozen=True)
class Entry:
    """One thing the guest asked the device to do."""

    index: int
    offset: int          # byte offset into the volume
    length: int          # payload bytes
    flags: int
    payload: bytes

    @property
    def is_flush(self) -> bool:
        return bool(self.flags & FLAG_FLUSH)

    @property
    def is_write(self) -> bool:
        return not self.flags & (FLAG_FLUSH | FLAG_DISCARD | FLAG_MARK)

    @property
    def is_fua(self) -> bool:
        return bool(self.flags & FLAG_FUA)


class WriteLogError(ValueError):
    pass


def parse(path: Path) -> List[Entry]:
    """Every request in the log, in the order the guest issued it.

    Stops at the first entry that cannot be read whole. A log written by an
    emulator that was killed ends in the middle of one, and the alternative to
    stopping is to treat whatever bytes follow as a request -- which is how a
    replayer scribbles a gigabyte of nothing over a volume and then reports
    the corruption it caused itself.
    """
    blob = path.read_bytes()
    if len(blob) < SECTOR_BYTES:
        raise WriteLogError(f"{path} is too short to hold a log superblock")
    magic, version, _declared_entries, log_sector = struct.unpack_from(
        "<QQQI", blob, 0)
    if magic != LOG_MAGIC:
        raise WriteLogError(
            f"{path} does not start with a dm-log-writes superblock "
            f"(magic {magic:#x}); the run was probably not given "
            f"XAIOS_XAI_FS_WRITE_LOG, so nothing recorded it")
    if version != LOG_VERSION:
        raise WriteLogError(f"{path} is log version {version}, expected "
                            f"{LOG_VERSION}")
    if log_sector <= 0 or log_sector % SECTOR_BYTES:
        raise WriteLogError(f"{path} declares a {log_sector}-byte log sector")

    def pad(value: int) -> int:
        return (value + log_sector - 1) // log_sector * log_sector

    entries: List[Entry] = []
    cursor = log_sector
    while cursor + ENTRY_HEADER_BYTES <= len(blob):
        sector, sectors, flags, _data_len = struct.unpack_from(
            "<QQQQ", blob, cursor)
        cursor += log_sector
        payload_bytes = 0
        if not flags & (FLAG_FLUSH | FLAG_DISCARD | FLAG_MARK):
            payload_bytes = sectors * SECTOR_BYTES
        if cursor + payload_bytes > len(blob):
            # The entry header landed but its data did not: the recording was
            # cut here. The device never saw the whole request either.
            break
        payload = blob[cursor:cursor + payload_bytes]
        entries.append(Entry(index=len(entries),
                             offset=sector * SECTOR_BYTES,
                             length=payload_bytes, flags=flags,
                             payload=payload))
        cursor += pad(payload_bytes)
    return entries


def epoch_boundaries(entries: Sequence[Entry],
                     ignore_flushes: bool = False) -> List[int]:
    """Indices after which everything earlier is durable.

    A completed flush is such a point. So is a FUA write, for itself -- but
    only for itself, so it is not a boundary for the writes around it and is
    handled at the point of use rather than here.
    """
    if ignore_flushes:
        return []
    return [entry.index for entry in entries if entry.is_flush]


def replay(base: Path, out: Path, entries: Sequence[Entry], *,
           cut_after: int, seed: int, survival: float = 0.5,
           ignore_flushes: bool = False) -> dict:
    """Write the volume the machine would find after the power went at `cut_after`.

    `base` is the volume as it was before the boot -- the same pristine copy
    the emulator was given. Everything the guest wrote is applied on top from
    the log, which is why this cannot produce a byte the guest did not write.

    `survival` is the chance that any one at-risk write reached the platter.
    Neither 0 nor 1 is the interesting setting: at 0 the cache lost everything
    and the volume is simply older, at 1 nothing was lost at all. What a real
    cache does is keep some and lose some, in an order of its own choosing,
    and that is the case a filesystem has to survive.
    """
    if not 0.0 <= survival <= 1.0:
        raise WriteLogError(f"survival must be a probability, got {survival}")
    cut_after = max(-1, min(cut_after, len(entries) - 1))
    considered = [entry for entry in entries if entry.index <= cut_after]
    boundaries = [index for index in epoch_boundaries(considered,
                                                      ignore_flushes)]
    last_durable = boundaries[-1] if boundaries else -1

    rng = random.Random(seed)
    applied: List[Entry] = []
    dropped: List[Entry] = []
    for entry in considered:
        if not entry.is_write:
            continue
        if entry.index < last_durable:
            applied.append(entry)
        elif entry.is_fua and not ignore_flushes:
            # FUA means "this one is durable when it is acknowledged", which is
            # a promise about that write alone. xaiFS does not currently issue
            # any, so this branch is unexercised; it is here because silently
            # dropping a FUA write would be a wrong answer rather than a
            # missing feature, and the next driver change might issue one.
            applied.append(entry)
        elif rng.random() < survival:
            applied.append(entry)
        else:
            dropped.append(entry)

    out.write_bytes(base.read_bytes())
    with out.open("r+b") as volume:
        for entry in applied:
            volume.seek(entry.offset)
            volume.write(entry.payload)
        volume.flush()
    return {
        "entries_in_log": len(entries),
        "cut_after_entry": cut_after,
        "last_durable_entry": last_durable,
        "flushes_before_cut": len(boundaries),
        "writes_applied": len(applied),
        "writes_dropped": len(dropped),
        "bytes_dropped": sum(entry.length for entry in dropped),
        "dropped_offsets": sorted({entry.offset for entry in dropped})[:16],
        "survival": survival,
        "seed": seed,
        "ignore_flushes": ignore_flushes,
    }


def summarise(entries: Iterable[Entry]) -> dict:
    entries = list(entries)
    return {
        "entries": len(entries),
        "writes": sum(1 for entry in entries if entry.is_write),
        "flushes": sum(1 for entry in entries if entry.is_flush),
        "write_bytes": sum(entry.length for entry in entries
                           if entry.is_write),
    }


def main(argv: Sequence[str]) -> int:
    import argparse
    import json

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("log", type=Path)
    parser.add_argument("--base", type=Path,
                        help="the volume as it was before the recorded boot")
    parser.add_argument("--out", type=Path, help="where to write the result")
    parser.add_argument("--cut-after", type=int, default=-1,
                        help="entry index the power went at; default the end")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--survival", type=float, default=0.5)
    parser.add_argument("--ignore-flushes", action="store_true",
                        help="model a device that accepts flushes and does "
                             "not honour them")
    args = parser.parse_args(list(argv))

    entries = parse(args.log)
    report = summarise(entries)
    if args.base and args.out:
        cut = args.cut_after if args.cut_after >= 0 else len(entries) - 1
        report["replay"] = replay(args.base, args.out, entries, cut_after=cut,
                                  seed=args.seed, survival=args.survival,
                                  ignore_flushes=args.ignore_flushes)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    import sys

    raise SystemExit(main(sys.argv[1:]))
