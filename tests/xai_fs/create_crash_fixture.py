#!/usr/bin/env python3
"""Build the xaiFS volume the crash-safety gate cuts power to.

The ordinary fixture exists to be read. This one exists to be interrupted: a
single staging package large enough that ingesting it takes many separate
commits, so that killing the machine at an arbitrary moment lands in the
middle of one. Each commit writes a fresh catalog and then flips the
superblock, and the whole claim under test is that a reader arriving after
the cut sees one side of that flip or the other and never a blend of the two.

Thirty-two chunks of two mebibytes -- two being the smallest chunk the format
allows. Thirty-two commit points is enough that a kill at a uniformly random
moment during ingest rarely lands twice in the same window, and small enough
that a full ingest still finishes inside a gate's patience on an emulator.

The active package is here only because a volume with nothing active is not
the volume XAIOS actually mounts; it keeps the fixture honest about the
signature and manifest checks that run at mount.
"""

import hashlib
import sys
from pathlib import Path

from xaios_xai_fs import XaiFs, manifest_for_file

VOLUME_BYTES = 256 * 1024 * 1024
CHUNK_BYTES = 2 * 1024 * 1024
STAGING_CHUNKS = 32
ACTIVE_BYTES = 2 * 1024 * 1024
PATTERN_PERIOD = 256


def chunk_pattern(index: int) -> bytes:
    """The bytes of staging chunk `index`, and the only bytes fsck accepts.

    The period repeats within a chunk but the phase is a function of the chunk
    number, so a chunk landing at the wrong offset fails its checksum instead
    of matching by luck. Both sides can generate it from two multiplies, which
    matters because the guest generating it has no tables and the host
    generating it is doing so sixty-four mebibytes at a time.
    """
    period = bytes(
        ((position * 31) + (index * 97) + 17) & 0xFF
        for position in range(PATTERN_PERIOD)
    )
    return period * (CHUNK_BYTES // PATTERN_PERIOD)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: create_crash_fixture.py OUTPUT")
    output = Path(sys.argv[1])
    # A fresh checkout has no build directory, and every path below is a
    # sibling of the output. Making it here rather than relying on a build
    # having happened first is what lets this run as the first step of a gate.
    output.parent.mkdir(parents=True, exist_ok=True)

    active_source = output.with_suffix(".crash-active")
    active_source.write_bytes(bytes(index % 251 for index in range(4096)) *
                              (ACTIVE_BYTES // 4096))
    active_manifest = manifest_for_file(
        active_source,
        bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0"),
        hashlib.sha256(b"crash-gate-active").digest(),
        "crash-gate",
        "portable",
        CHUNK_BYTES,
        bytes(range(32)),
    )

    staging_source = output.with_suffix(".crash-staging")
    staging_size = CHUNK_BYTES * STAGING_CHUNKS
    with staging_source.open("wb") as stream:
        for index in range(STAGING_CHUNKS):
            stream.write(chunk_pattern(index))
    staging_manifest = manifest_for_file(
        staging_source,
        bytes.fromhex("a1b2c3d4e5f60718293a4b5c6d7e8f90"),
        hashlib.sha256(b"crash-gate-staging").digest(),
        "crash-gate",
        "portable",
        CHUNK_BYTES,
        bytes(reversed(range(32))),
    )

    with XaiFs.format(
        output,
        VOLUME_BYTES,
        CHUNK_BYTES,
        bytes.fromhex("c4a5b6978089a1b2c3d4e5f607182930"),
    ) as volume:
        active_id = volume.stage_begin(active_manifest)
        volume.pwrite_from_file(active_id, active_source)
        volume.activate(active_id)
        staging_id = volume.stage_begin(staging_manifest)

    active_source.unlink()
    staging_source.unlink()
    print(f"crash fixture: {output} staging={staging_id.hex()} "
          f"chunks={STAGING_CHUNKS} chunk_bytes={CHUNK_BYTES}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
