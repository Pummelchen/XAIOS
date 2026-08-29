#!/usr/bin/env python3
"""Build a model volume large enough for the read cache to have to choose.

The ordinary fixture carries a two-megabyte active package: one chunk. A cache
measured against it proves the mechanism works and nothing about the policy,
because there is never a second chunk to prefer over the first and never a
moment where something has to be given up.

This one is ninety-six mebibytes of active package -- forty-eight chunks at
the smallest size the format allows. Read against the default 256 MB budget it
fits entirely and the hit rate is the question; read against a budget
deliberately set below it, every admission has to evict something, and what
gets kept is the policy under test.

The package is active rather than staging on purpose. Staging packages are
being written and the cache refuses them, which is the correct behaviour and
not the one worth measuring.
"""

import hashlib
import sys
from pathlib import Path

from xaios_xai_fs import XaiFs, manifest_for_file

VOLUME_BYTES = 512 * 1024 * 1024
CHUNK_BYTES = 2 * 1024 * 1024
ACTIVE_CHUNKS = 48
PATTERN_PERIOD = 4096


def chunk_pattern(index: int) -> bytes:
    """Distinct bytes per chunk, cheap to generate on both sides.

    The phase depends on the chunk number, so a chunk served from the wrong
    cache slot fails its checksum rather than matching by luck -- which is the
    failure a cache keyed by physical offset could plausibly have.
    """
    period = bytes(
        ((position * 7) + (index * 89) + 13) & 0xFF
        for position in range(PATTERN_PERIOD)
    )
    return period * (CHUNK_BYTES // PATTERN_PERIOD)


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: create_cache_fixture.py OUTPUT")
    output = Path(sys.argv[1])

    source = output.with_suffix(".cache-active")
    with source.open("wb") as stream:
        for index in range(ACTIVE_CHUNKS):
            stream.write(chunk_pattern(index))

    manifest = manifest_for_file(
        source,
        bytes.fromhex("5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"),
        hashlib.sha256(b"cache-gate-active").digest(),
        "cache-gate",
        "portable",
        CHUNK_BYTES,
        bytes(range(32)),
    )

    with XaiFs.format(
        output,
        VOLUME_BYTES,
        CHUNK_BYTES,
        bytes.fromhex("9b8a7c6d5e4f3a2b1c0d9e8f7a6b5c4d"),
    ) as volume:
        package_id = volume.stage_begin(manifest)
        volume.pwrite_from_file(package_id, source)
        volume.activate(package_id)

    source.unlink()
    print(f"cache fixture: {output} active={package_id.hex()} "
          f"chunks={ACTIVE_CHUNKS} chunk_bytes={CHUNK_BYTES} "
          f"package_bytes={ACTIVE_CHUNKS * CHUNK_BYTES}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
