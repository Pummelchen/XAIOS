#!/usr/bin/env python3

import hashlib
import sys
from pathlib import Path

from xaios_xai_fs import XaiFs, sparse_zero_manifest


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: create_c_sparse_fixture.py OUTPUT")
    output = Path(sys.argv[1])
    gib = 1024 * 1024 * 1024
    chunk_size = 16 * 1024 * 1024
    logical_size = 100 * gib + 2 * 4096
    manifest = sparse_zero_manifest(
        logical_size,
        chunk_size,
        bytes.fromhex("102132435465768798a9bacbdcedfe0f"),
        hashlib.sha256(b"c-reader-sparse-100-gib").digest(),
        "capacity-test",
        "portable",
        bytes(range(32)),
    )
    with XaiFs.format(
        output,
        128 * gib,
        chunk_size,
        bytes.fromhex("00112233445566778899aabbccddeeff"),
    ) as volume:
        package_id = volume.stage_begin(manifest)
        volume.stage_verify(package_id)
        volume.activate(package_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
