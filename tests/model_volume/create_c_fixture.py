#!/usr/bin/env python3

import hashlib
import sys
from pathlib import Path

from xaios_model_volume import ModelVolume, manifest_for_file


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: create_c_fixture.py OUTPUT")
    output = Path(sys.argv[1])
    source = output.with_suffix(".package")
    size = 2 * 1024 * 1024 + 4096
    block = bytes(index % 251 for index in range(4096))
    with source.open("wb") as stream:
        remaining = size
        while remaining:
            data = block[: min(remaining, len(block))]
            stream.write(data)
            remaining -= len(data)
    manifest = manifest_for_file(
        source,
        bytes.fromhex("1234567890abcdef1234567890abcdef"),
        hashlib.sha256(b"c-reader-fixture").digest(),
        "c-reader-test",
        "portable",
        2 * 1024 * 1024,
        bytes(range(32)),
    )
    with ModelVolume.format(
        output,
        64 * 1024 * 1024,
        2 * 1024 * 1024,
        bytes.fromhex("fedcba0987654321fedcba0987654321"),
    ) as volume:
        package_id = volume.stage_begin(manifest)
        volume.pwrite_from_file(package_id, source)
        volume.activate(package_id)
        staging_source = output.with_suffix(".staging-package")
        staging_source.write_bytes(bytes((index * 7 + 3) & 0xFF for index in range(4096)))
        staging_manifest = manifest_for_file(
            staging_source,
            bytes.fromhex("00112233445566778899aabbccddeeff"),
            hashlib.sha256(b"c-writer-staging-fixture").digest(),
            "c-staging-test",
            "portable",
            2 * 1024 * 1024,
            bytes(reversed(range(32))),
        )
        volume.stage_begin(staging_manifest)
        staging_source.unlink()

        sftp_source = output.with_suffix(".sftp-staging-package")
        sftp_size = 2 * 1024 * 1024 + 64 * 1024
        sftp_block = bytes((index * 13 + 11) & 0xFF for index in range(4096))
        with sftp_source.open("wb") as stream:
            remaining = sftp_size
            while remaining:
                data = sftp_block[: min(remaining, len(sftp_block))]
                stream.write(data)
                remaining -= len(data)
        sftp_manifest = manifest_for_file(
            sftp_source,
            bytes.fromhex("ffeeddccbbaa99887766554433221100"),
            hashlib.sha256(b"c-sftp-staging-fixture").digest(),
            "sftp-staging-test",
            "portable",
            2 * 1024 * 1024,
            bytes((index * 3 + 1) & 0xFF for index in range(32)),
        )
        volume.stage_begin(sftp_manifest)
        sftp_source.unlink()
    source.unlink()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
