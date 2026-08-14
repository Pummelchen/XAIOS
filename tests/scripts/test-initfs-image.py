#!/usr/bin/env python3
"""Verify that create-initfs materializes the sector-aligned image it declares."""

from __future__ import annotations

import pathlib
import struct
import subprocess
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[2]
SECTOR_SIZE = 512
HEADER_OFFSET = SECTOR_SIZE
# magic[16], six uint32 fields, data_offset[uint64], image_size[uint64]
IMAGE_SIZE_OFFSET = HEADER_OFFSET + 48


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="xaios-initfs-") as temporary:
        root = pathlib.Path(temporary)
        image = root / "initfs.img"
        image.write_bytes(b"\0" * 4096)
        inputs = []
        for name, content in (
            ("init.elf", b"init"),
            ("service-manager.elf", b"manager"),
            ("worker.elf", b"worker"),
            ("xaios-init.conf", b"service=/init\n"),
            ("source-index.svc", b"source=/init\n"),
            ("large-app", b"x" * 1301),
        ):
            path = root / name
            path.write_bytes(content)
            inputs.append(path)
        command = [
            sys.executable,
            str(ROOT / "scripts/create-initfs.py"),
            str(image),
            *(str(path) for path in inputs[:5]),
            f"/bin/large-app={inputs[5]}",
        ]
        subprocess.run(command, check=True)

        data = image.read_bytes()
        declared_size = struct.unpack_from("<Q", data, IMAGE_SIZE_OFFSET)[0]
        if len(data) != declared_size:
            raise SystemExit(
                f"initfs size mismatch: file={len(data)} declared={declared_size}"
            )
        if len(data) % SECTOR_SIZE:
            raise SystemExit(f"initfs is not sector aligned: {len(data)} bytes")
        if data[-1] != 0:
            raise SystemExit("initfs alignment padding was not zero-filled")
    print("initfs-image: declared size and on-disk size are sector aligned")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
