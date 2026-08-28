#!/usr/bin/env python3
"""Write a GUID partition table onto a disk image.

Used by scripts/make-installed-disk.sh to produce the disk an installed
machine has. The partition types are the ones kernel/storage/gpt.c declares,
because the kernel finds its durable volume by partition type rather than by
position -- on an installed machine nothing tells it where to look.

The protective MBR matters as much as the table: firmware that finds a disk
with no MBR at all may decline to look further, and one that finds a real MBR
partition table may act on it. A single 0xEE entry spanning the disk is what
says "this disk is GPT, do not interpret this record".
"""

from __future__ import annotations

import binascii
import os
import struct
import sys
import uuid

SECTOR = 512
ESP_TYPE = uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")
# Byte-for-byte XAIOS_GPT_TYPE_STATEFS in kernel/storage/gpt.c. Written big-
# endian here and converted with bytes_le below so the two representations of
# the same GUID cannot drift apart silently.
STATEFS_TYPE = uuid.UUID("1f3b2d7a-6e91-4a52-9c7d-5841494f5301")
ENTRY_SIZE = 128
ENTRY_COUNT = 128
TABLE_SECTORS = ENTRY_COUNT * ENTRY_SIZE // SECTOR


def entry(type_guid: uuid.UUID, unique: uuid.UUID, first: int, last: int,
          name: str) -> bytes:
    label = name.encode("utf-16-le")[:70].ljust(72, b"\0")
    return (type_guid.bytes_le + unique.bytes_le +
            struct.pack("<QQQ", first, last, 0) + label)


def header(current: int, backup: int, table_lba: int, first_usable: int,
           last_usable: int, disk_guid: uuid.UUID, table: bytes) -> bytes:
    fields = struct.pack(
        "<8sIIIIQQQQ16sQIII",
        b"EFI PART", 0x00010000, 92, 0, 0,
        current, backup, first_usable, last_usable,
        disk_guid.bytes_le, table_lba, ENTRY_COUNT, ENTRY_SIZE,
        binascii.crc32(table) & 0xFFFFFFFF)
    return fields[:16] + struct.pack("<I", binascii.crc32(fields)
                                     & 0xFFFFFFFF) + fields[20:]


def main() -> int:
    path = os.environ["XAIOS_GPT_DISK"]
    sectors = int(os.environ["XAIOS_GPT_SECTORS"])
    esp = (int(os.environ["XAIOS_GPT_ESP_FIRST"]),
           int(os.environ["XAIOS_GPT_ESP_LAST"]))
    state = (int(os.environ["XAIOS_GPT_STATE_FIRST"]),
             int(os.environ["XAIOS_GPT_STATE_LAST"]))

    first_usable = 2 + TABLE_SECTORS
    last_usable = sectors - 2 - TABLE_SECTORS
    if esp[0] < first_usable or state[1] > last_usable:
        print("xaios_write_gpt: partitions fall outside the usable range",
              file=sys.stderr)
        return 1

    # Deterministic identifiers: two runs of this script on the same inputs
    # produce the same disk, which is what lets a gate compare them.
    disk_guid = uuid.UUID("58414f53-0001-4000-8000-000000000000")
    table = (entry(ESP_TYPE, uuid.UUID("58414f53-0002-4000-8000-000000000000"),
                   esp[0], esp[1], "XAIOS ESP") +
             entry(STATEFS_TYPE,
                   uuid.UUID("58414f53-0003-4000-8000-000000000000"),
                   state[0], state[1], "xaibootFS"))
    table = table.ljust(ENTRY_COUNT * ENTRY_SIZE, b"\0")

    primary = header(1, sectors - 1, 2, first_usable, last_usable, disk_guid,
                     table)
    backup = header(sectors - 1, 1, last_usable + 1, first_usable, last_usable,
                    disk_guid, table)

    # Protective MBR. The 0xEE entry spans the disk, clamped as the spec
    # requires on a disk with more sectors than the field can hold.
    span = min(sectors - 1, 0xFFFFFFFF)
    mbr = bytearray(SECTOR)
    mbr[446:462] = struct.pack("<BBBBBBBBII", 0x00, 0x00, 0x02, 0x00, 0xEE,
                               0xFF, 0xFF, 0xFF, 1, span)
    mbr[510:512] = b"\x55\xaa"

    with open(path, "r+b") as disk:
        disk.seek(0)
        disk.write(bytes(mbr))
        disk.seek(SECTOR)
        disk.write(primary.ljust(SECTOR, b"\0"))
        disk.seek(2 * SECTOR)
        disk.write(table)
        disk.seek((last_usable + 1) * SECTOR)
        disk.write(table)
        disk.seek((sectors - 1) * SECTOR)
        disk.write(backup.ljust(SECTOR, b"\0"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
