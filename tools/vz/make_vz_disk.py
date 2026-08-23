#!/usr/bin/env python3
"""Wrap the XAIOS FAT boot image in a GPT disk for Virtualization.framework.

The image the QEMU and Fusion paths use is a bare FAT filesystem with no
partition table. EDK2 under QEMU boots it because it probes the whole device
for a filesystem; Apple's firmware looks for an EFI System Partition in a GPT,
finds no partition table, and silently boots nothing.

This writes a GPT disk whose single partition is an ESP holding that same
filesystem, byte for byte, so both paths consume the same artifact.
"""

import argparse
import binascii
import pathlib
import struct
import uuid

SECTOR = 512
ENTRIES = 128
ENTRY_SIZE = 128
ENTRY_SECTORS = ENTRIES * ENTRY_SIZE // SECTOR      # 32
FIRST_USABLE = 2 + ENTRY_SECTORS                    # 34
PART_ALIGN = 2048                                   # 1 MiB
ALIGN_BYTES = 1024 * 1024                           # whole-disk rounding
ESP_TYPE = uuid.UUID("C12A7328-F81F-11D2-BA4B-00A0C93EC93B")


def gpt_header(current_lba, backup_lba, first_usable, last_usable,
               entries_lba, entries_crc, disk_guid):
    header = struct.pack(
        "<8sIIIIQQQQ16sQIII",
        b"EFI PART", 0x00010000, 92, 0, 0,
        current_lba, backup_lba, first_usable, last_usable,
        disk_guid.bytes_le, entries_lba, ENTRIES, ENTRY_SIZE, entries_crc)
    crc = binascii.crc32(header) & 0xFFFFFFFF
    header = header[:16] + struct.pack("<I", crc) + header[20:]
    # Return a whole sector. The header is 92 bytes, and assigning a short
    # value into a bytearray slice resizes the array rather than padding it,
    # which silently shortens the disk and makes the image unreadable.
    return header.ljust(SECTOR, b"\0")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", help="FAT boot filesystem image")
    parser.add_argument("output", help="GPT disk image to write")
    parser.add_argument("--slack-mib", type=int, default=8,
                        help="spare space after the partition")
    args = parser.parse_args()

    payload = pathlib.Path(args.source).read_bytes()
    if len(payload) % SECTOR:
        payload += b"\0" * (SECTOR - len(payload) % SECTOR)
    payload_sectors = len(payload) // SECTOR

    part_first = PART_ALIGN
    part_last = part_first + payload_sectors - 1
    slack = args.slack_mib * 1024 * 1024 // SECTOR
    total = part_last + 1 + slack + ENTRY_SECTORS + 1
    # Virtualization.framework refuses an image whose length is not a whole
    # number of 4 KiB pages, reporting only "format is not recognized". Round
    # the disk up before placing the backup structures, which must sit at the
    #last sectors of the file.
    align = ALIGN_BYTES // SECTOR
    total = (total + align - 1) // align * align
    backup_lba = total - 1
    last_usable = backup_lba - ENTRY_SECTORS - 1

    disk = bytearray(total * SECTOR)
    disk[part_first * SECTOR:(part_last + 1) * SECTOR] = payload

    # Protective MBR: one 0xEE partition spanning the disk, so tooling that
    # only understands MBR sees the disk as claimed rather than empty.
    mbr = bytearray(SECTOR)
    span = min(total - 1, 0xFFFFFFFF)
    mbr[446:462] = struct.pack("<BBBBBBBBII", 0x00, 0x00, 0x02, 0x00, 0xEE,
                               0xFF, 0xFF, 0xFF, 1, span)
    mbr[510:512] = b"\x55\xAA"
    disk[0:SECTOR] = mbr

    entry = struct.pack("<16s16sQQQ72s", ESP_TYPE.bytes_le,
                        uuid.uuid4().bytes_le, part_first, part_last, 0,
                        "XAIOS".encode("utf-16-le").ljust(72, b"\0"))
    entries = entry + b"\0" * (ENTRIES * ENTRY_SIZE - len(entry))
    entries_crc = binascii.crc32(entries) & 0xFFFFFFFF
    disk_guid = uuid.uuid4()

    disk[2 * SECTOR:2 * SECTOR + len(entries)] = entries
    disk[1 * SECTOR:2 * SECTOR] = gpt_header(
        1, backup_lba, FIRST_USABLE, last_usable, 2, entries_crc, disk_guid)

    backup_entries_lba = backup_lba - ENTRY_SECTORS
    disk[backup_entries_lba * SECTOR:
         backup_entries_lba * SECTOR + len(entries)] = entries
    disk[backup_lba * SECTOR:(backup_lba + 1) * SECTOR] = gpt_header(
        backup_lba, 1, FIRST_USABLE, last_usable, backup_entries_lba,
        entries_crc, disk_guid)

    pathlib.Path(args.output).write_bytes(bytes(disk))
    print(f"wrote {args.output}: {total * SECTOR // (1024 * 1024)} MiB, "
          f"ESP at LBA {part_first}-{part_last}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
