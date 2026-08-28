# GPT Partitions

Status: GPT v1 parser/writer and bounded partition device implemented and
hosted-tested. Automatic boot discovery and authenticated online partition
administration are not implemented.

XAIOS uses UEFI GPT revision 1.0 without private header extensions. Integers
are little-endian. A normal model/state disk contains:

```text
LBA 0                    protective MBR
LBA 1                    primary GPT header
LBA 2..                  primary partition-entry array
first_usable..last_usable partitions
..last LBA - 1           backup partition-entry array
last LBA                 backup GPT header
```

The writer uses 128 entries of 128 bytes. The reader validates that format,
checks the protective MBR, CRC32 of both headers and entry arrays, reciprocal
header LBAs, usable ranges, partition bounds, overlap, and unique GUIDs.
Unknown partition type GUIDs are retained and listed; they are not mounted or
modified automatically.

## XAIOS partition types

These UUIDs are stable format identifiers:

| Type | GUID | Purpose |
| --- | --- | --- |
| StateFS/xaibootFS | `1f3b2d7a-6e91-4a52-9c7d-5841494f5301` | Small mutable configuration, state, audit, and logs |
| xaiFS | `1f3b2d7a-6e91-4a52-9c7d-5841494f5302` | Large staged and immutable model packages |
| Update/recovery | `1f3b2d7a-6e91-4a52-9c7d-5841494f5303` | Explicit update or recovery storage |

The boot/root device is not inferred from these type GUIDs. Device-role and
active-mount checks remain mandatory before mutation.

## Update protocol

The entry arrays and headers have no generation field, so XAIOS uses a defined
ordering:

1. Write the complete backup entry array.
2. Write the backup header with the new array CRC.
3. Flush.
4. Write the complete primary entry array.
5. Write the primary header.
6. Flush and read both copies back.

If power fails while the backup is being replaced, the old primary remains
valid and authoritative. Once the new backup is complete, both copies can
briefly be valid but disagree; the primary remains authoritative until its
array is replaced. During the primary replacement, a checksum mismatch makes
the new backup authoritative. After the primary header is written, both copies
agree on the new layout.

The parser reports whether primary/backup copies are valid and consistent. A
single valid copy is recoverable. Repair rewrites the invalid copy only through
an explicit, offline, confirmed operation. If two copies disagree outside a
controlled update, the selected primary layout is reported with an
inconsistency warning rather than silently claiming the disk is clean.

## Alignment and bounds

Partition starts default to 1 MiB alignment expressed in device logical LBAs.
First/last LBAs and all byte translations are checked in 64-bit arithmetic.
Empty ranges, reserved GPT regions, overlaps, duplicate unique GUIDs, and any
end beyond the device are rejected.

Partition-backed block devices inherit the parent's sector geometry and
optional-operation capabilities. Their capacity is exactly the partition LBA
range. Every operation is validated against that capacity before adding the
partition byte offset; the translated range is then validated again by the
parent device.

## Mutation safety

The low-level GPT writer accepts an explicit block device, complete desired
layout, dry-run flag, and fault-injection point. It does not choose targets.
The `xaiosctl storage partition` layer must additionally enforce administrator
capability, exact UUID confirmation, current identity revalidation, unmounted
state, boot/update/active-model exclusion, and audit logging before calling it.
