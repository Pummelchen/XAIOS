# XAIOS xaiFS volume v1

Status: v1 is implemented in the hosted writer/administrator and portable C
reader/writer, with dynamic signed staging, cleanup/reuse, immutable active
reads, scrub/quarantine and trim validated under QEMU. The canonical byte layout is
[`MODELFS-FORMAT.md`](./MODELFS-FORMAT.md).

The format is separate from xaibootFS and from `xaios.model.v2`. A xaiFS volume
stores one or more immutable model package objects; xaibootFS stores only small
control records.

## Byte order and addressing

All integers are unsigned little-endian. All offsets, lengths, generations,
record counts and logical block addresses are 64-bit. The volume block size is
4096 bytes. Package chunk size is selected when the volume is formatted and
must be a power of two from 2 MiB through 16 MiB.

Every addition, multiplication and range check is performed before I/O. A
volume implementation must reject an extent that wraps, exceeds the declared
volume size, overlaps reserved metadata, or is not 4 KiB aligned.

## Redundant superblocks

Superblocks occupy bytes `0..4095` and `4096..8191`. Each uses this fixed
layout; unused bytes are zero.

| Offset | Size | Field |
|---:|---:|---|
| 0 | 8 | Magic `XAIOSV1\0` |
| 8 | 2 | Major version, `1` |
| 10 | 2 | Minor version, `0` |
| 12 | 1 | Endianness, `1` for little-endian |
| 13 | 1 | Hash algorithm, `1` for SHA-256 |
| 14 | 2 | Flags |
| 16 | 8 | Header size, `4096` |
| 24 | 8 | Block size, `4096` |
| 32 | 8 | Chunk size |
| 40 | 8 | Declared volume size |
| 48 | 8 | Superblock generation |
| 56 | 8 | Active catalog offset |
| 64 | 8 | Active catalog length |
| 72 | 8 | Catalog generation |
| 80 | 8 | Append allocator tail |
| 88 | 16 | Volume UUID |
| 104 | 32 | SHA-256 of the complete catalog blob |
| 136 | 32 | Superblock SHA-256 with this field zeroed |
| 168 | 3928 | Reserved, zero |

Readers validate both copies and select the valid copy with the greatest
generation. Equal generations must describe the same catalog. The older valid
copy is the recovery point if a new catalog or superblock is corrupt.

## Catalog snapshots

A catalog is immutable after publication. Catalogs and payload extents never
overlap. Each catalog contains a 256-byte header, fixed 384-byte package
records, fixed 128-byte chunk records, and an optional canonical extension
area. The superblock hashes the complete catalog, including physical extent
placement.

Package states are `staging`, `active` and `quarantined`. Active package bytes
are immutable; quarantined packages cannot activate or return data.
Package records contain a record ID, model UUID, package identity,
architecture ID, portable/backend target, source revision, logical size,
chunk range, Ed25519 signer public key and signature. A package can be active
only after every non-zero chunk has been written and verified.

Chunk records contain the owning record ID, logical offset, physical offset,
length, flags and SHA-256. Chunks cover the logical package exactly with no
gaps or overlap. A sparse-zero chunk has no physical extent and reads as zero;
its checksum is still the SHA-256 of its logical zero bytes. This permits CI to
exercise a logical 100 GB package without writing 100 GB.

The package identity is SHA-256 over the canonical logical manifest:

```text
domain = "xaios.model.volume.package.v1\0"
model UUID
source revision
architecture ID padded to 32 bytes
target ID padded to 32 bytes
logical size
chunk size
for every chunk in logical order:
    logical offset, length, logical flags, chunk SHA-256
```

Physical offsets and staging state are excluded, so copying or compacting a
package does not change its identity. Ed25519 signs the 32-byte package
identity. Both the hosted tooling and QEMU fixture builder require a valid
signature; unsigned package records are rejected.

## Lifecycle and ordering

`xai_fs_stage_begin` validates the signed logical manifest, allocates
aligned physical extents, writes a staging catalog, flushes it, then publishes
the alternate superblock and flushes again. `xai_fs_pwrite` accepts one
complete expected chunk, verifies its checksum before publication and records
completion in a new catalog snapshot. Reopening the volume resumes from the
last published chunk bitmap.

`xai_fs_stage_verify` rereads every physical chunk, verifies all hashes,
recomputes package identity and verifies the Ed25519 signature.
`xai_fs_activate` publishes a new catalog containing the active state;
the previous superblock remains a valid pre-activation recovery point until a
later transaction. A failure before the final superblock flush leaves the old
catalog authoritative.

The kernel exposes the same C commit and activation path through xaiFS.
Administrator-only registration creates a signed staging record and allocates
or reuses aligned extents. SFTP `stat` reports the contiguous committed prefix
so OpenSSH `reput` resumes at a verified chunk boundary. `xaiosctl model verify`,
cleanup and replay-protected activation are administrator-only; active package
files never accept writes.

`xai_fs_remove` and staging garbage collection remove catalog references
and return payload extents to a coalesced free list. Old catalog snapshots are
append-only recovery metadata and are not reused by format v1.

## I/O API

The portable boundary provides operations equivalent to:

```c
xai_fs_open(...)
xai_fs_stage_begin(...)
xai_fs_pwrite(...)
xai_fs_pread(...)
xai_fs_stage_verify(...)
xai_fs_activate(...)
xai_fs_remove(...)
xai_fs_extent_map(...)
xai_fs_prefetch(...)
xai_fs_sync(...)
xai_fs_recover(...)
```

Kernel reads use a 64-bit positional block callback. Hosted files use
`pread`, `pwrite`, and `fsync`. The QEMU VirtIO adapter has an
interrupt-dispatched eight-request queue with direct-or-bounce DMA,
event-index suppression and indirect descriptors. The focused emulated-NVMe
gate validates admin/I/O queue and write/flush/read correctness. These remain
QEMU format/ABI/device-contract checks, not production storage throughput,
physical durability, or zero-copy performance evidence.

The portable `model_file` boundary in
`engine/include/xaios_engine/model_file.h` adds signed package open, verified
ranged reads, extent enumeration, prefetch callbacks, aligned caller-owned
arena reads, and storage metrics. It never allocates memory proportional to the
package size.

## Stability and migration

Readers reject unknown major versions. A minor version may add only fields in
reserved or length-delimited extension space. Incompatible descriptor changes
require a new major version and an explicit streaming migration tool. The
source package identity and signature must survive migration unchanged unless
the logical package bytes change.

Format v1 deliberately does not provide in-place mutable package metadata,
database rows, fixed per-file block arrays, or weight payloads in xaibootFS.
