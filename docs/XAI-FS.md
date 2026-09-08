# XAIOS xaiFS volume v1

Status: v1 is implemented in the hosted writer/administrator and portable C
reader/writer, with dynamic signed staging, cleanup/reuse, immutable active
reads, scrub/quarantine and trim validated under QEMU. The canonical byte layout is
[`MODELFS-FORMAT.md`](./MODELFS-FORMAT.md).

The format is separate from xaibootFS and from `xaios.model.v2`. A xaiFS volume
stores one or more immutable model package objects; xaibootFS stores only small
control records.

## What this document covers

The byte layout — superblocks, catalog snapshots, package and chunk records,
and the canonical manifest the package identity is hashed over — is specified
once, in [`MODELFS-FORMAT.md`](./MODELFS-FORMAT.md). It used to be written out
here as well, and the two copies had already drifted into naming different
chunk-size limits. This document is the layer above: how a volume is used, in
what order, and by which interfaces.

Two properties from the format are worth restating because the rules below
depend on them. A catalog is immutable once published, so every mutation is a
new snapshot and a superblock switch rather than an edit. And package states
are `staging`, `active` and `quarantined`: active bytes never change, and a
quarantined package can neither activate nor return data.

## Lifecycle and ordering

`xaios_xai_fs_register_staging` validates the signed logical manifest,
allocates aligned physical extents, writes a staging catalog, flushes it, then
publishes the alternate superblock and flushes again.
`xaios_xai_fs_pwrite_staging` accepts staged bytes and
`xaios_xai_fs_commit_staging_range` verifies a completed chunk's checksum
before publication and records the completion in a new catalog snapshot.
Reopening the volume resumes from the last published chunk bitmap.

`xaios_xai_fs_verify_package` rereads every physical chunk, verifies all
hashes, recomputes the package identity and verifies the Ed25519 signature.
`xaios_xai_fs_activate_staging` publishes a new catalog containing the active
state; the previous superblock remains a valid pre-activation recovery point
until a later transaction. A failure before the final superblock flush leaves
the old catalog authoritative — which is the whole reason the order is
catalog, flush, superblock, flush and not something shorter.

The kernel exposes the same commit and activation path through xaiFS.
Administrator-only registration creates a signed staging record and allocates
or reuses aligned extents. SFTP `stat` reports the contiguous committed prefix,
so OpenSSH `reput` resumes at a verified chunk boundary. `xaiosctl model
verify`, cleanup and replay-protected activation are administrator-only; active
package files never accept writes.

`xaios_xai_fs_remove_staging`, `xaios_xai_fs_remove_quarantined` and staging
garbage collection remove catalog references and return payload extents to a
coalesced free list. Old catalog snapshots are append-only recovery metadata
and are not reused by format v1.

## I/O API

The portable boundary is `engine/include/xaios_engine/xai_fs.h`. Every entry
point is prefixed `xaios_xai_fs_` and returns `xaios_engine_status_t`:

| Group | Operations |
|---|---|
| Volume | `format`, `probe`, `open`, `grow`, `repair_superblock` |
| Staging | `register_staging`, `pwrite_staging`, `commit_staging_range`, `activate_staging`, `remove_staging` |
| Integrity | `verify_package`, `verify_package_manifest`, `verify_range`, `quarantine_package`, `remove_quarantined`, `repair_from_replica` |
| Reading | `pread`, `pread_verified`, `read_package`, `read_chunk` |

Kernel reads use a 64-bit positional block callback; hosted files use `pread`,
`pwrite` and `fsync`. The QEMU VirtIO adapter has an interrupt-dispatched
eight-request queue with direct-or-bounce DMA, event-index suppression and
indirect descriptors. The focused emulated-NVMe gate validates admin/I/O queue
and write/flush/read correctness. These remain QEMU format, ABI and
device-contract checks — not production storage throughput, physical
durability, or zero-copy performance evidence.

The portable `model_file` boundary in
`engine/include/xaios_engine/model_file.h` adds signed package open, verified
ranged reads, extent enumeration, prefetch callbacks, aligned caller-owned
arena reads, and storage metrics. It never allocates memory proportional to the
package size.

## Stability and migration

Migration rules are part of the format and are stated in
[`MODELFS-FORMAT.md`](./MODELFS-FORMAT.md). What belongs here is the
consequence for callers: format v1 deliberately provides no in-place mutable
package metadata, no database rows, no fixed per-file block arrays, and no
weight payloads in xaibootFS. A caller that wants any of those is asking for a
different format, not a newer minor version of this one.
