# XAIOS Storage Implementation Plan

Status: all storage work that can be validated on the current hosted and QEMU
targets is implemented. Dynamic ModelFS lifecycle, recovery, scrub, free-space
reclamation and VirtIO discard are correctness-tested. Asynchronous NVMe and
physical-device durability/performance remain hardware phases, not QEMU claims.

Starting source revision: `8ddefb26f3dbc366dc4402677a156cf235daed82`.
The working tree already contained unrelated Phase 2 control-plane and network
changes when this work began. They are preserved.

## Verified starting state

- MutableFS v2/v3 is the only writable filesystem. V3 has 64 fixed nodes, 256
  512-byte data sectors, 16 inline block numbers per file, 8 open handles, and
  an 8 KiB maximum file size. It is appropriate only for small configuration,
  state, audit, and log records.
- Initramfs is a separate read-only boot image with 32 fixed entries. It is not
  a model store.
- The VirtIO block driver performs synchronous copied 512-byte operations. It
  reports a 64-bit sector count and supports flush when negotiated, but there
  is no device-independent API, discovery view, discard, write-zeroes, or
  partition boundary enforcement.
- QEMU attaches the deterministic test disk at VirtIO MMIO slot 0 and the
  MutableFS state disk at slot 1. Network and RNG occupy slots 2 and 3. Model
  storage must remain a separate image/device.
- Filesystem syscalls route through a VFS. MutableFS is the root backend and
  a signed ModelFS volume is mounted at `/models` in the AArch64 QEMU image.
  Active package files are immutable; authenticated online registration creates
  signed staging records and allocates or reuses their extents.
- SFTP v3 uses 64-bit positional read/write syscalls, loops over partial I/O,
  exposes 64-bit stat sizes, supports OpenSSH attributes/append semantics and
  the OpenSSH fsync extension. One QEMU gate runs native macOS and Debian 13
  clients concurrently through registration, upload, download, verification,
  activation, cleanup/reuse, scrub and trim/discard.
- The portable engine can open a signed ModelFS package, verify ranges, expose
  extents/prefetch hints, and stream into a caller-owned aligned arena. The
  legacy model-v1 fixture path still copies its bounded fixture; real model-v2
  execution is not integrated.
- The current acceptance suite includes generic block, GPT, VFS, SFTP, Python
  ModelFS, Python-writer/C-reader, model-file, and sparse 128 GiB volume tests.
  Exact results are established by the current run, not by this document.

## Storage architecture

```text
block_device API
  +-- VirtIO-blk backend (current)
  +-- bounded partition device
  +-- mock/file backend (host tests)
        |
        +-- GPT parser/writer
        |
        +-- MutableFS/StateFS (/config, /state, /logs)
        +-- ModelFS (/models and /models/.staging)
                 |
                 +-- VFS mount routing and 64-bit handles
                 +-- SFTP and model_file streaming APIs
```

The root/initramfs namespace remains read-only. MutableFS remains compatible
and stores only bounded state. ModelFS is architecture-neutral: it stores
signed immutable package objects and does not interpret Qwen, Kimi, tensor, or
backend semantics.

## Block-device invariants

- Device identity is explicit and stable for the boot. No mutating API selects
  the first device implicitly.
- Capacity, offsets, sector counts, byte counts, and statistics are 64-bit.
- Byte-to-sector and sector-to-byte conversion uses checked arithmetic.
- Public read/write/discard ranges must fit entirely inside the device and obey
  the reported logical-sector alignment.
- A partition device applies the same checks after translating through its
  bounded start LBA. A corrupt caller cannot escape the partition.
- Flush, discard, and write-zeroes return `unsupported` when the backend did
  not advertise them. Unsupported discard never changes data.
- Discard/write-zeroes requests obey device granularity and alignment and are
  split at the advertised maximum without wrapping.
- The initial VirtIO implementation remains synchronous. Queue-based NVMe and
  asynchronous model reads are later backend work, not implied by this API.

## GPT strategy

XAIOS uses standard GPT with a protective MBR, primary and backup headers, and
CRC32-verified entry arrays. On-disk integers are little-endian. The default
partition alignment is 1 MiB. Both header copies describe the same disk GUID,
usable LBA range, and entry array.

Stable XAIOS partition type GUIDs are defined in `docs/GPT-PARTITIONS.md` and
must not be reused for another purpose. Unknown type GUIDs are listed read-only.
Mutation writes the backup entry array/header first, flushes, then writes the
primary array/header and flushes. Recovery accepts exactly one valid copy and
can reconstruct the invalid copy only through an explicit repair operation.
Overlaps, duplicate unique GUIDs, reserved-LBA use, arithmetic overflow, and
out-of-device extents are rejected.

## VFS contract

The VFS owns mount routing and file handles. Backends implement 64-bit
`pread`, `pwrite`, truncate, allocation, fsync, stat, statfs, directories, and
same-filesystem atomic rename where supported. MutableFS compatibility calls
route to the existing backend. `/models` routes to ModelFS. Cross-filesystem
rename is rejected. Paths are absolute, case-sensitive UTF-8 without NUL;
`.` is normalized and `..` may not escape a mount root. Initial limits are a
255-byte component, 1,024-byte path, and 32 components. Symlinks are not
supported.

Handles carry the mount generation. Unmount refuses live handles; a stale
generation cannot access a remounted backend. Each handle has an independent
cursor, while positional I/O never changes it. Partial I/O is returned to the
caller and never converted silently into success.

## ModelFS v1 format and invariants

The canonical byte layout is specified in `docs/MODELFS-FORMAT.md`;
`docs/MODEL-VOLUME.md` provides the implementation overview. ModelFS v1 uses:

- little-endian 4 KiB metadata blocks;
- two independently SHA-256-checksummed superblocks;
- monotonically increasing 64-bit generations;
- copy-on-write catalog snapshots selected by a superblock switch;
- 64-bit package, logical, physical, extent, count, and volume fields;
- 2-16 MiB independently SHA-256-verifiable data chunks;
- aligned raw extents, sparse-zero extents, staging and active states;
- package identities derived from model UUID, source revision, target layout,
  logical manifest, and chunk digests;
- Ed25519 signatures over package identity;
- explicit free extents and immutable active package data.

The format field maximum is below 2^64 bytes after alignment. A 128 GiB sparse
volume containing a logical package above 100 GiB passes both the Python path
and the portable C reader at offsets above 100 GiB. This proves metadata width,
range validation, and bounded read memory; it is not a physical 100 GiB write
or throughput test.

The namespace is specialized rather than general POSIX storage:

```text
/models/<active-package-id>       immutable package object
/models/.staging/<package-id>     resumable staging object
```

Directory entries are generated from the catalog. Package data is extent based
and never stored in a fixed inline block array. Metadata memory may scale with
the number of objects/chunks, but no buffer scales with package byte size.

## Crash consistency

Data chunks are written and flushed before a catalog marks them complete. A
new catalog snapshot is written and flushed before its alternate superblock is
published and flushed. Mount selects the highest generation whose superblock,
catalog, package identities, and structural invariants all validate. A failure
before the final superblock switch exposes the previous generation; a failure
after it exposes the new complete generation. Orphan snapshots/extents are
reclaimable but never treated as committed data.

Activation is a metadata-only generation change after all chunks, package
identity, and signature validate. It is never a partial directory rename.
Resize is grow-only and uses the same generation switch. Shrink returns
`shrink_not_supported`.

## Integrity and recovery

- GPT and fast structural fields use CRC32/CRC32C as documented per format.
- ModelFS metadata uses an independently verified cryptographic checksum in v1.
- Model chunks use SHA-256 from the signed package manifest.
- Ed25519 establishes package-manifest authenticity; a checksum alone does not.
- Corrupt packages are quarantined and cannot activate or load. Reports name
  object and chunk identifiers, never model bytes.
- Fsck defaults to read-only. Repair requires an unmounted target, an explicit
  deterministic plan, administrator authorization, and UUID confirmation.
- Structural metadata can be recovered from a valid redundant copy. Weight
  bytes cannot be invented. Data repair requires a separately trusted replica
  or source and is not part of ModelFS v1.

## Destructive-operation protections

Every partition, format, repair, resize, and manual trim mutation must:

1. Require its specific storage capability and authenticated administrator.
2. Require an exact device/partition identifier and target UUID confirmation.
3. Reject empty, ambiguous, stale, mounted, boot/root, update/rollback, and
   active-model targets.
4. Produce a dry-run/plan without writes and support stable JSON output.
5. Re-read and revalidate target identity immediately before the first write.
6. Flush and read back critical metadata before reporting success.
7. Emit an audit record with principal, operation, UUID, request ID, result,
   and byte/range counts. Model content and secrets are never logged.

There is no generic force switch that bypasses boot-device protection.

## Compatibility and migration

- MutableFS v2/v3 remains mounted for small state. Its bytes are never
  interpreted as ModelFS.
- ModelFS uses a separate GPT partition and normally a separate QEMU block
  image. Existing boot and state images remain valid.
- Model weights cannot be migrated from MutableFS because its format cannot
  contain them. Small state migration, if needed, is an explicit offline tool.
- Unknown required ModelFS feature bits prevent read-write mount. A compatible
  reader may mount older supported versions read-only.
- Format upgrades require a new documented version and fault-injected migration
  tests. No in-place reinterpretation is permitted.

## Implementation phases and acceptance gates

| Phase | Status | Gate |
| --- | --- | --- |
| 1. Generic block API | Complete (hosted + QEMU correctness) | 64-bit mock I/O above 4 GiB, overflow checks, flush/discard/write-zeroes capability tests, safe splitting, unsupported behavior, and VirtIO discovery passed |
| 2. GPT partitions | Complete (hosted + QEMU administration) | Primary/backup parsing and writing, CRC/overlap/GUID rejection, dry-run, fault points, 512/4096 sectors, bounded partition I/O, explicit confirmation and replay-protected online plan/mutation operations pass. |
| 3. VFS and 64-bit file API | Complete, core + QEMU mount | MutableFS compatibility, longest-prefix mounts, owner/generation handles, positional I/O above 4 GiB, immutable active-package routing and bounded staging writes pass. The mount table remains boot-time bounded. |
| 4. ModelFS v1 | Complete for current format scope | Signed C/Python parsing, COW lifecycle, sparse 128 GiB volume, >100 GiB logical package, corruption/recovery, dynamic guest registration, staging cleanup, free-extent reuse, immutable activation and QEMU verified reads/writes pass. |
| 5. Format/mount/usage/grow tools | Complete for hosted + QEMU scope | Hosted and guest format, mount/unmount, discovery, usage and grow-only resize use typed plans/results, target confirmation and replay-protected audit. Native macOS and Debian 13 OpenSSH gates validate the live `/dev/vblk4` and `/models` inventory. |
| 6. Fsck/repair | Complete for structural recovery | Read-only fsck and explicit redundant-superblock repair exist in hosted and guest administration paths. Damaged weight bytes remain unrepairable without a trusted source, by design. |
| 7. Scrub | Complete for current QEMU scope | Full signed-manifest/chunk scrub, persistent progress, generation/UUID pinning, pause/resume/cancel, cooperative one-chunk work units, exact corruption offsets and atomic quarantine pass. Scrub yields between units so reads continue. |
| 8. TRIM/discard | Complete for hosted + QEMU scope | Free-only plans, dry-run, range validation, alignment/splitting, persisted progress/cancellation and unsupported behavior pass. Linux block/file backends and negotiated QEMU VirtIO discard are exercised; physical SSD behavior is unclaimed. |
| 9. Large SFTP | Complete for QEMU-testable scope | Packet tests cover >4 GiB offsets, partial I/O, fsync, 64-bit stat, malformed ranges, 32 KiB OpenSSH writes and append semantics. One VM passes concurrent macOS/Debian 13 dynamic registration, resumable upload/download, byte comparison, cleanup/reuse, activation, scrub and discard. A physical 100+ GiB transfer remains a hardware validation task. |
| 10. Model loader | Portable hosted boundary complete | Signed open, verified ranged reads, extent maps, prefetch callbacks, aligned caller-owned arena reads, metrics, and >100 GiB offsets pass. Model-v2 admission/execution wiring remains pending. |

Phase status changes only after its tests run. QEMU evidence proves emulated
correctness and ABI behavior, not physical disk performance. Hardware storage
flush guarantees, discard behavior, failure recovery and throughput remain
unknown until tested on named physical systems.
