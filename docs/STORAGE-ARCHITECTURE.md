# Storage Architecture

Status: the hosted and QEMU-testable storage path is implemented, including
dynamic online ModelFS lifecycle, persisted scrub and free-space trim. Physical
device validation and asynchronous hardware queues remain pending.

## Layers

```text
userspace filesystem syscalls and SFTP
                 |
                 v
VFS: path routing, owner-scoped handles, 64-bit positional I/O
        |                              |
        v                              v
MutableFS root                    ModelFS /models
small state                       immutable active + bounded staging
                                       |
                                       v
portable model_volume/model_file reader
                                       |
                                       v
block_device API -> partition device -> VirtIO-blk or hosted backend
```

GPT is the standard partition-map layer between whole devices and bounded
partition devices. The QEMU image currently supplies ModelFS as a dedicated
VirtIO device at slot 4 instead of discovering it through GPT. That preserves
the existing state disk and makes the current boot contract deterministic.

## Ownership boundaries

The kernel owns device discovery, validated byte ranges, mount routing, handle
ownership, immutable active-package reads, staging writes, authenticated
registration/cleanup, lifecycle administration, scrub and trim policy. The
portable engine owns package parsing, signature/hash validation, transactional
catalog publication, extent allocation/reuse, prefetch hints, quarantine, and
streaming into caller-owned arenas. The hosted Python tool owns offline volume
creation and administration.

ModelFS does not parse tensors or identify a model architecture beyond signed
package metadata. `xaios.model.v2` remains the model package format, while
ModelFS is the placement and lifecycle container.

## Current guarantees

- Block and file offsets, lengths, capacities, generations, and counts use
  unsigned 64-bit fields with checked range translation.
- Device and partition I/O rejects wrapping, unaligned, empty, and out-of-range
  requests before backend dispatch.
- VFS paths are absolute, UTF-8 validated, component-bounded, and cannot use
  `..` to escape a mount. Longest-component mount matching prevents `/models2`
  from being mistaken for `/models`.
- VFS handles are scoped by owner and mount generation. Positional I/O does not
  change the per-handle cursor.
- Active ModelFS packages are immutable. Opening a package verifies its signed
  manifest; every read verifies all touched chunks before returning bytes.
- A signed staging record created by authenticated online registration accepts
  only the package ID, logical length and content authorized by its signature.
  Completed chunk data and each copy-on-write catalog/superblock generation are
  flushed before the committed prefix becomes visible to SFTP resume.
- Administrator-only `xaiosctl model verify` and replay-protected `model
  activate` revalidate complete package contents. Activation is a metadata-only
  generation switch and is recorded in the control audit log.
- Incomplete staging cleanup is a copy-on-write catalog mutation. Its physical
  extents become coalesced free records and can be reused by later registration.
- Online scrub pins the volume UUID and catalog generation, persists progress,
  processes one chunk per cooperative step, and supports status, pause, resume
  and cancel. Corruption reports the package and logical offset before an atomic
  quarantine publication.
- Online trim is restricted to catalog-owned free extents, obeys device discard
  alignment/granularity, flushes first, persists progress, and supports dry-run,
  status and cancel. Unsupported discard fails explicitly.
- The portable loader uses caller-provided scratch and destination memory. Its
  memory requirement is bounded by metadata and chunk verification, not model
  byte size.

## Current limits

- The block registry is bounded to 32 boot-time devices, the VFS to its
  compile-time mount/handle counts, and MutableFS remains suitable only for
  small state.
- The QEMU VirtIO path is interrupt-dispatched with eight request slots,
  direct-or-bounce DMA, event-index suppression and indirect descriptors. The
  AArch64/x86_64 emulated-NVMe gate negotiates four I/O queues and verifies
  four-page PRP 16 KiB transfers through every queue. Async block integration,
  SGL, MSI-X affinity, cancellation and physical durability remain open; QEMU
  is not throughput evidence.
- Registration accepts the bounded signed identity fields defined by
  `xaios.control.v1`; it is not a general JSON manifest parser. Package payloads
  still arrive through SFTP after allocation.
- Device, GPT and filesystem administration is exposed through typed,
  capability-gated `xaiosctl` operations. Boot/root/update target protection and
  exact UUID confirmation remain mandatory for destructive operations.
- Scrub is cooperatively throttled at one chunk per control step rather than by
  an autonomous worker. Writes and metadata mutation are rejected while scrub
  or trim is active; reads continue between work units.
- The current allocator reuses a sufficiently large coalesced free extent. It
  does not compact old catalog snapshots or move active package data.
- ModelFS activation and MutableFS audit persistence are not one distributed
  transaction. An audit failure after publication is logged but cannot revert
  an already durable ModelFS generation.

See [the canonical project tracker](../wiki/Project-Tracker.md) for phase status
and [storage security](./STORAGE-SECURITY.md) for mutation policy.
