# ModelFS v1 Format

Status: implemented by `tools/xaios_model_volume.py` and parsed by
`engine/src/model_volume.c`. This document is the canonical v1 byte contract.

## Common rules

- All integers are unsigned little-endian.
- Metadata and physical payload extents are 4 KiB aligned.
- Chunk size is one power of two from 2 MiB through 16 MiB.
- Every reserved byte is zero and every range is checked before I/O.
- Offsets, lengths, counts, logical sizes, and generations are 64-bit.
- Hash algorithm ID 1 is SHA-256. Package signatures are Ed25519 over the
  32-byte package identity.

## Superblocks

Two 4 KiB superblocks occupy offsets 0 and 4096. A reader validates both and
selects the highest valid generation. Equal generations must identify the same
catalog.

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 8 | `XAIOSV1\0` magic |
| 8 | 2 | major version, 1 |
| 10 | 2 | minor version, 0 |
| 12 | 1 | little-endian ID, 1 |
| 13 | 1 | SHA-256 ID, 1 |
| 14 | 2 | flags, zero |
| 16 | 8 | superblock size, 4096 |
| 24 | 8 | block size, 4096 |
| 32 | 8 | package chunk size |
| 40 | 8 | declared volume size |
| 48 | 8 | superblock generation |
| 56 | 8 | active catalog offset |
| 64 | 8 | active catalog length |
| 72 | 8 | catalog generation |
| 80 | 8 | append allocator tail |
| 88 | 16 | volume UUID |
| 104 | 32 | SHA-256 of the complete catalog |
| 136 | 32 | SHA-256 of the superblock with this field zeroed |
| 168 | 3928 | reserved, zero |

## Catalog

A catalog is an immutable generation snapshot. It begins with a 256-byte
header, followed by 384-byte package records and 128-byte chunk records.

Catalog header fields are: magic `XAICAT1\0`; version/endianness/hash IDs;
header size and generation; volume UUID; package record size/count; chunk
record size/count; package and chunk offsets; catalog length; extension length
(zero); allocator tail; free-extent count; reserved feature field (zero); and a
SHA-256 of the 256-byte header with its checksum field at bytes 144..175 zeroed.
Bytes 176..255 are reserved and zero.

## Package record

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 4 | state: staging 1, active 2, quarantined 3 |
| 4 | 4 | flags, zero |
| 8 | 8 | nonzero record ID |
| 16 | 16 | model UUID |
| 32 | 32 | package identity |
| 64 | 32 | signer public key |
| 96 | 64 | Ed25519 signature |
| 160 | 32 | source revision identity |
| 192 | 8 | logical size |
| 200 | 8 | chunk size |
| 208 | 8 | first chunk-record index |
| 216 | 8 | chunk-record count |
| 224 | 32 | zero-padded ASCII architecture ID |
| 256 | 32 | zero-padded ASCII target layout ID |
| 288 | 96 | reserved, zero |

Target IDs currently accepted are `portable`, `apple-neon`,
`apple-accelerate`, `intel-avx2`, `intel-avx512-vnni`, and `intel-amx`. An
accepted target ID records layout intent; it does not prove the backend exists.

## Chunk record

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 8 | owner record ID, or zero for a free extent |
| 8 | 8 | logical offset |
| 16 | 8 | physical offset, zero for sparse-zero chunks |
| 24 | 8 | logical length |
| 32 | 4 | flags: complete 1, sparse zero 2, free 4, hash pending 8 |
| 36 | 4 | reserved, zero |
| 40 | 32 | SHA-256 of logical chunk bytes |
| 72 | 8 | allocated physical extent length |
| 80 | 48 | reserved, zero |

Owned chunks exactly cover a package from offset zero without gaps or overlap.
Physical extents do not overlap metadata, catalogs, or each other. Sparse-zero
chunks are complete, have no physical extent, and retain the hash of their
logical zeros. Free extents have no owner or checksum. A dynamically registered
staging chunk starts with `hash pending`, an all-zero digest and an allocated
physical extent. A full contiguous write is flushed and hashed before a COW
catalog replaces `hash pending` with `complete` and stores the digest. Pending
chunks are never readable as verified content and prevent activation.

## Package identity

Package identity is SHA-256 over the domain
`xaios.model.volume.package.v1\0`, model UUID, source revision, padded
architecture and target IDs, logical size, chunk size, then each ordered
logical chunk's offset, length, logical flags, and SHA-256. Physical placement
and lifecycle state are excluded.

## Compatibility

Readers reject unknown major/minor versions, nonzero feature/reserved fields,
unknown target IDs, invalid signatures, duplicate IDs, multiple active packages
for one model UUID, and every structural or arithmetic inconsistency. Any
incompatible format change requires a new major version and migration tool.
