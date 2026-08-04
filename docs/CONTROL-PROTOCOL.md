# Control Protocol

`xaios.control.v1` is the bounded internal request/response ABI behind
`xaiosctl`. Kernel definitions live in
`kernel/include/xaios/control_protocol.h`; the freestanding userspace mirror is
`userspace/include/xaios_control.h`. Compile-time assertions freeze the request
header at 48 bytes and the response header at 40 bytes.

## Framing

The protocol uses native little-endian fixed-width fields on the current
AArch64 ABI. Cross-machine cluster transport is not defined by this ABI and
will require its own explicit wire encoding.

Request headers contain magic `0x58414350`, version `1`, header size,
operation, flags, payload type, 64-bit request ID, requested role, node ID,
timeout and payload length. Responses carry matching identity fields, stable
status, request ID, payload type and length. Requests are limited to 512 bytes
and responses to 8,192 bytes. All length arithmetic is bounds-checked.

## Operations and access

| Operation | Code | Minimum role | Typed response |
|---|---:|---|---|
| `version` | 1 | observer | Build/commit and ABI/package versions. |
| `status` | 2 | observer | Measured node and service state. |
| `health` | 3 | observer | Liveness/readiness and fatal indicator. |
| `capabilities` | 4 | observer | Available, fixture, interface and unsupported features. |
| `hardware` | 5 | observer | Discovered topology/memory and explicit unknown ISA fields. |
| `metrics` | 6 | observer | Measured counters plus unknown future service metrics. |
| `logs` | 7 | observer | Cursor metadata and bounded structured text records. |
| `config show` | 8 | observer | Active typed config and generation. |
| `config validate` | 9 | observer | Parsed candidate and change mask. |
| `config diff` | 10 | observer | Parsed candidate and change mask. |
| `config apply` | 11 | operator | Applied generation and change mask. |
| `auth key list` | 12 | observer | Active key metadata and revocation count. |
| `auth key add` | 13 | administrator | Added principal, role and fingerprint. |
| `auth key remove` | 14 | administrator | Removed/revoked key metadata. |
| `auth host-key rotate` | 15 | administrator | Mutation result; never key bytes. |
| `audit show` | 16 | observer | Cursor metadata and bounded audit records. |
| `model verify` | 17 | administrator | Revalidated signed staging metadata and every uploaded chunk. |
| `model activate` | 18 | administrator | Replay-protected ModelFS generation publication. |
| `storage device list` | 19 | observer | Bounded live block-device records with explicit truncation. |
| `storage device show` | 20 | observer | One exact device and its capacity, capabilities, counters and errors. |
| `storage filesystem list` | 21 | observer | Mounted MutableFS/ModelFS records and usage. |
| `storage filesystem show` | 22 | observer | One exact mount record; also used by `storage usage`. |
| `storage partition list` | 23 | observer | Bounded GPT entries. |
| `storage partition verify` | 24 | observer | Primary/backup validation report. |
| `storage partition plan-create/create` | 25/26 | observer/administrator | Deterministic plan and confirmed GPT creation. |
| `storage partition plan-delete/delete` | 27/28 | observer/administrator | Deterministic plan and confirmed GPT deletion. |
| `storage partition plan-resize/resize` | 29/30 | observer/administrator | Deterministic plan and confirmed GPT resize. |
| `storage partition repair` | 31 | administrator | Confirmed redundant GPT repair. |
| `storage format-plan/format` | 32/33 | observer/administrator | ModelFS format plan and confirmed format. |
| `storage mount/unmount` | 34/35 | administrator | Validated ModelFS mount lifecycle. |
| `storage fsck/fs-repair` | 36/37 | observer/administrator | Structural check and confirmed redundant-superblock repair. |
| `storage resize-plan/resize` | 38/39 | observer/administrator | Grow-only ModelFS plan and mutation. |
| `model register` | 40 | administrator | Signed staging allocation/publication. |
| `storage scrub start/status/pause/resume/cancel` | 41-45 | administrator/observer | Persisted cooperative scrub and quarantine. |
| `storage trim start/status/cancel` | 46-48 | observer or administrator | Dry-run/status or confirmed free-space discard. |
| `model cleanup` | 49 | administrator | Remove incomplete staging and reclaim extents. |

Request payloads are typed as log query, bounded path, mutation or audit query.
Mutation payloads carry the authenticated principal context, nonzero operation
ID, optional assigned role and bounded path/fingerprint fields. Responses use
version, status, health, capabilities, hardware, metrics, logs, config,
auth-key, mutation or audit payload types. No generic text command is passed to
the kernel protocol.

`model register` accepts bounded signed identity fields, logical size and one
lowercase 64-hex expected package ID, then allocates or reuses aligned staging
extents. `model verify` accepts the package identity. `model activate` accepts
the same identity plus a nonzero operation ID. Activation first verifies
the signed manifest and every non-zero chunk, rejects an existing active model
UUID or live writable staging handle, then publishes a copy-on-write ModelFS
catalog generation. Active package bytes are immutable. `model cleanup` accepts
staging packages only and publishes reclaimed extents through a new generation.

Storage responses use fixed-width 64-bit capacity, sector, byte, generation and
package counters. List responses carry returned and total counts plus a
truncation flag. Device show requires an exact stable boot identifier such as
`/dev/vblk4`; filesystem show accepts an exact mount (`/` or `/models`) and the
small-state aliases `/config`, `/state` and `/logs`. Mutations use distinct
typed payloads, capability checks, administrator role, replay-protected
operation IDs and exact target confirmation where destructive.

Stable response statuses are `ok`, `invalid_request`, `unsupported_version`,
`unknown_operation`, `denied`, `buffer_too_small`, `timeout`, `internal`,
`unknown_node`, `not_found`, `replayed` and `conflict`. The client renders
`replayed` as `replayed_operation`.

## Authorization boundary

Syscall 37 validates both user buffers before copying. Read access requires
`XAIOS_CAP_CONTROL_QUERY`. A process can request administrator operations only
when it also holds `XAIOS_CAP_CONTROL_ADMIN`; the kernel computes the trusted
maximum role from the process capability mask. The request role may be equal or
less privileged, never greater.

The SSH daemon holds the administrative process capability because it brokers
all authenticated roles. It passes the key-derived role and principal into the
shared client. Authorization is repeated in the kernel control module, so a
userspace role field alone cannot grant mutation access.

Mutations require a nonzero operation ID. Authorization and replay reservation
happen before operation-specific validation, and every accepted or rejected
mutation is recorded once in the persistent bounded audit log. Atomic config
apply retains the previous active generation on validation or storage failure.

## Session and storage boundary

Syscall 38 is a separate `xaios.remote-session.v1` ABI for executing within
(lazily creating) and closing one of 16 bounded shell contexts. It gives each SSH
connection its own current directory and parser state. It is intentionally not
part of the control protocol.

Administrative config, key/revocation and audit records use versioned,
checksummed structures in persistent mutable storage. Source config and public
key files are accepted only from `/tmp/`. Shell and SFTP deny the private host
key, password database, legacy authorized-key source and `/state/control`
subtree.

## Logging policy

Log reads use non-destructive sequence snapshots. Lines containing
credential/token/private-key patterns are replaced in full. Prompts, generated
text, passwords, submitted keys and raw model data are prohibited from control
logs. Audit records contain hashes and metadata rather than operation payloads.

## Compatibility

The QEMU release-candidate contract freezes magic, version, header sizes,
limits, operation codes 1 through 49, syscall 37, and control/storage/model
capability bits. Syscall 38 is separately frozen for session lifecycle. New
incompatible layouts require a new protocol version; existing structures must
not be silently reinterpreted.
