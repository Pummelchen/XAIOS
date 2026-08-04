# Storage Tools

Status: the hosted ModelFS administration CLI is implemented in
`tools/xaios_model_volume.py`; capability-gated guest lifecycle commands are
implemented through `xaiosctl storage` and `xaiosctl model`.

Run commands with `PYTHONPATH=tools python3 tools/xaios_model_volume.py` from
the repository root. Every command emits one JSON object. Exit codes are 0 for
success, 1 for detected corruption/repairable state, 2 for invalid or unsafe
requests, 3 for unsupported operations or shrink, and 4 for I/O failure.

## Lifecycle

```sh
PYTHONPATH=tools python3 tools/xaios_model_volume.py format \
  build/models.img --size 137438953472 --chunk-size 16777216 \
  --confirm-path build/models.img

PYTHONPATH=tools python3 tools/xaios_model_volume.py stage \
  build/models.img model.xaios manifest.json
PYTHONPATH=tools python3 tools/xaios_model_volume.py verify \
  build/models.img PACKAGE_ID
PYTHONPATH=tools python3 tools/xaios_model_volume.py activate \
  build/models.img PACKAGE_ID
```

`format` refuses unless `--confirm-path` exactly matches the target and performs
a read-back fsck. `stage` validates the signed manifest, writes expected chunks
incrementally, and preserves resumable completion metadata. `activate` refuses
incomplete or invalid packages.

Inspection commands are `list`, `inspect PACKAGE_ID`, and `usage`. Removal
requires `--confirm-package PACKAGE_ID`; active removal additionally requires
`--allow-active`.

## Capacity and recovery

```sh
PYTHONPATH=tools python3 tools/xaios_model_volume.py resize-plan \
  build/models.img --grow-to NEW_SIZE
PYTHONPATH=tools python3 tools/xaios_model_volume.py resize \
  build/models.img --grow-to NEW_SIZE --confirm-volume VOLUME_UUID
PYTHONPATH=tools python3 tools/xaios_model_volume.py fsck \
  build/models.img --verify-data
PYTHONPATH=tools python3 tools/xaios_model_volume.py repair-superblock \
  build/models.img --confirm-volume VOLUME_UUID
```

Resize is grow-only. Shrink returns `shrink_not_supported` and makes no change.
`recover --drop-incomplete` and mutating `scrub` also require exact volume UUID
confirmation. See [ModelFS recovery](./MODELFS-RECOVERY.md).

## Trim

`trim-plan` lists only catalog-owned free extents. `trim --dry-run` applies
geometry and request splitting without issuing discard. A real trim requires
`--confirm-volume`; an optional `--range OFFSET:LENGTH` must lie wholly inside
free space.

On Linux block devices the backend uses `BLKDISCARD`; on Linux regular files it
uses hole punching. Unsupported hosts, including the current macOS hosted path,
return a structured `unsupported` result. Trim flushes before discard and never
assumes discarded reads return zero.

These commands operate on explicit paths but do not yet identify mounted,
boot, rollback, or active serving devices through a system inventory. Operators
must keep host-tool targets offline. Guest commands apply the live storage
inventory and target-protection policy described below.

## Guest administration

The guest exposes typed human and JSON responses for:

```text
xaiosctl storage device list|show ...
xaiosctl storage partition list|verify|plan-create|create ...
xaiosctl storage partition plan-delete|delete|plan-resize|resize|repair ...
xaiosctl storage format-plan|format|mount|unmount|fsck|resize-plan|resize ...
xaiosctl model register PACKAGE_ID ... --operation-id ID
xaiosctl model verify PACKAGE_ID
xaiosctl model activate PACKAGE_ID --operation-id ID
xaiosctl model cleanup PACKAGE_ID --operation-id ID
xaiosctl storage scrub /models --start|--status|--pause|--resume|--cancel
xaiosctl storage trim /models --dry-run
xaiosctl storage trim /models --all-free --operation-id ID
xaiosctl storage trim /models --range OFFSET:LENGTH --operation-id ID
xaiosctl storage trim-status /models
xaiosctl storage trim-cancel /models --operation-id ID
```

Actual mutations require their operation-specific capability, administrator
role, a nonzero replay-protected operation ID, and target confirmation where the
device or volume can be destroyed. `storage trim /models --dry-run` safely
defaults to all catalog-owned free extents. Actual trim requires an explicit
`--all-free` or `--range` scope and flushes before discard.

Scrub and trim progress survives control-client disconnects. Each status call
advances at most one scrub chunk or one bounded trim work unit, keeping the
freestanding path cooperative. Mount-time recovery resumes valid persisted
state and rejects state whose volume UUID or catalog generation no longer
matches.
