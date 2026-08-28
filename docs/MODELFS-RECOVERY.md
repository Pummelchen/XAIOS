# xaiFS Recovery

Status: hosted and guest administrative fsck, superblock repair, and offline
trusted-replica payload repair are implemented. Repair requires unmounted
target and replica volumes. Mounted xaiFS supports persistent online scrub,
quarantine, staging cleanup and free-extent reuse.

## Commit ordering

Each mutation follows this order:

1. Write payload bytes for a chunk and flush them.
2. Build a new immutable catalog snapshot in unused aligned space.
3. Write and flush the catalog.
4. Write the alternate superblock pointing to that catalog.
5. Flush, then reopen/read back critical metadata before reporting success.

Activation is a metadata-only generation change after every chunk, manifest,
identity, signature, and hash validates. Active package bytes never change.

At mount, each superblock is parsed independently. The highest complete valid
generation wins. A torn new catalog or superblock leaves the previous valid
generation authoritative. If both copies are invalid, mount fails closed.

## Fsck outcomes

`fsck` is read-only. Without `--verify-data`, it validates redundant
superblocks, catalog hashes, record ownership, extents, identities, and
signatures. With `--verify-data`, it also streams every package chunk and
validates SHA-256.

Stable status classes are:

- `clean`: no structural or payload errors found.
- `repairable`: one redundant superblock copy is invalid and can be recreated
  from the selected valid copy.
- `corrupt_unrepairable`: no trustworthy structural source remains, or model
  bytes are damaged and no trusted replacement was supplied.

`repair-superblock` requires exact volume UUID confirmation, writes only the
invalid redundant copy, flushes, and revalidates. It does not fabricate
catalogs or model bytes.

## Trusted-replica payload repair

`xaiosctl storage repair-from-replica TARGET REPLICA PACKAGE_ID` repairs a
quarantined target package from one administrator-selected xaiFS replica.
It requires `--confirm-partition TARGET_UUID` and a nonzero
`--operation-id`. Both partitions must be distinct and unmounted.

Before the target changes, XAIOS requires the replica package to be active and
to pass complete manifest, Ed25519 signature, and streamed SHA-256 payload
verification. The target package must be quarantined and must match the
replica's immutable model UUID, package ID, signer key, signature, source
revision, logical size, chunk size, architecture ID, and target ID exactly.

Repair removes only the unavailable quarantined record, registers a fresh
staging record, copies bounded scratch-sized portions, commits each complete
chunk, re-verifies the entire replacement, and publishes it active. Active
payload bytes are never modified. A failure before removal leaves the target
unchanged; a later failure can leave only absent or staging data, never a
newly active unverified package. The target remains recoverable through a new
replica repair attempt.

## Incomplete staging and quarantine

Hosted `recover` reports incomplete staging packages and can drop them with
exact volume UUID confirmation. A mounted guest uses `xaiosctl model cleanup
PACKAGE_ID --operation-id ID`; this accepts staging packages only and releases
their extents through a new catalog generation.

Hosted `scrub --check-only` reports corruption without mutation. Mounted guest
scrub pins volume UUID and catalog generation, stores progress in
`/state/modelfs-scrub.bin`, verifies one chunk per cooperative control step, and
supports pause, resume and cancel. A damaged package is atomically quarantined.
Quarantined packages cannot activate, open through the portable model-file API,
or be read through the kernel xaiFS namespace.

## Remaining recovery boundaries

- Superblock repair is never performed on a mounted filesystem. The guest
  control path can unmount, repair with exact UUID confirmation, and remount.
- Scrub uses cooperative chunk-sized work units, not an autonomous background
  thread or a wall-clock bandwidth-rate controller. Reads continue between
  units; registration, cleanup, activation and trim are rejected while it runs.
- Replica selection is currently an offline, administrator-specified xaiFS
  partition. Network retrieval, replica discovery, quorum policy, and
  automatic repair remain out of scope.
- Production signer private-key custody, operator authorization, trust-root
  rotation, and trusted-replica enrollment are deployment responsibilities;
  fixture keys exercise the format contract only.
- Old catalog snapshots are recovery metadata and are not compacted in v1.

Run recovery against an unmounted copy and preserve the original image before
any confirmed mutation.
