# xaiosctl

`xaiosctl` is the single structured XAIOS administrative command surface. The
freestanding SSH server exposes it through an exact allowlist and does not
launch arbitrary executables. Because XAIOS has no general userspace `exec`
path yet, the `/bin/xaiosctl` image application exercises the same client as a
boot-time ABI/rendering gate; SSH is the current interactive operator path.

## Implemented commands

```text
xaiosctl version
xaiosctl status
xaiosctl health
xaiosctl capabilities
xaiosctl hardware
xaiosctl metrics
xaiosctl logs [--component NAME] [--since CURSOR] [--limit 1..1000] [--follow]
xaiosctl config show
xaiosctl config validate /tmp/FILE
xaiosctl config diff /tmp/FILE
xaiosctl config apply /tmp/FILE --operation-id ID
xaiosctl auth key list
xaiosctl auth key add /tmp/KEY.pub --principal NAME --role ROLE --operation-id ID
xaiosctl auth key remove FINGERPRINT --operation-id ID
xaiosctl auth host-key rotate --operation-id ID
xaiosctl audit show [--since SEQUENCE] [--limit 1..16]
xaiosctl model register PACKAGE_ID --model-uuid UUID --signer-key KEY \
  --signature SIGNATURE --source-revision REVISION --architecture ID \
  --target ID --size SIZE --operation-id ID
xaiosctl model verify PACKAGE_ID
xaiosctl model activate PACKAGE_ID --operation-id ID
xaiosctl model cleanup PACKAGE_ID --operation-id ID
xaiosctl storage device list
xaiosctl storage device show DEVICE
xaiosctl storage partition list|verify DEVICE
xaiosctl storage partition plan-create|create DEVICE --type TYPE --size SIZE --name NAME [...]
xaiosctl storage partition plan-delete|delete PARTITION [...]
xaiosctl storage partition plan-resize|resize PARTITION --grow-to SIZE [...]
xaiosctl storage partition repair DEVICE [...]
xaiosctl storage filesystem list
xaiosctl storage filesystem show MOUNT
xaiosctl storage mount-status
xaiosctl storage usage MOUNT
xaiosctl storage format-plan|format TARGET --type modelfs [...]
xaiosctl storage mount TARGET /models [--read-only] --operation-id ID
xaiosctl storage unmount /models --operation-id ID
xaiosctl storage fsck TARGET [--check|--repair] [--verify-data] [...]
xaiosctl storage repair-from-replica TARGET REPLICA PACKAGE_ID \
  --confirm-partition TARGET_UUID --operation-id ID
xaiosctl storage resize-plan|resize TARGET --grow-to SIZE|max [...]
xaiosctl storage scrub /models --start|--status|--pause|--resume|--cancel [...]
xaiosctl storage trim /models --dry-run
xaiosctl storage trim /models --all-free|--range OFFSET:LENGTH [...]
xaiosctl storage trim-status /models
xaiosctl storage trim-cancel /models --operation-id ID
```

Every command accepts `--json`, `--timeout <1ms..60000ms|1s..60s>` and
`--node <local|unsigned-node-id>`. Only local node `0` exists. Other node IDs
return the stable `unknown_node` error. Cluster routing is planned, not
silently emulated.

`--filter` is a compatibility alias for the log `--component` option. Log
follow is a bounded long poll and rejects timeouts above five seconds. Log and
audit cursors are monotonic and non-destructive.

`ssh.command_rate_per_minute` limits shell and `xaiosctl` exec requests. SFTP
protocol packets do not consume that command quota; file transfer remains
bounded by authenticated connection/channel limits, packet sizes, SSH flow
control and filesystem authorization.

All mutations require a caller-selected, nonzero `--operation-id`. Reusing an
ID for the same authenticated principal returns `replayed_operation`, including
when the first attempt failed validation. Replay detection is retained with the
latest 64 audit records; callers must still use durable, non-repeating IDs.

Model package IDs are exactly 64 lowercase hexadecimal characters. Registration
accepts bounded signed identity fields, checks capacity, allocates or reuses
aligned extents, and publishes a staging record. Verification rechecks the
signed identity and all completed chunks without publishing a new generation.
Activation repeats verification, atomically publishes a copy-on-write ModelFS
generation and records `model.package.activate`. Cleanup accepts incomplete
staging only and reclaims its extents. These lifecycle mutations are
administrator-only and replay protected.

Storage discovery and usage commands are observer-safe typed reads. Device
lists are bounded to eight records per response and report `total_count` plus
`truncated`, so a large server never silently appears to have only the returned
devices. `mount-status` aliases `storage filesystem list`; `usage` aliases
`storage filesystem show`. The current guest exposes live block capabilities,
I/O counters, and the `/` xaibootFS and `/models` ModelFS mounts. Typed guest
operations cover GPT plan/mutation, format/mount/unmount, fsck/repair, grow-only
resize, persistent scrub/quarantine, offline trusted-replica payload repair,
and free-only trim/discard. Replica repair requires two distinct unmounted
ModelFS partitions. It accepts only an active replica whose signed immutable
package identity and complete payload verify exactly against an existing
quarantined target package; it never overwrites active bytes. Destructive
operations require their dedicated capability, administrator role, nonzero
operation ID and exact target confirmation. Dry-run trim is observer-safe and
defaults to all catalog-owned free extents; actual trim requires explicit scope.

Scrub persists UUID/generation-pinned progress and supports pause, resume and
cancel. Trim persists its free-extent cursor and supports status/cancel. Both
use bounded cooperative work units. Registration, activation and cleanup reject
live ModelFS handles or incompatible maintenance rather than racing metadata.

## Roles

| Role | Control access | Remote shell/SFTP |
|---|---|---|
| `observer` | Read operations, config validate/diff, key list and audit reads. | Denied. |
| `operator` | Observer access plus atomic config apply. | Denied. |
| `administrator` | All operations, including key mutation and host-key rotation. | Allowed by the current compatibility shell/SFTP policy. |

The authenticated key determines the maximum role. A request can reduce its
role but cannot elevate it. An administrator cannot remove the final active
administrator key. Removed keys enter a bounded persistent revocation list and
are rejected on later authentication attempts.

Key-add input must be an OpenSSH Ed25519 public key staged below `/tmp/`.
Fingerprints are 64 lowercase hexadecimal characters containing SHA-256 of the
raw 32-byte Ed25519 public key. Principals are unique bounded identifiers.

## Configuration schema

Config files are strict, complete `xaios.config.v1` documents staged below
`/tmp/`. Unknown, duplicate, missing or malformed fields are rejected.

```text
schema=xaios.config.v1
ssh.max_connections=1..4
ssh.max_channels_per_connection=1..2
ssh.max_auth_attempts=1..5
ssh.command_rate_per_minute=1..120
ssh.password_auth=disabled|development
```

`config validate` parses and bounds-checks without modifying state. `config
diff` reports the field change mask. `config apply` validates a candidate,
writes it atomically to persistent control state, reloads the daemon, and
retains the previous generation if any step fails.

Development images start with password authentication enabled for the public
`admin` / `xaios` test account. Set `XAIOS_SSH_PASSWORD_AUTH=0` to build a
key-only development image, or pass an explicit PBKDF2 record with
`XAIOS_SSH_USERS_FILE` and `XAIOS_SSH_PASSWORD_AUTH=1` to replace it. Release
builds reject every password-enabled profile; public-key authentication is
required in release mode.

## Persistence and sensitive state

Configuration, authorized keys, revocations and audit records are checksummed
and persisted below `/state/control`. The Ed25519 host identity persists at
`/state/xaios_host_key`; rotation requires administrator authorization and
secure entropy, writes a replacement, and closes existing transports so new
connections observe the new key. The shell and SFTP path guards deny these
files and the password database, including to administrators. No command
returns private host-key bytes. Operational remote-login records contain
dispatch metadata only; user-supplied command text and arguments are omitted.

The current fixture stores at most 16 active keys, 16 revoked fingerprints and
64 audit records. These are explicit bounded-QEMU limits, not a production
fleet-scale identity store.

## Output contract

Human and JSON output are rendered from the same typed protocol response.
Successful JSON uses deterministic field order and this envelope:

```json
{"schema_version":1,"request_id":"1","status":"ok","data":{}}
```

Errors include `data: null`, a stable code, safe text and the request ID:

```json
{"schema_version":1,"request_id":"1","status":"error","data":null,"error":{"code":"unknown_operation","message":"Unknown xaiosctl command."}}
```

Unavailable numeric values are `null` in JSON and `unknown` in human output.
Unavailable states are not synthesized as success. `health` exits `0` only for
ready state; it currently exits `1` with a typed degraded response because
production model inference and clustering are unavailable.

Operational log reads replace credential, token and private-key patterns with
a redaction record. Administrative audit records contain principal, role,
operation, result, operation ID and an object hash, never the source config,
password, submitted public-key body or private key.

## Validation boundary

```sh
make hosted-test
make qemu-abi-contract
make qemu-smoke
make qemu-model-sftp-gate
make qemu-docker-network-suite
```

These gates cover deterministic parsing/rendering, ABI behavior, valid and
invalid roles/keys/configs, revocation, replay, rollback, persistent and rotated
host identity, rekey, concurrent session isolation and secret redaction through
Debian 13 OpenSSH against QEMU. The ModelFS gate additionally runs concurrent
native macOS and Debian 13 package lifecycle traffic, cleanup/reuse, scrub and
VirtIO discard against one guest. They do not prove hostile-network resistance,
physical-hardware behavior, independent security review or production safety.
