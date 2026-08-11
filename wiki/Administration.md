# Administration

XAIOS exposes the versioned `xaios.control.v1` protocol through `xaiosctl` and
the authenticated shell. Queries and mutations use typed requests, role and
capability checks, replay protection, bounded audit records, and explicit
errors.

## Main command groups

| Group | Purpose |
|---|---|
| `status`, `health`, `hardware`, `metrics`, `logs` | Inspect system state and telemetry. |
| `config show|validate|diff|apply` | Validate and atomically apply bounded configuration transactions. |
| `auth key list|add|remove` | Manage role-mapped administrative keys and revocation. |
| `auth host-key rotate` | Rotate the persistent SSH host key. |
| `audit show` | Read bounded, redacted audit history by sequence. |
| `storage device|partition|format|mount|unmount|fsck|resize|scrub|trim` | Inspect and manage GPT, filesystems, ModelFS integrity, and free extents. |
| `model register|verify|activate|cleanup` | Manage signed ModelFS package lifecycle around resumable SFTP staging. |

Examples:

```sh
xaiosctl status
xaiosctl health
xaiosctl hardware
xaiosctl storage device list
xaiosctl storage partition list
xaiosctl audit show --limit 16
```

Mutating operations require an administrator role, matching capability, and a
fresh request identity. Planning operations are separate from confirmed
mutation where destructive state is involved. Unknown cluster nodes and
unimplemented services return stable errors rather than simulated success.

## Capacity boundaries

The current QEMU-tested control plane is intentionally bounded to 16 active
keys, 16 revoked fingerprints, 64 audit/replay records, and 16 shell contexts.
It is suitable for a single XAIOS instance, not fleet-scale administration.

For exact syntax and operation IDs, use the repository
[`xaiosctl` reference](https://github.com/Pummelchen/XAIOS/blob/main/docs/XAIOSCTL.md)
and [control protocol](https://github.com/Pummelchen/XAIOS/blob/main/docs/CONTROL-PROTOCOL.md).
