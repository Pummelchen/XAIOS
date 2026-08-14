# Administration

XAIOS exposes the versioned `xaios.control.v1` protocol through `xaiosctl` and
the authenticated shell. Queries and mutations use typed requests, role and
capability checks, replay protection, bounded audit records, and explicit
errors.

Signed application installation and A/B operating-system delivery are handled
by `xapt`; see [[xapt Package Updates|Xapt-Package-Updates]].

## Main command groups

| Group | Purpose |
|---|---|
| `status`, `health`, `hardware`, `metrics`, `logs` | Inspect system state and telemetry. |
| `config show|validate|diff|apply` | Validate and atomically apply bounded configuration transactions. |
| `auth key list|add|remove` | Manage role-mapped administrative keys and revocation. |
| `auth host-key rotate` | Rotate the persistent SSH host key. |
| `audit show` | Read bounded, redacted audit history by sequence. |
| `storage device|partition|format|mount|unmount|fsck|repair-from-replica|resize|scrub|trim` | Inspect and manage GPT, filesystems, ModelFS integrity, trusted-replica recovery, and free extents. |
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

The complete QEMU-tested command family is:

```text
xaiosctl version
xaiosctl status
xaiosctl health
xaiosctl capabilities
xaiosctl hardware
xaiosctl metrics
xaiosctl logs
xaiosctl config show|validate|diff|apply
xaiosctl auth key list|add|remove
xaiosctl auth host-key rotate
xaiosctl audit show
xaiosctl model verify PACKAGE_ID
xaiosctl model register PACKAGE_ID --model-uuid UUID --signer-key KEY \
  --signature SIGNATURE --source-revision REVISION --architecture ID \
  --target ID --size BYTES --operation-id ID
xaiosctl model activate PACKAGE_ID --operation-id ID
xaiosctl model cleanup PACKAGE_ID --operation-id ID
xaiosctl storage device list
xaiosctl storage partition list|verify|plan-create|create|plan-delete|delete|plan-resize|resize|repair ...
xaiosctl storage filesystem list
xaiosctl storage usage /models
xaiosctl storage format-plan|format|mount|unmount|fsck|repair-from-replica|resize-plan|resize ...
xaiosctl storage scrub /models --start|--status|--pause|--resume|--cancel
xaiosctl storage trim /models --dry-run
xaiosctl storage trim /models --all-free --operation-id ID
xaiosctl storage trim-status|trim-cancel /models ...
```

Every command accepts `--json`, `--timeout`, and `--node`. Mutations require a
nonzero replay-protected `--operation-id`. Ed25519 principals map to observer,
operator, or administrator roles: configuration application requires operator,
while key and host-identity changes require administrator.

Mutating operations require an administrator role, matching capability, and a
fresh request identity. Planning operations are separate from confirmed
mutation where destructive state is involved. Unknown cluster nodes and
unimplemented services return stable errors rather than simulated success.
`xaiosctl health` therefore reports degraded and exits nonzero while production
model inference and clustering remain unavailable.

## Operations and recovery

The authenticated shell also exposes a bounded host-operations layer:

```sh
power status
service list
service start /bin/xaios-worker
service stop /bin/xaios-worker
ifconfig
route
netstat
ping 10.0.2.2
ping status
nslookup example.com
date
ntp sync
ntp status
limits
recovery status
config export /tmp/xaios-config.conf
config import /tmp/xaios-config.conf
update status
support > /tmp/xaios-support.txt
shutdown
```

`shutdown` and `reboot` are delayed briefly so the SSH response can be sent,
then persist lifecycle intent, flush the kernel log and all flush-capable block
devices, and invoke the architecture power primitive. A boot left in `running`
state is counted as unclean. Three consecutive unclean boots or `recovery
enter` select rescue mode; `recovery clear` removes the forced rescue marker.
Rescue SSH sessions permit diagnostics and bounded filesystem repair commands,
but block ordinary application launch.

`config export` writes the canonical `xaios.config.v1` text format. Import uses
the existing validation, role, replay, audit, and transactional commit path.
`support` contains build, lifecycle, clock, resource, network, and log counters
and explicitly redacts secrets. See [[Operations and Recovery|Operations-and-Recovery]].

## Capacity boundaries

The current QEMU-tested control plane is intentionally bounded to 16 active
keys, 16 revoked fingerprints, 64 audit/replay records, and 16 shell contexts.
It is suitable for a single XAIOS instance, not fleet-scale administration.

For exact syntax and operation IDs, use the repository
[`xaiosctl` reference](https://github.com/Pummelchen/XAIOS/blob/main/docs/XAIOSCTL.md)
and [control protocol](https://github.com/Pummelchen/XAIOS/blob/main/docs/CONTROL-PROTOCOL.md).
