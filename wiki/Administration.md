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
