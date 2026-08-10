# SSH and Remote Login Status

This page name is retained for incoming links. XAIOS does not currently have a
physically deployed, audited, production-supported Internet SSH service.

## Current Evidence

| Path | Status | Boundary |
|---|---|---|
| Kernel remote-login contract | QEMU fixture | Exercises allowlisted commands, capability checks, password-login rejection, and deterministic telemetry. |
| Host OpenSSH-compatible bridge | Development tool | `scripts/xaios-ssh-bridge.py` listens on localhost and exposes the QEMU command contract through Paramiko. |
| Freestanding userspace SSH/SFTP service | Experimental | FreeBSD 15.1, native macOS and Debian 13 OpenSSH clients authenticate to QEMU guests. FreeBSD covers the Unix-reference key/SFTP/PTY/UDP subset; macOS and Debian cover the broader parallel administration, saturation, recovery and direct-TCP suite. Physical-network deployment and security acceptance are not established. |
| Phase 2 `xaiosctl` administration | QEMU-tested | Forty-nine typed operations cover measured queries, strict config transactions, role-mapped key lifecycle/revocation, host-key rotation, payload-redacted audit, GPT/ModelFS lifecycle, dynamic staging, scrub and trim. Role, replay, rollback, persistence and secret-exposure checks pass through OpenSSH gates. Cluster control is not implemented. |

The bridge is useful for local integration testing with commands such as
`ssh -p 2222 admin@localhost`. It must not be represented as proof that the
freestanding userspace server is safe for direct Internet exposure.

The guest service is also reachable locally with QEMU TCP forwarding. It has no
built-in password: Ed25519 authorized keys and strict PBKDF2 password records
are packaged explicitly. VirtIO RNG entropy is mandatory, the persistent
Ed25519 host key is flushed and stable across reboot, and OpenSSH-forced rekey
passes. Default-disabled and malformed credentials fail closed. It currently
admits four active SSH connections and two channels per connection, deliberate
fixed userspace-memory bounds. Shared exec/SFTP channels, overlapping SFTP,
wrong-key/password rejection, 40 combined reconnects, and post-load recovery
pass from macOS and Debian 13 against one guest. UDP userspace delivery and
asynchronous DNS, malformed/reset/reordered/retransmitted TCP, and out-of-order
IPv4/IPv6 fragment reassembly are in
[`docs/NETWORK-SSH-STATUS.md`](https://github.com/Pummelchen/XAIOS/blob/main/docs/NETWORK-SSH-STATUS.md).

The server currently negotiates classical `curve25519-sha256` only; it does not
yet implement an OpenSSH hybrid post-quantum KEX such as
`mlkem768x25519-sha256`. OpenSSH 10 therefore warns on a direct connection.
For local QEMU development, `scripts/ssh-xaios-qemu.sh` uses a persistent
project-local known-hosts file and suppresses that client notice for this scoped
connection. This convenience does not add post-quantum protection or relax the
production security gate.

The guest validates SSH PTY and resize dimensions. Running `htop` on a PTY
selects a native XAIOS-generated live ANSI monitor with sampled CPU/memory
meters, process selection and paging, CPU paging, sorting, filtering, help and
resize-aware rerendering. Each SSH channel has independent monitor state and
bounded refresh/backpressure behavior with a hard monotonic 60-frame-per-second
render cap. The PTY uses the terminal alternate-screen buffer and restores the
original screen on exit, preventing live frames from accumulating in normal
scrollback. CPU sampling uses a complete interrupt-backed timer wait that is
excluded from process runtime, so htop does not create a permanent 100% CPU 0
reading. CPU, memory and swap meter brackets share one dynamically sized label
column;
memory and swap remain beneath the left CPU group, capacity values are
right-aligned there when width permits, and footer keys use htop-style color
segments.
Non-PTY calls remain one-shot plain
snapshots for automation. Process kill and priority controls are not offered
until XAIOS has a safe generic process-control ABI.

Ed25519 principals are assigned observer, operator or administrator roles.
Administrative audit entries and operational remote-login records omit command
payloads and authentication material.
Configuration, keys/revocations and audit metadata persist across reboot;
mutations require replay-protected operation IDs. Private host-key and control
state paths are denied through shell and SFTP. Password support is disabled by
default, requires an explicit development-image opt-in and is forbidden in
release builds.

## Required Production Gates

- Physical NIC and full network-stack execution outside QEMU fixtures.
- Fleet identity integration, durable external audit export and production
  secret-storage/replay-retention policy beyond the bounded Phase 2 stores.
- Extended rate-limit, timeout, repeated-loss, and long concurrent-session soak.
- Independent cryptographic and security review.
- Reviewed hybrid post-quantum SSH KEX, interoperability and downgrade-policy
  validation.
- Long-run physical-hardware soak, recovery, logging, and update validation.

## Validation Commands

```sh
make qemu-network-suite
make qemu-freebsd-network-suite
make qemu-docker-network-suite
make qemu-parallel-network-load
make qemu-model-sftp-gate
make qemu-ssh-smoke
make xaios-ssh-bridge
```

These commands provide development and QEMU correctness evidence only.

The guest SSH server only admits its existing bounded shell command set plus
the exact `xaiosctl` prefix. It does not provide arbitrary executable launch.
See the [xaiosctl reference](https://github.com/Pummelchen/XAIOS/blob/main/docs/XAIOSCTL.md)
and [control protocol](https://github.com/Pummelchen/XAIOS/blob/main/docs/CONTROL-PROTOCOL.md).

## Relevant Source

- `kernel/runtime/remote_login.c`
- `userspace/sshd/`
- `scripts/xaios-ssh-bridge.py`
- `scripts/qemu-ssh-smoke.py`
- `scripts/qemu-docker-network-suite.py`
- `scripts/qemu-freebsd-network-suite.py`
- `scripts/qemu-parallel-network-load.py`
- `scripts/qemu-model-sftp-gate.py`
- `tests/network/`

See the [repository README](https://github.com/Pummelchen/XAIOS/blob/main/README.md)
and [hardware-readiness contract](https://github.com/Pummelchen/XAIOS/blob/main/HARDWARE-READINESS.md)
for current support boundaries.
