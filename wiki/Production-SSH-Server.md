# SSH and Remote Login Status

This page name is retained for incoming links. XAIOS does not currently have a
physically deployed, audited, production-supported Internet SSH service.

## Current Evidence

| Path | Status | Boundary |
|---|---|---|
| Kernel remote-login contract | QEMU fixture | Exercises allowlisted commands, capability checks, password-login rejection, and deterministic telemetry. |
| Host OpenSSH-compatible bridge | Development tool | `scripts/xaios-ssh-bridge.py` listens on localhost and exposes the QEMU command contract through Paramiko. |
| Freestanding userspace SSH/SFTP service | Experimental | Native macOS and Debian 13 OpenSSH clients authenticated to one QEMU guest and completed remote-command, strict SFTP, four-connection/eight-channel saturation, over-capacity rejection, reconnect, UDP, and direct TCP tests in parallel. Physical-network deployment and security acceptance are not established. |

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
direct malformed/reset/reordered/retransmitted TCP are in
[`docs/NETWORK-SSH-STATUS.md`](https://github.com/Pummelchen/XAIOS/blob/main/docs/NETWORK-SSH-STATUS.md).

## Required Production Gates

- Physical NIC and full network-stack execution outside QEMU fixtures.
- Deployed key rotation, account lifecycle, revocation, and secret-storage
  policy beyond build-time provisioning.
- Extended rate-limit, timeout, repeated-loss, and long concurrent-session soak.
- Independent cryptographic and security review.
- Long-run physical-hardware soak, recovery, logging, and update validation.

## Validation Commands

```sh
make qemu-network-suite
make qemu-docker-network-suite
make qemu-parallel-network-load
make qemu-ssh-smoke
make xaios-ssh-bridge
```

These commands provide development and QEMU correctness evidence only.

## Relevant Source

- `kernel/runtime/remote_login.c`
- `userspace/sshd/`
- `scripts/xaios-ssh-bridge.py`
- `scripts/qemu-ssh-smoke.py`
- `scripts/qemu-docker-network-suite.py`
- `scripts/qemu-parallel-network-load.py`
- `tests/network/`

See the [repository README](https://github.com/Pummelchen/XAIOS/blob/main/README.md)
and [hardware-readiness contract](https://github.com/Pummelchen/XAIOS/blob/main/HARDWARE-READINESS.md)
for current support boundaries.
