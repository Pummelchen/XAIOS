# SSH and Remote Login Status

This page name is retained for incoming links. XAIOS does not currently have a
physically deployed, audited, production-supported Internet SSH service.

## Current Evidence

| Path | Status | Boundary |
|---|---|---|
| Kernel remote-login contract | QEMU fixture | Exercises allowlisted commands, capability checks, password-login rejection, and deterministic telemetry. |
| Host OpenSSH-compatible bridge | Development tool | `scripts/xaios-ssh-bridge.py` listens on localhost and exposes the QEMU command contract through Paramiko. |
| Freestanding userspace SSH/SFTP source | Experimental | Protocol, connection, crypto, channel, host-key, server, and SFTP modules compile, but physical-network deployment and security acceptance are not established. |

The bridge is useful for local integration testing with commands such as
`ssh -p 2222 admin@localhost`. It must not be represented as proof that the
freestanding userspace server is safe for direct Internet exposure.

## Required Production Gates

- Physical NIC and full network-stack execution outside QEMU fixtures.
- Durable CSPRNG-backed host-key provisioning and rotation.
- Secure account/key storage with no built-in credentials.
- Protocol interoperability, malformed-packet, rate-limit, timeout, and
  concurrent-session testing.
- Independent cryptographic and security review.
- Long-run physical-hardware soak, recovery, logging, and update validation.

## Validation Commands

```sh
make qemu-network-suite
make qemu-ssh-smoke
make xaios-ssh-bridge
```

These commands provide development and QEMU correctness evidence only.

## Relevant Source

- `kernel/runtime/remote_login.c`
- `userspace/sshd/`
- `scripts/xaios-ssh-bridge.py`
- `scripts/qemu-ssh-smoke.py`

See the [repository README](https://github.com/Pummelchen/XAIOS/blob/main/README.md)
and [hardware-readiness contract](https://github.com/Pummelchen/XAIOS/blob/main/HARDWARE-READINESS.md)
for current support boundaries.
