# Networking and SSH

XAIOS provides a native IPv4/IPv6 stack, TCP, UDP, DNS, an SSH/SFTP server, and
bounded outbound SSH/SCP clients. The server is implemented in XAIOS userspace;
it is not a forwarded host `sshd`.

## Connect to QEMU

The default QEMU launcher maps `127.0.0.1:7788` to guest TCP port 22:

```sh
ssh -p 7788 admin@127.0.0.1
sftp -P 7788 admin@127.0.0.1
```

Images do not contain a default password. Provision public keys for routine
access. Password authentication requires an explicitly generated PBKDF2 user
database and development-image opt-in; release builds reject it.

## Supported server behavior

- Ed25519 public-key authentication and optional development password auth.
- Persistent host identity, host-key rotation, revocation, and fail-closed RNG.
- Concurrent SSH connections and multiple channels on one transport.
- PTY shells, one-command execution, terminal resize, rekey, and reconnect.
- SFTP v3 read, write, positional I/O, stat, list, mkdir, rename, remove, and
  rmdir with per-process descriptor ownership.
- Stateful per-session cwd, prompt, command status, and terminal applications.
- Connection, channel, command-rate, and resource bounds with explicit errors.

## Network behavior

The QEMU-tested stack includes IPv4/IPv6 fragment reassembly, TCP
handshake/data retransmission, out-of-order receive, duplicate-ACK/SACK
handling, UDP delivery semantics, asynchronous DNS A-record resolution, socket
ownership, cancellation, and cleanup. Runtime-sized CPU/queue metadata avoids
a fixed small-core limit.

## Outbound clients

From an XAIOS shell:

```sh
ssh [-p PORT] user@host [command]
scp [-r] [-P PORT] SOURCE DESTINATION
```

The clients support password authentication, Ed25519 host signatures,
persistent trust-on-first-use host-key checking, IPv4 literals, and DNS A
records. They do not yet support client public keys, IPv6 active open,
forwarding, agents, jump hosts, or hybrid post-quantum key exchange.

## Interoperability evidence

Automated suites exercise XAIOS from macOS OpenSSH, Debian 13 OpenSSH, and an
official FreeBSD 15.1 VM. They cover valid/invalid authentication, four
simultaneous sessions, reconnects, PTY applications, SFTP lifecycle and
isolation, SCP, UDP, IPv6/TCP, malformed traffic, rekey, reboot persistence,
and concurrent clients against one guest.

This is protocol correctness evidence under QEMU, not approval for direct
Internet exposure. See [[Security Model|Security-Model]],
[[Testing XAIOS|Testing-XAIOS]], and [[Current Limitations|Current-Limitations]].
