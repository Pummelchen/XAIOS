# Network and SSH Status

This document separates current QEMU interoperability evidence from deferred
network and security work. QEMU results establish protocol and ABI correctness
only; they do not establish physical-NIC readiness or production security.

## Verified Guest Paths

The following paths were exercised from a macOS OpenSSH/Python client against
the freestanding AArch64 guest on 2026-08-02:

- correct `admin` development credentials completed SSH authentication and a
  remote command;
- an incorrect password was rejected by OpenSSH;
- SFTP v3 put, stat, and get completed for an 8,170-byte file, with identical
  source and downloaded SHA-256 hashes;
- a 24-byte UDP datagram reached a guest userspace buffer and was echoed with
  the same payload;
- direct IPv6/TCP completed a handshake and transferred client and guest SSH
  identification data with validated TCP checksums.

These are local development paths. The server has a built-in QEMU development
credential, derives host-key material without a production CSPRNG when firmware
entropy is unavailable, and has not received an independent security review.
It closes an encrypted connection when a rekey boundary is reached because
rekey negotiation is not implemented. The current service admits one active
SSH connection at a time and releases it when the peer closes the TCP stream.

## Reproduce on macOS

Install `sshpass` in addition to the normal build prerequisites, build the
image, and launch QEMU with localhost forwarding:

```sh
brew install sshpass
make image
XAIOS_QEMU_HOSTFWD_PORT=2299 XAIOS_QEMU_HOSTFWD_UDP_PORT=2298 make qemu
```

In a second terminal, verify successful and rejected authentication:

```sh
sshpass -p admin ssh -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password \
  -o PubkeyAuthentication=no -p 2299 admin@127.0.0.1 \
  'echo ssh-regression-ok'

sshpass -p wrong-password ssh -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null -o NumberOfPasswordPrompts=1 \
  -o PreferredAuthentications=password -o PubkeyAuthentication=no \
  -p 2299 admin@127.0.0.1 true
```

The second command must exit nonzero with authentication denied. A batch SFTP
round trip can be run with:

```sh
dd if=README.md of=/tmp/xaios-sftp-source bs=8170 count=1 status=none
printf '%s\n' \
  'put /tmp/xaios-sftp-source /tmp/xaios-sftp-readme' \
  'ls -l /tmp/xaios-sftp-readme' \
  'get /tmp/xaios-sftp-readme /tmp/xaios-sftp-roundtrip' \
  'rm /tmp/xaios-sftp-readme' | \
  sshpass -p admin sftp -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no -P 2299 admin@127.0.0.1
cmp /tmp/xaios-sftp-source /tmp/xaios-sftp-roundtrip
```

The bounded fixture reflects the mutable filesystem's current 8,192-byte
per-file limit. `ls -l` exercises SFTP attributes/stat and must report 8,170
bytes.

Send and validate a UDP payload with any datagram client against
`127.0.0.1:2298`. To exercise IPv6/TCP directly, stop the forwarding VM, launch
the socket backend, and run the repository client:

```sh
XAIOS_QEMU_HOSTFWD_PORT=none XAIOS_QEMU_NET_SOCKET_PORT=12345 make qemu
python3 scripts/qemu-ipv6-tcp-client.py --port 12345
```

## Deferred Boundaries

| Area | Current source-grounded status |
|---|---|
| General threads | No `xaios_thread_create()` lifecycle API. Bounded `xaios_thread_group_run()` and SMP worker dispatch exist. |
| DNS | A-record encoding, parsing, cache, and retry code exists, but its tick is not wired and no userspace resolver API exists. Not operational. |
| TCP retransmission | SYN/timeout fixtures exist. The active payload send path does not retain unacknowledged bytes or arm its retransmission fields, so payload retransmission remains deferred. |
| Fragmentation | IPv4 helper self-tests exist but are not integrated into the persistent packet path. IPv6 multi-fragment reassembly is absent. |
| SMMU | AArch64 implementation is bypass-only; Stage 1 translation remains deferred. |
| Kernel heap | The old bump-only report is resolved: the current heap exposes `kheap_free()` and reuses freed blocks. |

The direct IPv4/IPv6 paths currently target a 1500-byte MTU. Do not infer loss
recovery, fragment interoperability, Internet exposure safety, or physical
server readiness from the local QEMU checks.
