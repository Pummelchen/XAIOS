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
- Hybrid `mlkem768x25519-sha256` key exchange with classical fallback.
- `direct-tcpip` forwarding for OpenSSH jump-host use and agent forwarding.
- SFTP v3 read, write, positional I/O, stat, list, mkdir, rename, remove, and
  rmdir with per-process descriptor ownership.
- Stateful per-session cwd, prompt, command status, and terminal applications.
- A 32-transport server ceiling, up to two active channels per transport, and
  64 asynchronous child-channel records, with explicit saturation errors and
  reclamation after disconnect.

## Address configuration

Every network device asks the network for an IPv4 address by DHCP before
falling back to the compiled-in QEMU address of `10.0.2.15`. A guest that
assumes that address is simply off-net anywhere else; Virtualization.framework
hands out a different subnet entirely.

IPv6 derives a link-local address from the hardware address, then solicits a
router and polls briefly for the advertisement, because nothing else reads the
interface between bringing it up and starting services. A prefix that is
globally routable or unique-local is configured and used as the source address
for outbound IPv6; whether an address is *globally* routable stays a separate
question. Both hypervisors available here advertise unique-local prefixes
(`fd4a:25c::/64` under Virtualization.framework, `fec0::/64` under QEMU's
slirp), so the address configured on those is unique-local.

## Network behavior

The QEMU-tested stack includes IPv4/IPv6 fragment reassembly and source
fragmentation, TCP
handshake/data retransmission, slow start, congestion avoidance, fast
retransmit, out-of-order receive, duplicate-ACK/SACK handling, UDP delivery
semantics, asynchronous DNS A/AAAA resolution, bounded TTL caching,
DNS-over-TCP fallback, socket ownership, cancellation, and cleanup. DNS
requests set EDNS DO and CD; answers are admitted only after XAIOS locally
validates the DNSKEY/DS delegation chain from compiled root DS anchors and a
matching RRSIG. The upstream resolver's AD bit is not trusted. Unsigned,
malformed, expired, unsupported-algorithm, or clock-untrusted replies fail
closed and are reported to the caller without waiting for the query timeout.
RSA/SHA-256, ECDSA P-256/P-384, and Ed25519 signatures plus SHA-256/SHA-384
DS digests are supported. Signed exact-owner NSEC NODATA proofs are supported;
NXDOMAIN, NSEC3, CNAME/DNAME synthesis, wildcard synthesis, and root-anchor rollover policy
are deliberately unsupported and fail closed. SNTP applies accepted corrections through a bounded
500-ppm monotonic slew after initial calibration. Runtime-sized CPU/queue
metadata avoids a fixed small-core limit.

Boot readiness uses a real IPv4 TCP connection to port 443 before starting
`sshd`; it does not treat a DNS response as proof of Internet reachability. The
boot-test image uses the in-guest local-DNSSEC resolver wiring self-test so
`make qemu-smoke` remains deterministic when public DNS is unavailable. The
normal `nettest` application performs an external locally validated lookup.

## Outbound clients

From an XAIOS shell:

```sh
ssh [-A] [-i KEY] [-p PORT] [-J user@host[:port]] user@host [command]
scp [-r] [-A] [-i KEY] [-P PORT] SOURCE DESTINATION
```

The dedicated `/bin/ssh` process supports password, Ed25519 identity-file and
forwarded-agent authentication, including passphrase-protected OpenSSH private
keys. It verifies Ed25519 host signatures with persistent trust-on-first-use
records and connects through IPv4/IPv6 literals or DNS A/AAAA results. Recursive
SCP is SFTP-backed. `ssh -J user@host[:port]` opens a separately authenticated
password session to one jump host, requests a bounded `direct-tcpip` channel,
then authenticates the target through that channel. Target password and
identity-file authentication are supported; agent authentication with `-J`,
multiple jump hosts, `ProxyCommand`, and the wider OpenSSH option/algorithm
matrix are intentionally out of scope.

## Interoperability evidence

Automated suites exercise XAIOS from macOS OpenSSH, Debian 13 OpenSSH, and an
official FreeBSD 15.1 VM. They cover valid/invalid authentication, 32
simultaneous sessions under the combined macOS/Debian load gate, reconnects,
PTY applications, SFTP lifecycle and
isolation, SCP, UDP, IPv6/TCP, malformed traffic, rekey, reboot persistence,
and concurrent clients against one guest. The raw Ethernet gates additionally
send maximum-size fragmented UDP requests and independently reassemble XAIOS
IPv4 and IPv6 replies on AArch64 and x86_64 QEMU.

`make qemu-network-adversarial-gate` adds sanitizer-backed coverage-guided
SSH/SFTP/DNS parser campaigns, packet loss/reordering/corruption cases,
connection and channel exhaustion with recovery, concurrent macOS/Debian load,
and 20 fresh boots on each of ARM64 and x86_64. This remains emulated
correctness evidence rather than physical deployment qualification.

This is protocol correctness evidence under QEMU, not approval for direct
Internet exposure. See [[Security Model|Security-Model]],
[[Testing XAIOS|Testing-XAIOS]], and [[Current Limitations|Current-Limitations]].
