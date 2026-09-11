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
- An accept-rate limit of 120 connections per minute per client address,
  bounding a flood from a peer that has proved nothing. A connection is
  credited back once it authenticates, so a peer holding a credential this
  machine accepts is not throttled -- an administrator moving many files over
  SFTP opens a connection per transfer, and counting those protected nothing
  while breaking the workload the machine is for. Unauthenticated connections
  still count and still trip it; authenticated peers remain bounded by the
  transport ceiling above. A refused connection is closed before the version
  banner, which from the client is `Connection closed` with no explanation, so
  the guest names the reason on its console with a per-reason counter: a
  refusal nobody can attribute is indistinguishable from a defect.

## Address configuration

Every network device asks the network for an IPv4 address by DHCP before
falling back to the compiled-in QEMU address of `10.0.2.15`. A guest that
assumes that address is simply off-net anywhere else; Virtualization.framework
hands out a different subnet entirely.

IPv6 derives a link-local address from the hardware address, then solicits a
router and polls briefly for the advertisement, because nothing else reads the
interface between bringing it up and starting services. A prefix that is
globally routable or unique-local is configured and used as the source address
for outbound IPv6. The router that sent the advertisement is kept as the
default route for as long as its Router Lifetime says, and traffic to anything
outside the advertised /64 is sent to it -- without that a host configures an
address and can still only reach its own link, because the neighbour lookup
asks about a destination no neighbour will answer for.

Which prefix arrives depends on the network, and the two non-global cases are
not the same case. Virtualization.framework advertises `fd4a:25c::/64`, which
is unique-local, so the address configured there is unique-local. QEMU's slirp
advertises `fec0::/64`, which is deprecated *site-local*, and this stack keeps
its public address slot for genuinely global addresses on purpose: a guest
asked for a public address must not hand out one that cannot be routed. So on
the default QEMU network the guest forms a SLAAC address, correctly declines to
call it public, and reports its link-local one. That is not a missing feature,
and it is why the default network could not evidence SLAAC at all -- there was
no configuration in which the question could be put.
`XAIOS_QEMU_USER_NET_IPV6` puts it, through slirp's `ipv6-net`: with
`2001:db8::/64`, the RFC 3849 documentation range and global in scope, the
guest forms `2001:db8::5054:ff:fe12:3457` from the advertisement, the interface
identifier derived from its own MAC. `make qemu-slaac-gate` runs both networks,
because either alone proves the wrong thing -- one that ran only the global
prefix would pass against a stack that called every address public.
A bridged Fusion guest on a network with real IPv6 takes a globally routable
address, and has been shown end to end on one: ICMPv6, inbound SSH and SFTP,
inbound UDP, and outbound SSH and SCP to a host in another country.

## Network behavior

The QEMU-tested stack includes IPv4/IPv6 fragment reassembly and source
fragmentation, TCP
handshake/data retransmission, slow start, congestion avoidance, fast
retransmit, out-of-order receive, duplicate-ACK/SACK handling, UDP delivery
semantics, asynchronous DNS A/AAAA resolution, bounded TTL caching,
DNS-over-TCP fallback, socket ownership, cancellation, and cleanup. A
userspace datagram socket can now name its peer in the call:
`xaios_net_sendto` allocates the flow for the four-tuple and transmits on it,
where before this existed the only thing that ever created a UDP socket's flow
was an *inbound* datagram, so a socket that had bound a port and received
nothing was refused every send. It reaches the device, which
`xaios_net_udp_echo` and `xaios_net_external_session` do not -- both process a
frame inside the stack rather than transmitting one, which is why nothing had
noticed. The destination must be IPv4 today; the v6 branch needs flow addresses
and a neighbour entry this path does not fill, and is refused rather than
half-built. The first datagram to an unseen peer blocks briefly, against a
two-second deadline, while ARP resolves, and an unresolved peer and a failed
send are separate reasons so that an ARP fact never reads as a code defect. DNS
requests set EDNS DO and CD; answers are admitted only after XAIOS locally
validates the DNSKEY/DS delegation chain from compiled root DS anchors and a
matching RRSIG. The upstream resolver's AD bit is not trusted. Unsigned,
malformed, expired, unsupported-algorithm, or clock-untrusted replies fail
closed and are reported to the caller without waiting for the query timeout.
RSA/SHA-256, ECDSA P-256/P-384, and Ed25519 signatures plus SHA-256/SHA-384
DS digests are supported. Signed exact-owner NSEC NODATA proofs are supported,
as is the NSEC3 proof that a delegation carries no DS -- including the opt-out
form -- which is what lets an unsigned delegation resolve as insecure rather
than bogus; iteration counts above 150 are refused rather than computed.
NXDOMAIN, CNAME/DNAME synthesis, wildcard synthesis, and root-anchor rollover policy
are deliberately unsupported and fail closed. SNTP applies accepted corrections through a bounded
500-ppm monotonic slew after initial calibration. Runtime-sized CPU/queue
metadata avoids a fixed small-core limit.

Boot readiness requires the interface to hold a usable IPv4 address before
`sshd` opens port 22, and probes no external DNS name or TCP endpoint, so SSH
availability does not depend on a third party's service being up. The
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
IPv4 and IPv6 replies on AArch64, x86_64 and RISC-V QEMU.

`make qemu-network-adversarial-gate` adds sanitizer-backed coverage-guided
SSH/SFTP/DNS parser campaigns, packet loss/reordering/corruption cases,
connection and channel exhaustion with recovery, concurrent macOS/Debian load,
and 20 fresh boots on each of ARM64, x86_64 and RISC-V -- the same
`XAIOS_NF3Q_BOOTS` count on all three. This remains emulated
correctness evidence rather than physical deployment qualification.

This is protocol correctness evidence under QEMU, not approval for direct
Internet exposure. See [[Security Model|Security-Model]],
[[Testing XAIOS|Testing-XAIOS]], and [[Current Limitations|Current-Limitations]].
