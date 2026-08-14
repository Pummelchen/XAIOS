# Network and SSH Status

This document separates the completed QEMU correctness surface from work that
requires physical hardware, deployment policy, or independent security review.
QEMU evidence is sufficient for the core-OS release gate; it is not approval to
expose XAIOS directly to the Internet.

## QEMU-Tested Surface

Normal boot now treats SSH readiness as a checked state rather than a startup
claim. After the persistent VirtIO network is initialized, `/bin/sshd` first
resolves `example.com` through the configured IPv4 DNS path. It opens TCP port
22 only after receiving a nonzero A record, then initializes crypto, host keys,
configuration, users, channels, and the listener before printing `SSH server:
up and running`. A failed stage is shown on the serial console with a numeric
error code and leaves the local command prompt running without an SSH listener.
The configured QEMU address is also printed at completion.

Boot error codes are stable by stage: `1001`-`1006` identify IPv4/DNS status
failures (`1005` is the bounded DNS timeout), `2001` entropy, `2002` host-key
initialization, `2101` and above crypto self-tests, `2201` runtime
configuration, `2202` users, `2203` authorized keys, `2301` the TCP listener,
and `2302` the companion UDP service. No SSH-ready message is emitted on these
paths.

The following paths passed from OpenSSH clients on macOS and in an official
Debian 13 Docker container as of 2026-08-11. The broad Debian suite passes
against both the freestanding AArch64 and x86_64 QEMU guests; the x86 report is
`build/qemu-docker-network-suite-x86_64.json`. An official FreeBSD 15.1 AArch64
client passed the explicitly identified subset below on 2026-08-10:

- OpenSSH Ed25519 public-key login succeeded and an unauthorized key failed;
- an explicitly provisioned PBKDF2-HMAC-SHA256 password succeeded and a wrong
  password failed;
- the typed `xaios.control.v1` administration surface was exercised through the shared
  `xaiosctl` parser, including strict config show/validate/diff/apply,
  role-mapped key list/add/remove, host-key rotation, audit reads, ModelFS
  lifecycle and storage device/filesystem administration;
- observer/operator/administrator permissions, mutation replay rejection,
  failed-config rollback, key revocation, per-connection cwd isolation,
  command-rate rejection and sensitive-state denial were verified;
- operational and administrative log queries were checked for submitted key,
  password and private-key material;
- password login remained disabled when no user database was packaged, and a
  malformed user database made the SSH service fail closed;
- the SSH service refused to start when the VirtIO RNG device was removed;
- the Ed25519 host identity remained unchanged across a QEMU reboot using the
  persistent VirtIO block image and negotiated block flushes;
- SFTP v3 put, stat, get, directory list-to-EOF, rename, remove, and rmdir
  completed for an 8,170-byte file with byte-identical output and
  offset-correct reads and writes;
- two overlapping SFTP connections retained isolated handles;
- one SSH transport carried simultaneous exec and SFTP channels;
- client-initiated rekey at a 4 KiB OpenSSH `RekeyLimit` completed without
  interrupting SFTP;
- the focused suite completed four simultaneous SSH connections and 20
  sequential reconnects; the load gate separately holds all 32 transports;
- storage discovery reported the expected writable `/dev/vblk4` ModelFS
  device, the MutableFS root, the `/models` mount, and consistent staging/active
  package accounting before and after activation;
- a 24-byte UDP payload reached the guest application buffer and was echoed
  byte-for-byte; kernel self-tests also verify that a short receive discards the
  remainder of that datagram without contaminating the next one;
- direct IPv6/TCP accepted reordered input, rejected a zero TCP checksum and an
  out-of-window reset, and retransmitted an identical guest segment after its
  ACK was withheld;
- the direct framed receive path rejected malformed IPv4 checksums, retained
  incomplete fragments without exposing them to TCP, and reassembled complete
  out-of-order IPv4 and IPv6 fragment pairs before processing their TCP SYNs;
- guest userspace resolved `example.com` through the asynchronous DNS syscall,
  then completed an immediate cache hit.
- a Debian 13 OpenSSH PTY drove the native guest-generated live ANSI `htop`,
  including sort, filter, help, CPU/memory meters, process framing, a hard
  60-frame-per-second render cap and clean cursor-restoring exit, while a
  non-PTY command retained the plain automation format.
- the guest outbound SSH client completed password-authenticated remote exec
  against Debian 13 OpenSSH through QEMU SLIRP, verified and persisted the
  server's Ed25519 host key, and returned remote output to the originating PTY;
- SFTP-backed outbound `scp` transferred regular files and recursive directory
  trees in both directions with byte-identical nested content.
- the native `pong` terminal game rendered through an OpenSSH PTY, accepted
  movement/pause/quit input, retained independent session state, and restored
  the host terminal; the authenticated local-console gate exercises the same
  fixed-point game engine.

### Outbound guest client

The dedicated `/bin/ssh` process owns each guest outbound session and exchanges
terminal data with the parent through bounded asynchronous child-channel IPC.
The kernel provides checked IPv4/IPv6 TCP active-open and stream syscalls. From
an XAIOS SSH PTY:

```sh
ssh [-A] [-i KEY] [-p PORT] user@host [command]
scp [-r] [-A] [-i KEY] [-P PORT] SOURCE user@host:PATH
scp [-r] [-A] [-i KEY] [-P PORT] user@host:PATH DESTINATION
```

It negotiates the repository's bounded SSH suite, requests a shell or exec
channel, and uses SFTP v3 for file operations. Password input and private-key
passphrases are not echoed. Authentication supports passwords, Ed25519
identity files, passphrase-protected OpenSSH keys, and a forwarded OpenSSH
agent. First contact persists an Ed25519 known-host record under
`/home/admin/.ssh`; a changed host key fails closed. IPv4/IPv6 literals and DNS
A/AAAA results are accepted. Native outbound `-J`/`ProxyCommand` parsing and
the wider OpenSSH option and algorithm matrix are not implemented.

### FreeBSD Unix-reference gate

`make qemu-freebsd-network-suite` boots the checksum-pinned official FreeBSD
15.1 AArch64 cloud image beside one XAIOS guest. FreeBSD base-system OpenSSH
10.0p2 and SFTP passed authorized login, unauthorized-key rejection, a typed
`xaiosctl version` query, SFTP write/stat/read/rename/remove with exact byte
comparison, interactive PTY ANSI `htop`, and UDP echo. The passing report is
`build/qemu-freebsd-network-suite.json`.

This is the primary external Unix behavioral-reference gate. It does not prove
FreeBSD binary ABI compatibility, and it does not replace the broader Debian
and macOS administration, concurrency, persistence, rekey and malformed-packet
coverage. See [`UNIX-COMPATIBILITY.md`](./UNIX-COMPATIBILITY.md).

The machine-readable result is `build/qemu-docker-network-suite.json`. Serial
logs and the direct-network packet capture are also generated under `build/`.
This long-running interoperability suite builds with `XAIOS_BOOT_VERBOSE=1` so
an early entropy or storage timeout remains attributable in its saved logs;
normal in-place boot UI behavior is covered separately by smoke and console
gates.
The harness permits at most two nonfatal QEMU startup retries and retains every
failed serial log because macOS TCG/EDK2 can intermittently stop advancing.
Guest panic or assertion markers fail immediately, and a repeatable timeout
still exhausts the bounded retry and fails the gate. Reboot persistence waits
for the same SSH-ready marker as first boot in both normal and verbose modes.

### Dual-origin one-guest load gate

`make qemu-parallel-network-load` adds a local concurrency and recovery gate.
Its latest passing run used macOS 26.6 and Debian 13 against one successful
XAIOS guest instance and recorded:

- successful key/password authentication, unauthorized-key/wrong-password
  rejection, strict batch-mode SFTP, and UDP echo from both client origins;
- two direct raw TCP clients while SSH, SFTP, and UDP traffic remained active,
  including malformed/incomplete fragment rejection and complete out-of-order
  IPv4/IPv6 fragment reassembly from both client origins;
- all four allowed SSH connections saturated concurrently, with two active
  channels per connection;
- 40 strict SFTP cycles and 330 UDP round trips during the combined workload;
- two additional over-capacity connections rejected cleanly;
- 40 sequential reconnects after saturation; and
- successful post-load SSH, SFTP, and UDP health checks from both origins.

The machine-readable result is `build/qemu-parallel-network-load.json`; serial,
client, listener, and packet-capture artifacts are generated under `build/`.
This is bounded QEMU interoperability and load evidence, not a physical-network
throughput benchmark or an Internet-exposure approval.

## Security and Resource Model

The SSH daemon has no built-in account password. Images may package an
`admin` Ed25519 authorized key, an `admin` password record, or both. Password
records use the strict format generated by `scripts/create-sshd-user-config.py`;
plaintext and malformed records are rejected. Authentication attempts are
bounded per connection and by a 256-entry, expiration-aware source-address
rate table.

The transport currently negotiates this bounded suite:

- preferred `mlkem768x25519-sha256` hybrid key exchange with
  `curve25519-sha256` compatibility fallback;
- `ssh-ed25519` host and user keys;
- `aes128-ctr` encryption;
- `hmac-sha2-256` integrity;
- no compression.

The hybrid path passes ML-KEM known-answer tests and OpenSSH interoperability
under both AArch64 and x86_64 QEMU. Classical fallback remains for compatible
clients. Independent cryptographic review, downgrade-policy review, side-channel
analysis and physical deployment qualification remain required.

Fresh randomness comes from a VirtIO RNG-backed ChaCha20 DRBG. SSH startup is
fail-closed when secure entropy is unavailable. The host key is created once,
stored on the persistent mutable filesystem, flushed to the block device, and
reused on reboot. Rekey works in both protocol directions; the Debian gate
forces the client-initiated path.

The SSH command boundary recognizes an exact `xaiosctl` prefix and invokes the
shared userspace control client. It does not launch arbitrary guest
executables. Ed25519 keys map to observer, operator or administrator roles.
Read operations require `XAIOS_CAP_CONTROL_QUERY`; administrator operations
also require `XAIOS_CAP_CONTROL_ADMIN`, and the kernel rejects a requested role
above the process's trusted capability role. Operators may apply strict
versioned configs; only administrators may mutate keys or rotate host identity.

Configuration, active/revoked keys and audit records are checksummed and
persistent. Mutations require nonzero replay IDs and are payload-redacted.
Operational remote-login records omit user-supplied command text and arguments.
The shell and SFTP deny the host private key, password database, legacy key
source and `/state/control` subtree. The current stores are intentionally
bounded to 16 keys, 16 revoked fingerprints and 64 audit records.

SSH identification, packet, authentication, channel, and SFTP lengths are
validated before arithmetic or copying. Invalid encrypted lengths, MACs,
padding, embedded NULs, unsupported service names, malformed client versions,
all-zero X25519 shared secrets, and malformed PTY or resize payloads terminate
the connection. Valid PTY dimensions are retained per channel and bounded to
the native dashboard's supported terminal range.

The service is cooperatively scheduled and intentionally bounded to 32
connections, two channels per connection, and 64 asynchronous child channels.
Each connection has independent shell cwd/parser state. The kernel TCP table
retains admission headroom so over-capacity attempts reach the auditable SSH
policy rejection, while socket buffers cover the complete TCP and UDP tables.
These are explicit resource limits, not
claims of unlimited server concurrency. Connection/authentication and
shell/control command rates are independently bounded. SFTP protocol packets do
not consume the shell-command quota; they remain bounded by connection/channel
limits, SSH/SFTP packet sizes, flow-control windows and filesystem policy.

## Automated Gate

The FreeBSD gate uses a real QEMU VM because Docker containers share a Linux
kernel and cannot provide FreeBSD kernel/userland behavior:

```sh
make qemu-freebsd-network-suite
```

It verifies the official compressed image SHA-256, caches the immutable base,
uses a disposable QCOW2 overlay and disables vendor first-boot updating in the
overlay to keep the test bounded. GitHub Actions runs it independently from the
Linux client gate.

Docker does not publish a separate Debian server-edition image. The repository
therefore builds a disposable client from the official `debian:13` image and
installs OpenSSH, SFTP, sshpass, and network diagnostics:

```sh
make qemu-docker-network-suite
make qemu-parallel-network-load
make qemu-model-sftp-gate
```

The gate creates disposable credentials, builds the guest, runs the complete
control and read-only storage inventory over forwarded IPv4, exercises UDP,
reboots the persistent image, runs direct framed IPv4/IPv6 checks, and rebuilds
fail-closed image variants. It removes QEMU processes and listeners during
cleanup. GitHub Actions runs this target as an independent job so failures in
unrelated jobs cannot silently skip network evidence.

The parallel gate requires a macOS host plus Docker because it verifies native
macOS and Debian clients at the same time. It is a local release gate and is not
currently run by Linux GitHub Actions.

The ModelFS gate also requires macOS plus Docker. Against one XAIOS instance it
runs concurrent native macOS and Debian 13 SFTP upload/download, exact byte
comparison, dynamic package lifecycle, abandoned-staging cleanup and reuse,
online scrub, free-space trim and VirtIO discard accounting. Its transfer rate
under TCG is not physical network or storage performance evidence.

## Provision a Development Image

Generate an Ed25519 key and, only when password testing is required, a password
record. Keep the plaintext password outside the repository:

```sh
mkdir -p build/local-ssh
ssh-keygen -t ed25519 -N '' -f build/local-ssh/admin
printf '%s' 'replace-this-password' > build/local-ssh/password
chmod 600 build/local-ssh/password
python3 scripts/create-sshd-user-config.py \
  --password-file build/local-ssh/password \
  --output build/local-ssh/users
XAIOS_AUTHORIZED_KEYS_FILE=build/local-ssh/admin.pub \
XAIOS_SSH_USERS_FILE=build/local-ssh/users \
XAIOS_SSH_PASSWORD_AUTH=1 make image
XAIOS_QEMU_HOSTFWD_UDP_PORT=2298 make qemu
```

Connect from a second terminal. The launcher uses
`build/local-ssh/known_hosts`, `StrictHostKeyChecking=accept-new`, and an
OpenSSH-version-gated `WarnWeakCrypto=no`; it does not discard host identity via
`UserKnownHostsFile=/dev/null`:

```sh
scripts/ssh-xaios-qemu.sh
scripts/ssh-xaios-qemu.sh -- htop
ssh -p 7788 admin@127.0.0.1
sftp -i build/local-ssh/admin -o IdentitiesOnly=yes -P 7788 admin@127.0.0.1
```

Both QEMU architecture launchers use host TCP port `7788` by default and
forward it to guest TCP port `22`. Override it with
`XAIOS_QEMU_HOSTFWD_PORT`. OpenSSH uses `-p 7788`, not a bare
`admin@127.0.0.1:7788` destination; clients that implement SSH URI syntax may
instead use `ssh ssh://admin@127.0.0.1:7788`.

Pass a non-default key with `--identity`, for example
`scripts/ssh-xaios-qemu.sh --identity /tmp/xaios-htop-key -- htop`.
If a rebuilt guest intentionally rotates its host key, remove only the matching
entry from `build/local-ssh/known_hosts` after verifying the rotation.

Do not package development private keys or plaintext passwords into the image.
MutableFS v5 limits a state file to 262,144 bytes; interactive `nano` accepts
at most 32 KiB so its complete editing buffer remains bounded.

## Remaining Non-QEMU Gates

| Area | Current source-grounded boundary |
|---|---|
| Physical networking | No physical NIC driver interoperability, cable/link recovery, DHCP deployment, firewall, or hostile-Internet soak has been established. |
| Security assurance | Deterministic malformed corpora, sanitizer-backed coverage-guided SSH/SFTP/DNS campaigns, packet-fault injection, bounded resource exhaustion/recovery, concurrent macOS/Debian load, and 20 fresh ARM64 plus 20 fresh x86_64 boots pass. Independent review, side-channel analysis, physical lossy-link testing, and long-lived Internet deployment remain open. |
| Post-quantum SSH | `mlkem768x25519-sha256` passes known-answer and OpenSSH interoperability gates with classical fallback. Independent cryptographic and downgrade-policy review plus physical qualification remain open. |
| Administrative scale | Phase 2's config, key/revocation, replay/audit and session stores are bounded QEMU fixtures. Fleet identity integration, long-lived audit export and production replay retention are not implemented. |
| TCP throughput | Correct ACK/reset validation, checksums, an eight-segment transmit window, cumulative and partial ACK release, retained-segment RTT/RTO tracking, slow start, congestion avoidance, SACK parsing/emission, fast retransmit, zero-window handling, bounded reordering, keepalive, FIN state, and RTO backoff exist. High-bandwidth/lossy-link tuning remains outside the QEMU release gate. |
| UDP service | IPv4 and IPv6 checksums, bounded atomic datagram delivery, truncation semantics, flow expiry, and buffer reclamation are implemented. QEMU evidence covers IPv4 application echo and kernel-level IPv4/IPv6 parsing; physical lossy-link behavior remains untested. |
| Fragmentation | Bounded IPv4 and IPv6 reassembly accepts complete out-of-order fragment sets, rejects malformed overlaps/checksums, and expires incomplete sets. The common transmit boundary performs IPv4 and IPv6 source fragmentation. Dual-client load, coverage-guided parser campaigns, and focused AArch64/x86_64 gates verify maximum-size fragmented UDP echo and malformed handling. Physical lossy-link behavior remains open. |
| DNS | The asynchronous resolver supports A/AAAA results, TTL-bounded caching, retry/timeout, and DNS-over-TCP fallback. Queries set EDNS DO and advertise AD understanding; unsigned answers fail closed and are returned without an artificial timeout. The deterministic boot fixture tests parser/cache behavior without depending on public DNS. XAIOS does not perform local DNSSEC chain validation, so production validating-resolver selection and physical deployment remain open. |
| General threads | EL0 create/join/cancel/exit syscalls dispatch general workers across the runtime-sized online CPU set and pass QEMU concurrency tests. Physical many-core scheduling, fairness, and long-duration stress remain unverified. |
| SMMU | The focused QEMU SMMUv3 gate proves translated authorized DMA, a translation fault for forbidden DMA, and stale-mapping rejection after teardown. Default QEMU boot remains bypass-compatible; physical-platform Stage 1 policy and performance remain unverified. |

Within these declared boundaries, the repository now has automated QEMU
correctness evidence for the Phase 2 administration surface and core SSH,
SFTP, IPv4/IPv6 TCP, and UDP paths. A physical production release still
requires the non-QEMU gates above.
