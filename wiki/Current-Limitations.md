# Current Limitations

This page records verified implementation gaps and explicit non-claims. It is
kept consistent with current source and the QEMU release-candidate contract.
Progress status and ownership live only in [[Project Tracker|Project-Tracker]].

## Platform and hardware

- AArch64 QEMU provides the broadest complete OS-service path. QEMU validates
  behavior, not physical ARM performance, firmware behavior, or scaling.
- VMware Fusion on Apple Silicon has a qualified one-vCPU ARM64 profile with a
  generated compatibility stage, PCI-discovered E1000E DHCP, AHCI MutableFS,
  public-key SSH/SFTP, recovery, reboot, clean shutdown and repeat-boot
  evidence. Multi-vCPU startup, VMXNET3, live DNSSEC interoperability, IPv6,
  outbound-client, snapshot semantics and physical qualification remain open.
- Apple Virtualization.framework runs XAIOS to a login with storage and
  dual-stack networking, but is a development target with no automated gate, so
  none of it is qualification evidence. Its firmware describes no GIC ITS, so
  message-signalled interrupts cannot be delivered and every virtio queue runs
  polled; its GOP is `PixelBltOnly`, so the kernel has no linear framebuffer and
  renders to the virtio console; and it presents no PL011. Its router advertises
  a unique-local IPv6 prefix, so the address configured there is unique-local
  rather than globally routable.
- A guest on Apple Virtualization.framework is not reachable from the host with
  the NAT attachment: guest-initiated traffic works, but host-initiated frames
  are not delivered, so sshd listens without being reachable and the console is
  output-only. Use the QEMU targets for anything that must be connected to.
- MSI-X for virtio on PCI is implemented against the GIC ITS but is exercised by
  no target available here: Virtualization.framework has no ITS, and QEMU's
  `virt` machine puts virtio on MMIO, where interrupts arrive through the
  distributor. It is unverified until it meets ARM PCIe hardware.
- The x86_64 QEMU image executes the complete common process/thread, filesystem,
  networking, SSH/SFTP, control, security, AI Cell and telemetry service set.
  Modern PCI VirtIO block/network and emulated NVMe pass focused correctness
  gates. The platform matrix reaches 256 vCPUs with x2APIC.
- Physical x86 firmware, interrupt routing, NIC, NVMe durability, NUMA locality,
  AVX2/AVX-512/VNNI/AMX state, security exposure and performance remain
  unvalidated. QEMU parity is not a physical support claim.
- Physical Apple, Intel desktop, Xeon, SMMU/IOMMU, NVMe, NIC, NUMA, many-core,
  thermal, power, and performance evidence is not present.
- The macOS TCG/EDK2 harness permits at most two nonfatal startup retries and
  saves each failed serial log. Guest panic/assertion markers are never retried.
  This is emulator robustness handling, not physical boot evidence.

## Networking and SSH

- FreeBSD 15.1, native macOS, and Debian 13 OpenSSH clients pass bounded QEMU
  interoperability suites. This is not a production Internet deployment or an
  independent security audit.
- The normal QEMU boot requires a bounded IPv4 TCP connection to
  `1.1.1.1:443` before SSH binds. This checks configured external reachability
  without depending on public DNS; it is not a general Internet-health check.
  Failure reports a numeric startup error. A local shell is available after
  PBKDF2 authentication in the default development image (`admin` / `xaios`,
  or the six-digit console PIN `012345`); key-only and release consoles stay
  locked. The PIN is console-only and never accepted over SSH. Its search
  space is 10^6, so it is protected only by a 60-second lockout after five
  consecutive failures; it is a development convenience and is not a
  production-strength credential.
- The SSH service deliberately supports 32 transports and two active channels
  per transport, backed by 64 asynchronous child-channel records. Fleet-scale
  identity, audit, replay, and connection policy remains unresolved.
- SSH prefers hybrid `mlkem768x25519-sha256` with classical
  `curve25519-sha256` fallback. Known-answer and OpenSSH interoperability gates
  pass; independent cryptographic, downgrade-policy, side-channel and physical
  deployment review remain open.
- The dedicated outbound SSH/SCP process supports password, Ed25519 identity
  file and forwarded-agent authentication, encrypted OpenSSH keys, persistent
  Ed25519 TOFU, IPv4/IPv6 literals, DNS A/AAAA results, and one
  password-authenticated `-J user@host[:port]` jump host with a separately
  authenticated target. Multi-hop `-J`, `ProxyCommand`, `-J` agent
  authentication, and the complete OpenSSH matrix are not provided.
- DNS performs asynchronous A/AAAA resolution with timeout, retry, bounded TTL
  cache, and DNS-over-TCP fallback. It locally validates DNSKEY, DS, and RRSIG
  chains from compiled root DS anchors and accepts signed exact-owner NSEC NODATA proofs.
  It also resolves names under an unsigned delegation, proving the absent DS
  from a signed NSEC3 the parent serves, including the opt-out form, and then
  accepting the unsigned answer as insecure rather than refusing it as bogus.
  Insecure answers are counted separately from authenticated ones, because
  they carry a weaker guarantee. NSEC3 iteration counts above 150 are refused
  rather than computed. NXDOMAIN, CNAME/DNAME and wildcard synthesis, plus
  production root-anchor rollover/update policy, remain unsupported and fail
  closed.
- The SNTP client validates request binding, server mode/version, stratum, and
  bounded retry/timeout behavior, then applies corrections through a monotonic
  500-ppm slew after initial calibration. Boot performs one bounded, non-fatal
  synchronization against a fixed server address before services start, and an
  offset from an unset clock is stepped rather than slewed. QEMU's PL031 RTC may
  report epoch zero, and public UDP/123 may be filtered; a filtered port leaves
  boot on the RTC reading after a bounded pause, so both conditions remain
  explicit.
  Production NTP authentication, source policy, oscillator characterization,
  and physical RTC qualification remain open.
- TCP implements retained segments, cumulative and partial ACK handling,
  RTT/RTO backoff, SACK, fast retransmit, zero-window handling, bounded
  reordering, keepalive, and FIN bookkeeping. Repeated-loss physical-network
  soak and congestion-control tuning remain unverified.
- Bounded IPv4/IPv6 reassembly and source fragmentation pass maximum-size UDP
  echo under dual-client load and focused AArch64/x86_64 QEMU gates.
  Deterministic and coverage-guided sanitizer campaigns plus packet-fault and
  recovery gates pass; physical lossy-link behavior remains.

## Storage and persistence

- VirtIO block/network use interrupt-assisted completions, indirect
  descriptors, and bounded queued work. The x86 block gate records whether
  the post-reset completion arrived through MSI-X and otherwise verifies the
  bounded polling fallback. Repeated block MSI-X delivery after a device reset
  is not claimed from QEMU. Emulated NVMe covers focused
  identify/write/flush/read and backing-byte checks.
- AArch64 and x86_64 QEMU negotiate four NVMe I/O queues and pass four-page PRP
  and SGL 16 KiB write/read/flush operations with async submission, direct
  aligned buffers, cancellation, malformed-completion rejection, queue
  affinity, and host backing-byte verification. Every queue must deliver its
  canary through APIC/MSI-X on x86_64 or GICv3 ITS LPIs on AArch64. Physical
  durability, discard behavior, and throughput remain open.
- ModelFS supports signed registration, resumable staging, verification,
  immutable activation, scrub/quarantine, cleanup/reuse, and free-only trim
  under hosted and QEMU tests.
- Offline trusted-replica repair is implemented for a selected unmounted
  ModelFS partition with exact signed package identity and full payload
  verification. Production signing/key custody, replica enrollment, physical
  multi-terabyte transfer, and model-v2 execution admission are not complete.
- ModelFS activation and MutableFS audit persistence are separate durability
  domains. A post-publication audit failure cannot roll back an already
  published active generation.
- MutableFS v5 keeps two metadata copies and alternates writes between them,
  so a write interrupted by power loss damages only the copy that is not
  currently authoritative and mount falls back to the survivor. The mirror
  sits past the data region, so volumes written before it keep mounting, and
  a volume with no room for it operates single-copy. When both copies are
  damaged the mount still refuses rather than formatting, because falling
  back is a recovery and not a licence to discard data. Host tests damage
  each copy in turn and require the volume to mount with contents intact.
- MutableFS v5 is intentionally bounded to 256 nodes, 256 open handles, 256 KiB
  files and 4 MiB of data space. Interactive `nano` is further bounded to a
  32 KiB editing buffer. This is suitable for OS state and small user files,
  not general bulk storage or model weights.
- Tar/ZIP exchange is bounded by that 256 KiB file limit. Tar extraction accepts
  ustar, PAX paths, GNU long names and one gzip member; ZIP accepts stored and
  Deflate entries. Symlinks, device nodes, encrypted ZIP, ZIP64, multi-member
  gzip and gzip creation are explicitly unsupported.

## Administration and security

- `xaios.control.v1` operations are bounded to 16 active keys, 16 revoked
  fingerprints, 64 audit/replay records, and 16 shell contexts. These are
  implementation limits, not fleet-scale targets.
- Role, capability, replay, rollback, host-key rotation, sensitive-path denial,
  and secret-redaction behavior pass QEMU/OpenSSH gates but have not received an
  independent production security review.
- `xapt` supports TLS 1.2, validating the certificate chain against compiled-in
  ISRG roots with server-name and validity checks, or an exact RSA public-key
  pin for a private origin. Chain validation depends on the realtime clock set
  during boot and refuses an unset one. The shipped configuration currently
  sets `tls=off` and fetches over plain HTTP; signed catalogs and per-artifact
  hashes remain the authenticity layer, and transport confidentiality is
  forfeited until TLS is restored. It supports signed
  release-root rotation, revocation, offline recovery, and rollback of an
  interrupted trust/catalog activation. The checked-in TLS and signing private
  fixtures are public; production key custody and release authorization remain
  unresolved. Transfer encoding, compression, proxies, mirrors, deltas,
  dependencies, and unattended updates are not supported.
- External applications are bounded to 256 KiB by the current MutableFS/app
  loader, and only one previous version is retained. Shipped applications,
  including `xapt`, `nano`, `htop`, and `pong`, are standalone ELFs; publishing
  them as independently upgradable repository packages still requires signed
  package manifests and architecture-specific payloads.
- QEMU verifies persistent clean/unclean lifecycle records, rescue selection,
  reset/poweroff dispatch, and block flush completion. It cannot establish
  physical power-loss durability or platform reset correctness. Thermal and PMU
  support reports remain explicitly unavailable until physical backends exist.

## Inference engine and model support

- The kernel model-v1 path is a deterministic fixture. It does not execute a
  transformer and must not be described as real inference.
- Model-v2 parsing, streaming writing, architecture/backend registries,
  immutable readers, sessions, and scalar packed kernels are foundations only.
  Model-v2 packages are not yet executed end to end.
- No official tokenizer importer, real Qwen tensor importer, transformer plan,
  logits parity, or deterministic 32-token decode parity exists.
- Qwen 3.8 is the next active correctness workstream now that the declared
  QEMU platform gate passes. Kimi K3 and DeepSeek V4 Flash 0731 remain later
  roadmap targets.
- A miniature Kimi K3 reference covers reduced KDA recurrence, causal Gated
  MLA, exact top-16 routing across 20 experts, shared-expert reduction, SiTU,
  and one native MXFP4 block. AttnRes, production dimensions, tokenizer/text
  parity, real checkpoints, and multimodal execution are not implemented.
- Scalar INT4/INT6 and experimental NEON/AVX2 packed kernels pass bounded
  correctness tests. An SVE2 arithmetic canary and per-task Z/P/FFR context
  preservation pass under QEMU, but an SVE inference backend does not exist.
  Physical AVX2 validation,
  AVX-512/VNNI, AMX, SVE,
  tiled prefill/verification, persistent worker gangs, and bandwidth autotuning
  remain incomplete.
- No complete model-executing native macOS process, Metal backend, physical
  model-parity run, cluster data plane, or immutable performance artifact
  exists.

## Evidence policy

Sparse files above 4 GiB or 100 GiB prove address width and bounded-memory
behavior, not physical transfer throughput. High-vCPU QEMU gates prove dynamic
metadata capacity, not server scalability. Performance claims require physical
artifacts satisfying `docs/BENCHMARK-CONTRACT.md`.

See [[Project Tracker|Project-Tracker]].
