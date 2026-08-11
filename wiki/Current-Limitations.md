# Current Limitations

This page records verified implementation gaps and explicit non-claims. It is
kept consistent with current source and the QEMU release-candidate contract.
Progress status and ownership live only in [[Project Tracker|Project-Tracker]].

## Platform and hardware

- AArch64 QEMU provides the broadest complete OS-service path. QEMU validates
  behavior, not physical ARM performance, firmware behavior, or scaling.
- VMware Fusion 25.0.1 on Apple Silicon reaches `/init` through a generated
  ARM64 compatibility stage. VMware networking, persistent storage,
  multi-vCPU discovery, and later service gates are not integrated.
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
- The normal QEMU boot requires an external IPv4 A-record response before SSH
  binds. This checks the configured gateway/DNS path only; it is not a general
  Internet-health check. Failure reports a numeric startup error. A local shell
  is available only after PBKDF2 authentication in explicitly password-enabled
  development images; default, key-only and release consoles stay locked.
- The SSH service deliberately supports four transports and two active
  channels per transport. Fleet-scale identity, audit, replay, and connection
  policy remains unresolved.
- SSH key exchange is classical `curve25519-sha256` only. Hybrid post-quantum
  key exchange, OpenSSH interoperability and downgrade-policy review remain
  production security gates; the quiet local QEMU launcher only suppresses the
  OpenSSH 10 client notice for that development connection.
- The outbound guest SSH/SCP client uses the same classical crypto suite,
  verifies Ed25519 host keys through persistent TOFU, and currently authenticates
  with passwords over IPv4 or DNS A records. Public-key client authentication,
  IPv6 active opens, forwarding, agents and jump hosts are not implemented.
- DNS performs asynchronous external A-record resolution with timeout, retry,
  cache, and a QEMU-verified cache hit. DNSSEC, TCP fallback, complete AAAA
  application results, and deployment resolver policy remain absent.
- The SNTP client validates request binding, server mode/version, stratum, and
  bounded retry/timeout behavior. QEMU's PL031 RTC may report epoch zero, and
  public UDP/123 may be filtered; both conditions remain explicit instead of
  being reported as synchronized. Production NTP authentication, source policy,
  drift discipline, and physical RTC qualification remain open.
- TCP implements retained segments, cumulative and partial ACK handling,
  RTT/RTO backoff, SACK, fast retransmit, zero-window handling, bounded
  reordering, keepalive, and FIN bookkeeping. Repeated-loss physical-network
  soak and congestion-control tuning remain unverified.
- Bounded IPv4/IPv6 reassembly and source fragmentation pass maximum-size UDP
  echo under dual-client load and focused AArch64/x86_64 QEMU gates. A
  deterministic sanitizer corpus covers 50,000 malformed fragment inputs;
  coverage-guided hostile fuzzing and physical lossy-link behavior remain.

## Storage and persistence

- VirtIO block/network use interrupt-assisted completions, indirect
  descriptors, and bounded queued work. The x86 block gate records whether
  the post-reset completion arrived through MSI-X and otherwise verifies the
  bounded polling fallback. Repeated block MSI-X delivery after a device reset
  is not claimed from QEMU. Emulated NVMe covers focused
  identify/write/flush/read and backing-byte checks.
- AArch64 and x86_64 QEMU negotiate four NVMe I/O queues and pass four-page PRP
  16 KiB write/read/flush operations with host backing-byte verification.
  Asynchronous block integration, SGL, queue affinity, cancellation, direct
  final-buffer reads, physical durability, discard behavior, and throughput
  remain open.
- ModelFS supports signed registration, resumable staging, verification,
  immutable activation, scrub/quarantine, cleanup/reuse, and free-only trim
  under hosted and QEMU tests.
- Trusted-replica repair, production signing and key custody, physical
  multi-terabyte transfer, and model-v2 execution admission are not complete.
- ModelFS activation and MutableFS audit persistence are separate durability
  domains. A post-publication audit failure cannot roll back an already
  published active generation.
- MutableFS v4 is intentionally bounded to 128 nodes, 64 open handles, 128 KiB
  files and 2 MiB of data space. Interactive `nano` is further bounded to a
  32 KiB editing buffer. This is suitable for OS state and small user files,
  not general bulk storage or model weights.
- Tar/ZIP exchange is bounded by that 128 KiB file limit. Tar extraction accepts
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
- Update signing uses a development trust root to validate transaction,
  fallback, and rollback behavior. Production key management is unresolved.
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
- Qwen 3.6 27B is the next active correctness workstream now that the declared
  QEMU platform gate passes. Kimi K3, DeepSeek V4 Flash 0731, and GLM 5.2
  remain later roadmap targets.
- Kimi K3 KDA, Gated MLA, AttnRes, exact top-16 routing, shared experts, native
  MXFP4, text parity, and multimodal execution are not implemented.
- Scalar INT4/INT6 and experimental NEON/AVX2 packed kernels pass bounded
  correctness tests. Physical AVX2 validation, AVX-512/VNNI, AMX, SVE,
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
